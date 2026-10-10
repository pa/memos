# Memos on skoop: Firestore storage, passphrase E2EE, private multi-user spaces

Status: draft, decisions recorded 2026-10-10, not implemented.

## 0. Decisions

| Question | Decision |
| --- | --- |
| Database | Rewrite storage to Firestore (MongoDB-compatible), the managed database skoop offers |
| Encryption scope | Every memo, always. No plaintext mode |
| Users | Multi-user. The instance admin invites people. Each person is a separate user who creates their own Spaces and invites their own team members. The admin cannot see other people's Spaces or memos |

## 1. What skoop gives us

Read live from `skoop get resource-types` for the `memos` app:

| Kind | Role here | Limits that matter |
| --- | --- | --- |
| `cloudrun/cpu` | Memos server | Stateless, max 5 instances, 1 vCPU, up to 2Gi, CPU throttled between requests |
| `cloudrun/cpu-job` | One-off data migration from SQLite | Run to completion |
| `firestore/mongodb` | Primary database | Mongo wire protocol, OIDC auth from the service account, `retryWrites=false`, stale idle connections |
| `gcs/standard` | Attachments (ciphertext) | Grant scoped by the bucket IAM condition |
| `firebase_hosting/gcp` | `notes.pramodhayyappan.dev`, TLS, CDN | Readme says only `__session` is forwarded. Live probe showed `memos_refresh` does arrive today |

The `firestore` connection string is OIDC based (`authMechanism=MONGODB-OIDC`, `ENVIRONMENT:gcp,TOKEN_RESOURCE:FIRESTORE`),
already used by hopnote. The official Go driver (`go.mongodb.org/mongo-driver/v2`) supports that environment natively, so no
keys or passwords are involved.

Feasibility checks run on 2026-10-10:

- `mongo-driver/v2` v2.9.2 parses and validates the real skoop Firestore connection string: mechanism `MONGODB-OIDC`,
  `ENVIRONMENT:gcp`, `TOKEN_RESOURCE:FIRESTORE`, `retryWrites=false`, `loadBalanced=true`.
- `filter/ir.go` has no SQL in it, so a Mongo renderer can reuse the parser and IR as is.
- The shared store suite runs per driver (`DRIVER=sqlite go test ./store/test/ -run TestSpace` passes), so the same tests
  can gate a `firestore` driver.

Firestore Mongo API facts that shape the design (Google's behavior differences page, updated 2026-10-07):

- Multi-document ACID transactions with snapshot isolation and optimistic concurrency. Good for the existing
  "validate then write" store transactions, but conflicts abort, so every transaction needs a retry loop.
- No index on `_id` by default, no wildcard indexes, multi-key must be chosen at index creation.
- Unsorted queries have no stable order. Every list must sort explicitly.
- No `$merge` / `$out`. Lookups (`$lookup`) and regex are supported.
- No auto-increment. Memos uses `int32` IDs everywhere (`store.Memo.ID`, foreign keys, proto store messages).

## 2. Database: Firestore store driver

### Shape

New package `store/db/firestore` implementing `store.Driver` (66 methods; the SQLite driver is 4.4k lines across 25
files). Registered in `store/db/db.go` as driver `firestore`, configured with `MEMOS_DRIVER=firestore` and
`MEMOS_DSN=${firestore.<name>.out.attributes.connection_string}`.

| SQL concept | Firestore approach |
| --- | --- |
| Tables | One collection per table: `memo`, `user`, `space`, `space_member`, `attachment`, `memo_relation`, `reaction`, `inbox`, `memo_share`, `user_setting`, `instance_setting`, `idp`, `user_identity` |
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `counters` collection with `$inc` inside the same transaction. Keeps `int32` IDs so nothing above the store changes. One counter per collection is a hotspot, which is fine at personal and team scale |
| `UNIQUE` (memo uid, username, email, space uid) | Mirror documents keyed by the unique value (`_id = "memo_uid:<uid>"`) inserted in the same transaction. Duplicate `_id` fails the transaction |
| Joins in access checks | Denormalize what lists need (for example `space_id` and `creator_id` on memos) and do point reads in the transaction for the rest |
| `json_extract` on payload | Store payload as a nested BSON document, query fields directly |
| Migrations / `LATEST.sql` | Index definitions in Go, created idempotently at startup (`createIndexes`). Schema version recorded in `instance_setting` like today |
| `GetDatabaseSize` | Return -1 (allowed by the interface) |

### Filters

`filter/` compiles CEL to an IR, then renders SQL. Add a Mongo renderer that emits a `bson.D` from the same IR. With
every memo encrypted, the server-side filter shrinks to metadata only: `creator`, `visibility`, `pinned`, timestamps,
`space`, row status, and tags only if we keep them plaintext (section 4). `content.contains`, regex, `has_task_list`,
`has_link`, `has_code`, title move to the client.

### Testing

`store/test/` already runs the same suite (44 test files) against each driver via `DRIVER=...` and TestContainers. Add
`DRIVER=firestore`. Locally the tests run against a MongoDB 7 container, which is close but not identical to Firestore.
Before cutover, run the same suite once against a real Firestore database to catch the differences (index rules,
transaction conflicts, sort order).

### What stays

SQLite, MySQL and Postgres drivers stay untouched so upstream merges keep working, and local development can still use
SQLite.

### Data migration

A `cloudrun/cpu-job` runs `memos migrate --from sqlite --to firestore` once. It reads the SQLite file from the bucket
mount (read-only, after checkpointing the WAL) and writes every table to Firestore keeping IDs. Then the service switches
to Firestore and the FUSE mount is removed. The old bucket objects stay as a backup until you confirm.

## 3. Users, Spaces, and admin isolation

Today's model (from `docs/design/multi-spaces.md` and `core/access`):

- Spaces, members with `ADMIN`/`USER` roles, and invite then accept already exist.
- An instance `ADMIN` is a superuser: on any named memo operation it bypasses authorship and Space membership checks.
  Lists keep normal visibility rules.

Changes:

1. **Invite-only signup.** Set `disallow_user_registration`. The admin creates a user, or better, creates a one-time
   invite link (new `UserInvitation`: token hash, email, expiry). The invitee sets their own password, then their own
   passphrase. The admin never handles anyone's passphrase.
2. **Remove the admin content bypass.** `IsInstanceAdmin` shortcuts in `core/access` and the store drivers (about 50 call
   sites) stop granting memo, attachment, reaction or Space access. Instance admin keeps only instance concerns: settings,
   user invites, disabling or deleting accounts, storage. With E2EE the bypass would only ever return ciphertext anyway,
   so removing it makes the rule match reality.
3. **No implicit visibility between users.** Memos are always `PRIVATE` (author only) or `SPACE` (members of one Space).
   `PROTECTED` (all users of the instance) and `PUBLIC` are removed from the UI and rejected by the API, because they
   cannot be encrypted for "everyone".
4. **Space invites stay inside the instance.** A Space admin invites an existing user by username, as today. `ListUsers`
   is already admin-only, so regular users cannot enumerate the instance; they can only look up an exact username.

## 4. End-to-end encryption

### Threat model

The server, GCP, the admin, and anyone with database or bucket access see ciphertext for memo bodies, comments,
attachments and their names, Space titles and descriptions. They see metadata: who is in which Space, timestamps, sizes,
counts, pins, relations, reactions. A compromised server could ship JavaScript that steals the passphrase, which is the
limit of any browser-based E2EE app.

### Keys

Per user (hopnote design, its crypto suite passes 14 of 14):

- Account key pair: X25519 for key exchange plus Ed25519 for signatures, generated in the browser.
- Personal content key `PK` (random 256-bit) for memos with no Space.
- Passphrase -> Argon2id (64 MiB, t=3) -> key that wraps the private keys and `PK`. A recovery key wraps them too.
- Stored as `UserSetting ENCRYPTION_KEYRING`. The public keys are readable by other users so they can share with you.

Per Space:

- Space key `SK` (random 256-bit), with an epoch number.
- For each member, `SK` is sealed to that member's X25519 public key and stored on the membership. `space_member` today
  is `(space_id, user_id, status, role)`, so this adds a `wrapped_space_keys: [{epoch, sealed}]` field (a new column in
  each SQL driver's migration plus `LATEST.sql`, a plain field in Firestore).
- Invite: the inviting Space admin's browser seals `SK` to the invitee's public key when creating the invitation. On
  accept, the server copies it to the membership. The server never sees `SK`.
- Remove a member: the next admin action rotates to a new epoch, seals the new `SK` to remaining members, and new memos
  use it. Old memos stay on the old epoch (the removed member may have cached them anyway). Optional re-encrypt of old
  memos.
- Trust: on first contact the inviter sees the invitee's key fingerprint. Showing and comparing fingerprints is
  optional, but it is the only defense against a malicious server swapping keys.

### What gets encrypted

| Data | Key |
| --- | --- |
| Memo content and comments | `PK` if unassigned, `SK` if in a Space. AAD = memo uid, Space uid, epoch, version |
| Attachments (bytes, filename, MIME) | Random per-file key, wrapped by the memo's key. Encrypted in chunks for large files |
| Thumbnails | Generated in the browser, encrypted like attachments |
| Space title and description | `SK` |
| Tags | Encrypted inside the content. Optional blind index (HMAC of the tag with a key derived from `PK`/`SK`) so the server can still filter by tag without learning names |
| Saved filters (memo views) | `PK` |

### Server features that change

| Feature | Plan |
| --- | --- |
| Search, content filters, task/link/code flags, title | Client side, over decrypted memos, with an in-memory index per session |
| Tag tree and tag filter | Client side, plus the blind index for server-side paging |
| `MemoPayload` rebuild (`memopayload.RebuildMemoPayload`, called inline on create, update and import) | Skipped for encrypted content. The client sends the blind-index tags and flags |
| Public share links, `PUBLIC`, `PROTECTED`, RSS | Removed. Possible later: share link with key in the URL fragment |
| AI, MCP server, webhooks, email notification bodies, link previews, mention parsing | Off. Notifications send "new memo in Space X" without content |
| Server-side export and import | Client-side export of decrypted memos |
| Third-party apps and API tokens | See ciphertext only. The web app (installable PWA) is the client |

### Unlock UX

Sign in with password, then enter passphrase (first time: create passphrase, save recovery key). Option to remember the
device for 30 days as a non-extractable key in IndexedDB. Auto-lock after idle. Changing the passphrase rewraps keys only.

## 5. Phases

| # | Phase | Done when |
| --- | --- | --- |
| 0 | Backup: in-app export now; skoop debug storage download is blocked (reported) | You hold an export |
| 1 | Firestore driver + Mongo filter renderer, `DRIVER=firestore` test suite green on Mongo, then on real Firestore | `go test ./store/...` green for 4 drivers |
| 2 | skoop: add `firestore/mongodb`, grant `datastore.user` + `datastore.indexAdmin` with the IAM condition, build image from this repo, migration job, switch, drop the FUSE mount, GCS attachment provider | Live site on Firestore with your data |
| 3 | Access model: invite-only signup, invite links, remove admin bypass, drop `PUBLIC`/`PROTECTED` | Server tests cover isolation |
| 4 | E2EE personal: keyring, unlock UI, encrypted memos, client search/tags/filters, encrypt existing memos | All personal memos are ciphertext in Firestore |
| 5 | E2EE Spaces: account key pairs, Space keys, invite/accept/remove/rotate | Two test users share an encrypted Space |
| 6 | Encrypted attachments and thumbnails, client export | No plaintext files in the bucket |
| 7 | Hardening: CSP, auto-lock, recovery drill, fingerprints, restore drill | Checklist done |

Phases 1 to 2 can ship before E2EE, so the database risk goes away first.

## 6. Remaining questions

1. Tags: encrypted with a blind index (recommended), or plaintext?
2. Remember device for 30 days, or passphrase every visit?
3. Is losing public share links acceptable for now?
4. Do you, as admin, need to see a list of all users and Spaces (names only, encrypted titles would show as "locked")?
