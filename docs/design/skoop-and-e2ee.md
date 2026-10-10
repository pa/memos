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

None. Decided 2026-10-10: start fresh on Firestore. The old SQLite files stay untouched in the `gcs/notes` bucket.

### As built (2026-10-10)

- Uniqueness does not use unique indexes. The Firestore IAM condition skoop emits
  (`resource.name == "projects/<p>/databases/<db>"`) does not cover index creation on collection groups, so the
  runtime identity cannot create indexes (reported to skoop). Composite-key rows use the key as `_id`; unique columns
  are claimed in a `uniques` collection in the same transaction. Query indexes are created in the background,
  best-effort.
- Writes that add a child row (invitation, memo in a Space, reaction, comment) bump a version field on the parent, so a
  concurrent parent delete conflicts and retries. This replaces the SQL drivers' row locks.
- Store suite with `DRIVER=firestore` on MongoDB 7: 302 pass, 17 skipped (raw SQL setup or released-binary upgrades).
  SQLite suite unchanged. Not yet run against the real Firestore database.

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

Requirement (2026-10-10): every user has exactly one passphrase, and no passphrase is ever shared, typed by someone
else, or sent to the server. Team sharing must still work. Recommended design: automatic key exchange (Option B below).

#### Option A, shared Space passphrase (rejected)

The Space owner sets a second passphrase and hands it to members. Rejected because it is a shared secret: it has to be
passed around, it leaks when anyone leaks it, and it must be re-shared after each removal.

#### Option B, automatic key exchange (recommended)

Keys never leave the browser unencrypted. Each user has one passphrase.

Per user (hopnote design, its crypto suite passes 14 of 14):

- Personal content key `PK` (random 256-bit) encrypts memos not shared to a Space.
- An X25519 key pair (Web Crypto). The public key is like an open padlock: anyone may use it to lock something for this
  user. The private key is the only key that opens it.
- Passphrase -> Argon2id (64 MiB, t=3) -> key that wraps `PK` and the private key. A recovery key, shown once, wraps
  them too. Stored as `UserSetting ENCRYPTION_KEYRING`. The public key is stored in the clear so teammates can use it.

Per Space:

- Space key `SK` (random 256-bit), created in the owner's browser when the Space is created.
- For each member, the browser locks `SK` with that member's public key (X25519 + HKDF + AES-GCM, an ECIES-style seal)
  and saves the result on the membership. `space_member` today is `(space_id, user_id, status, role)`, so it gains a
  `sealed_space_key` field (new column in each SQL driver's migration plus `LATEST.sql`, plain field in Firestore).
- Invite: when a Space admin invites someone, the admin's browser seals `SK` to the invitee's public key. The invitee
  accepts, signs in with their own passphrase, and their browser opens `SK` with their private key. Nobody types anything
  extra.
- An invitee who has not set up encryption yet has no public key. The invite stays pending until they do, then any Space
  admin's browser finishes the seal automatically the next time it is open.
- Remove a member: the admin's browser creates a new `SK` (next epoch) and seals it to the remaining members. New memos use
  it. Old memos stay on the old epoch unless the admin chooses "re-encrypt history", because the removed member may
  already have read them.
- The instance admin is not a member of other people's Spaces, so no `SK` is ever sealed to them and they read nothing.

What each party can see:

| Who | Personal memos of Alice | Memos in Alice's team Space |
| --- | --- | --- |
| Alice | Yes (her passphrase) | Yes (her passphrase opens her private key, which opens `SK`) |
| Bob, member of the Space | No | Yes (his own passphrase, same chain) |
| Carol, not a member | No | No |
| Instance admin, server, GCP | No | No |

Alice's passphrase is never shown to, typed by, or derivable by Bob. Bob only ever receives `SK` locked to his own key.

Proof of concept (2026-10-10, standard Web Crypto X25519 + HKDF + AES-GCM, Node 26): Alice sealed `SK` using only Bob's
public key, Bob opened it with his private key and read a memo encrypted with `SK`, Carol's private key failed to open
it, and replaying the sealed key into another Space was rejected by the AAD binding.

Browser support: the same proof of concept also passed unchanged in a real browser, headless Chrome 154 on macOS
(2026-10-10). Safari was not run locally; per published sources X25519 in Web Crypto ships in Firefox 130+, Safari 17+ and
Chrome/Edge 137+, and a public measurement on 2026-09-04 found it working in Safari 26.5 (iOS 26.5). Verify on an iPhone
before phase 5 ships. Older browsers get a clear "update your
browser" message. A JS fallback (`@noble/curves`) is possible but not planned, to avoid bundling crypto.

Trust caveat: a malicious server could hand Alice a fake public key for Bob and read what she seals to it. Defense: each
user has a short safety code (a fingerprint of their public key) on their profile. Teammates can compare it once, in
person or by chat, and the app warns if a teammate's key ever changes. This is the same model Signal and WhatsApp use, and
it is optional for a small trusted team.

### Sharing a memo with the team

- A memo is always encrypted. In the editor, the Space picker decides which key: no Space means `PK` (only you), a Space
  means `SK` (that team).
- Moving a memo into a Space re-encrypts it from `PK` to `SK` in the browser. Moving it out re-encrypts it back to `PK`.
- A memo belongs to at most one Space. Sharing one memo with several teams does not exist in Memos today and is out of
  scope.

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

### Scale (for example 1 TB)

- Almost all of the volume will be attachments. They live in Cloud Storage and stream in encrypted chunks, so size does not
  slow the app down.
- Memo text is small. Firestore scales storage and reads on its own. Timeline, Space feed and date views page by time
  on the server and stay fast at any size, because only the visible page is downloaded and decrypted.
- Full-text search is the one cost of E2EE: the server cannot search ciphertext. Plan: each browser keeps a local search
  index in IndexedDB, built once and then updated as memos change. A new device builds it in the background. Tag filters
  use the blind index on the server, so they stay fast without the local index.

### Unlock UX

Sign in with password, then enter your one passphrase (first time: create it, save recovery key). Spaces open
automatically, there is no extra passphrase. Option to remember the device for 30 days as a non-extractable key
in IndexedDB. Auto-lock after idle. Changing the personal passphrase rewraps keys only.

## 5. Phases

| # | Phase | Done when |
| --- | --- | --- |
| 0 | Backup: skipped, starting fresh | Done |
| 1 | Firestore driver + Mongo filter renderer, `DRIVER=firestore` test suite green on Mongo, then on real Firestore | Done on Mongo; real Firestore pending |
| 2 | skoop: add `firestore/mongodb`, grants, build image from this repo, switch, drop the FUSE mount, GCS attachment provider | Live on Firestore 2026-10-10; GCS attachment provider pending |
| 3 | Access model: invite-only signup, invite links, remove admin bypass, drop `PUBLIC`/`PROTECTED` | Server tests cover isolation |
| 4 | E2EE personal: keyring, unlock UI, encrypted memos, client search/tags/filters, encrypt existing memos | All personal memos are ciphertext in Firestore |
| 5 | E2EE Spaces: user key pairs, Space key sealed per member on invite, move memo in/out re-encrypts, rotate on removal, safety codes | Two test users share an encrypted Space with no shared passphrase; a third user and the instance admin see only ciphertext |
| 6 | Encrypted attachments and thumbnails, client export | No plaintext files in the bucket |
| 7 | Hardening: CSP, auto-lock, recovery drill, restore drill | Checklist done |

Phases 1 to 2 can ship before E2EE, so the database risk goes away first.

## 6. Remaining questions

1. Tags: encrypted with a blind index (recommended), or plaintext?
2. Remember device for 30 days, or passphrase every visit?
3. Is losing public share links acceptable for now?
4. Do you, as admin, need to see a list of all users and Spaces (names only, encrypted titles would show as "locked")?
