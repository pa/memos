# Memos on skoop, with passphrase end-to-end encryption

Status: draft for discussion (not implemented).

## 1. What skoop gives us

The skoop catalog for the `memos` app (read live from `skoop get resource-types`):

| Kind | Use for memos | Limits that matter |
| --- | --- | --- |
| `cloudrun/cpu` | The memos server | Stateless, scale to zero, max 5 instances, 1 vCPU, up to 2Gi, CPU throttled between requests |
| `cloudrun/cpu-job` | One-off jobs (migration, backfill) | Run to completion |
| `gcs/standard` | Attachments, DB replica, backups | IAM scoped to the bucket |
| `firestore/mongodb` | Document DB over the MongoDB wire protocol | No SQL, `retryWrites=false`, stale idle connections |
| `firebase_hosting/gcp` | Front door, `notes.pramodhayyappan.dev`, TLS, CDN | Forwards only the `__session` cookie, caches anything `public` |
| `identity/gcp` | Google, GitHub, email link sign-in | Not needed, memos has its own auth |
| `pubsub`, `cloud_tasks` | Async work | Not needed now |

There is no Postgres or MySQL kind. The only managed database is Firestore (Mongo API).

## 2. What is deployed today, and what is wrong with it

`cloudrun/web` runs the stock image with `MEMOS_DATA=/var/opt/memos` on a GCS FUSE mount of `gcs/notes`, `max_instances=1`.
`firebase_hosting/front` fronts it on the custom domain.

Problems, most urgent first:

1. **SQLite on GCS FUSE is unsafe.** FUSE has no file locking and no shared memory for the WAL `-shm` file, every write
   rewrites whole objects, and two instances overlapping during a deploy can both write. This is a corruption and data
   loss risk, not only a speed issue.
2. **Refresh cookie (verified OK today).** The skoop readme says Firebase Hosting forwards only `__session`, but a live
   probe on 2026-10-10 showed `memos_refresh` does reach the server on `/memos.api.v1.AuthService/RefreshToken`
   ("invalid refresh token" versus "refresh token not found" without it). No change needed now. Renaming to
   `__session` stays an optional hardening item if this platform behavior changes.
3. **CDN caching (verified OK).** Attachments are served `private, no-store`, and API responses `no-store`. Only avatars
   on a public instance are `public, max-age=3600`, which is fine. Enabling `cdn.enforce_no_store` is optional defense
   in depth.
4. **Attachments default to LOCAL storage** (`storageFromLegacySetting` in `store/storage.go`), which means files under
   `MEMOS_DATA`, today the GCS FUSE mount. It works but is slow, and it disappears once the FUSE mount is removed.
5. skoop shows pending changes on all three resources that were never released.

## 3. Database: options

### Option A (recommended): SQLite on local disk, replicated to GCS with Litestream

- DB file lives on the container's local disk (`/tmp`, memory backed). On start: `litestream restore` from
  `gs://<bucket>/db`. While running: `litestream replicate -exec memos` streams WAL pages to GCS.
- Keep `max_instances=1`. Add a single-writer lease (a GCS object with `if-generation-match`) so a new revision waits for
  the old one to flush and exit during a deploy. Without it, the overlap window can lose writes.
- CPU throttling between requests can delay replication. The live revision has `run.googleapis.com/cpu-throttling:
  true`, and the module's `annotations` field sets service annotations, not revision template ones, so we cannot
  assume it can be turned off. Plan: a write-path hook (Connect interceptor on mutating RPCs) that blocks until
  Litestream has synced the WAL before responding (Litestream as a Go library, not a sidecar), plus a final flush on
  SIGTERM.
- Code change is small: Dockerfile, entrypoint, lease. Zero changes to the 66-method store driver, the CEL to SQL
  filter engine, or migrations. Upstream merges stay easy.
- Cost: cold start includes a restore (fast for a notes DB). Single instance forever, fine for personal use.

### Option B: a Firestore (Mongo) store driver

- New `store/db/firestore` implementing all of `store.Driver` (about 66 methods, sqlite driver is 4.4k lines), a Mongo
  renderer for the `filter/` engine (today it only emits SQL), migrations re-thought, transactions checked against the
  Firestore Mongo API.
- Gains: real multi-instance scaling, no restore on cold start.
- Cost: weeks of work, large permanent fork surface, every upstream schema change needs porting.

E2EE (section 5) moves search and filtering to the client anyway, which removes much of what a richer database would buy.

### Attachments

Add a native GCS storage provider in `provider/storage/gcs` using the service account (no HMAC keys), set it as the
default, and copy existing local files (and any DB-stored blobs) to it with references updated. Optionally use V4 signed URLs (`enable_url_signing`). With E2EE the
objects are ciphertext anyway.

## 4. skoop wiring (Option A)

- `cloudrun/web`: build from this repo with `--source`, a skoop Dockerfile that builds the frontend too (linux/amd64).
  Remove `gcs_volumes`. Env: `MEMOS_DRIVER=sqlite`, `MEMOS_DSN=/tmp/memos/memos_prod.db`, replica URL and attachment
  bucket from `${gcs.notes.out.attributes.bucket_name}`. Keep the existing `roles/storage.objectAdmin` grant with its
  bucket condition. If we enable a probe, add a `/health/live` route (Cloud Run reserves paths ending in `z`, so
  `/healthz` is not reachable from Cloud Run probes).
- `firebase_hosting/front`: set `cdn.enforce_no_store=true` with a whitelist for hashed `/assets/**` only.
- One-time migration: copy the current `memos_prod.db` from the bucket, checkpoint it, seed the Litestream replica.

## 5. End-to-end encryption with a passphrase

### Threat model

The server, GCP, and anyone with bucket or DB access see only ciphertext for memo bodies and attachments. They still see
metadata: timestamps, sizes, counts, pinned, visibility, relations, and reactions. Caveat: the server ships the web app,
so a compromised server could ship JS that steals the passphrase. That is true of every browser-based E2EE app.

### Keys (same design as hopnote; its `web/src/crypto` suite passes, 14 of 14 tests on 2026-10-10)

- Random 256-bit master key (MK) per user.
- Passphrase -> Argon2id (64 MiB, t=3) -> KEK, wraps MK with AES-256-GCM.
- Recovery key (shown once) also wraps MK. Lose both and the data is gone, by design.
- Keyring stored server-side as a new `UserSetting` key `ENCRYPTION_KEYRING` (public parameters and wrapped keys only).
- The login password and the passphrase are separate. Changing the passphrase rewraps MK, no re-encryption.
- Unlock after sign-in, MK held in memory. Optional "remember this device" as a non-extractable `CryptoKey` in
  IndexedDB. Auto-lock after idle.

### What gets encrypted

- **Memo content**: AES-256-GCM, AAD bound to memo uid and format version, stored in `memo.content` as a versioned
  envelope, with a new `encrypted` flag on the memo payload (proto change, regenerated).
- **Attachments**: encrypted client-side in chunks before upload. Filename and MIME type encrypted too. Thumbnails are
  generated in the browser and uploaded encrypted.
- **Comments** on your own encrypted memos: same key.

### What breaks, and the replacement

| Server feature | Why it breaks | Plan |
| --- | --- | --- |
| Search, `content.contains` filters | Server sees ciphertext | Client-side search over decrypted memos (in memory index) |
| Tags, tag tree, has_task_list, title (`MemoPayload`) | Server parses markdown | Client computes them. Open question: plaintext tags or encrypted |
| Public share links, PUBLIC visibility, RSS | Viewer has no key | Disabled for encrypted memos. Later: share link with key in URL fragment |
| Spaces shared with others | Members have no key | Out of scope for v1 (needs per-space keys) |
| AI features, MCP, webhooks, email content | Server cannot read | Disabled for encrypted memos |
| Link previews, mentions, EXIF, media metadata | Server cannot read | Client-side or dropped |
| Server-side export | Would export ciphertext | Client-side export |
| Third-party mobile apps on the API | See ciphertext | Only the web app (PWA) supports the vault |

### Existing plaintext memos

After the vault is created, the client encrypts existing memos in batches and rewrites them, with a progress bar and
resume. Old plaintext lingers in Litestream history until retention expires, so we shorten retention after migration.

## 6. Phases

0. **Hotfixes on today's deploy**: back up the current DB, release or discard the pending skoop changes. The live DB is
   `memos_prod.db` (148 KiB) plus an active `memos_prod.db-wal` in the bucket, so a copy of only the main file is
   incomplete. `skoop debug gcloud storage cat` cannot sign URLs yet (platform IAM gap, reported 2026-10-10), so for now
   use the in-app memo export from Settings. The migration in phase 1 must checkpoint the WAL from inside the app.
1. **Storage**: Litestream plus lease, GCS attachment provider, skoop Dockerfile, migrate data, drop the FUSE mount.
2. **E2EE core**: keyring, unlock and lock UI, encrypted memo content, client-side tags, search, and filters.
3. **Encrypted attachments** and client thumbnails.
4. **Migration** of existing memos and UI gating of incompatible features.
5. **Hardening**: crypto tests, CSP, auto-lock, recovery flow, restore drill.

## 7. Open questions

1. Option A (SQLite + Litestream) or Option B (Firestore driver)?
2. Encrypt every memo always, or a per-memo lock toggle?
3. Only you, or other users and shared spaces too?
4. OK to lose public share links, AI, MCP, webhooks, RSS for encrypted memos?
5. Tags plaintext (server tag tree works, tag names leak) or encrypted?
6. Remember device, or passphrase on every visit?
7. Do you use any Memos mobile or third-party app?
