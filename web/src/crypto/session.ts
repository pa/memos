// Keeps the unlocked vault across page reloads without ever writing raw keys
// to disk. A device key is created as a non-extractable AES key and kept in
// IndexedDB: the browser can use it but no script can read its bytes. The
// secrets are sealed with it and stored in sessionStorage (cleared when the
// browser restarts) or localStorage (the "never lock" choice).

import { fromB64, fromUtf8, open, type Sealed, seal, toB64, utf8 } from "./core";
import type { Secrets } from "./keyring";

/** When the vault locks, like Bitwarden's vault timeout. */
export type LockPolicy = "restart" | "idle-15m" | "idle-1h" | "idle-4h" | "never";

export const LOCK_POLICIES: readonly LockPolicy[] = ["restart", "idle-15m", "idle-1h", "idle-4h", "never"];

const POLICY_KEY = "memos-e2ee-lock-policy";
const SEALED_KEY = "memos-e2ee-session";
const DB_NAME = "memos-e2ee";
const STORE = "keys";
const DEVICE_KEY_ID = "device";
const AAD = "memos:session:v1";

/** Idle time before locking, or undefined for no idle lock. */
export function idleTimeoutMs(policy: LockPolicy): number | undefined {
  switch (policy) {
    case "idle-15m":
      return 15 * 60 * 1000;
    case "idle-1h":
      return 60 * 60 * 1000;
    case "idle-4h":
      return 4 * 60 * 60 * 1000;
    default:
      return undefined;
  }
}

/** The lock policy chosen on this device. Defaults to locking on browser restart. */
export function getLockPolicy(): LockPolicy {
  try {
    const value = localStorage.getItem(POLICY_KEY) as LockPolicy | null;
    return value && LOCK_POLICIES.includes(value) ? value : "restart";
  } catch {
    return "restart";
  }
}

export function setLockPolicy(policy: LockPolicy) {
  localStorage.setItem(POLICY_KEY, policy);
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idb<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const request = run(tx.objectStore(STORE));
        tx.oncomplete = () => {
          db.close();
          resolve(request.result);
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error);
        };
      }),
  );
}

async function deviceKey(create: boolean): Promise<CryptoKey | undefined> {
  const existing = await idb<CryptoKey | undefined>("readonly", (s) => s.get(DEVICE_KEY_ID) as IDBRequest<CryptoKey | undefined>);
  if (existing || !create) return existing;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idb("readwrite", (s) => s.put(key, DEVICE_KEY_ID));
  return key;
}

interface Stored {
  user: string;
  sealed: Sealed;
}

function storageFor(policy: LockPolicy): Storage {
  return policy === "never" ? localStorage : sessionStorage;
}

function clearStored() {
  try {
    sessionStorage.removeItem(SEALED_KEY);
    localStorage.removeItem(SEALED_KEY);
  } catch {
    // Storage unavailable (private mode); nothing to clear.
  }
}

/** Saves the unlocked secrets for this device according to the lock policy. */
export async function persistSession(user: string, secrets: Secrets): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const policy = getLockPolicy();
  clearStored();
  try {
    const key = await deviceKey(true);
    if (!key) return;
    const bundle = utf8(
      JSON.stringify({
        ck: toB64(secrets.contentKey),
        tk: toB64(secrets.tagKey),
        sk: toB64(secrets.privateKey),
        pk: toB64(secrets.publicKey),
      }),
    );
    const stored: Stored = { user, sealed: await seal(key, bundle, `${AAD}:${user}`) };
    storageFor(policy).setItem(SEALED_KEY, JSON.stringify(stored));
  } catch {
    // Persisting is a convenience; without it the user unlocks again after a reload.
  }
}

/** Restores secrets saved by persistSession for `user`, if any. */
export async function restoreSession(user: string): Promise<Secrets | undefined> {
  if (typeof indexedDB === "undefined") return undefined;
  try {
    const raw = sessionStorage.getItem(SEALED_KEY) ?? localStorage.getItem(SEALED_KEY);
    if (!raw) return undefined;
    const stored = JSON.parse(raw) as Stored;
    if (stored.user !== user) return undefined;
    const key = await deviceKey(false);
    if (!key) return undefined;
    const json = JSON.parse(fromUtf8(await open(key, stored.sealed, `${AAD}:${user}`))) as Record<string, string>;
    return { contentKey: fromB64(json.ck), tagKey: fromB64(json.tk), privateKey: fromB64(json.sk), publicKey: fromB64(json.pk) };
  } catch {
    clearStored();
    return undefined;
  }
}

/** Forgets the saved session (on lock or sign-out). */
export function forgetSession() {
  clearStored();
}
