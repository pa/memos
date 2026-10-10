// @vitest-environment node
// Node's Web Crypto keeps CryptoKey objects usable when stored by reference, like IndexedDB does.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Secrets } from "@/crypto/keyring";
import { forgetSession, getLockPolicy, idleTimeoutMs, persistSession, restoreSession, setLockPolicy } from "@/crypto/session";

class MemoryStorage {
  private data = new Map<string, string>();
  getItem(key: string) {
    return this.data.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.data.set(key, String(value));
  }
  removeItem(key: string) {
    this.data.delete(key);
  }
  clear() {
    this.data.clear();
  }
}

// Just enough of IndexedDB for one object store with get/put.
function fakeIndexedDB() {
  const rows = new Map<string, unknown>();
  const request = <T>(result: T) => ({ result }) as unknown as IDBRequest<T>;
  return {
    open() {
      const req: Record<string, unknown> = {};
      const db = {
        createObjectStore() {},
        close() {},
        transaction() {
          const tx: Record<string, unknown> = {};
          tx.objectStore = () => ({
            get: (key: string) => request(rows.get(key)),
            put: (value: unknown, key: string) => {
              rows.set(key, value);
              return request(key);
            },
          });
          queueMicrotask(() => (tx.oncomplete as () => void)());
          return tx;
        },
      };
      req.result = db;
      queueMicrotask(() => {
        (req.onupgradeneeded as (() => void) | undefined)?.();
        (req.onsuccess as () => void)();
      });
      return req;
    },
  };
}

const secrets = (): Secrets => ({
  contentKey: crypto.getRandomValues(new Uint8Array(32)),
  tagKey: crypto.getRandomValues(new Uint8Array(32)),
  privateKey: crypto.getRandomValues(new Uint8Array(32)),
  publicKey: crypto.getRandomValues(new Uint8Array(32)),
});

let session: MemoryStorage;
let local: MemoryStorage;

beforeEach(() => {
  session = new MemoryStorage();
  local = new MemoryStorage();
  vi.stubGlobal("sessionStorage", session);
  vi.stubGlobal("localStorage", local);
  vi.stubGlobal("indexedDB", fakeIndexedDB());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("e2ee session", () => {
  it("defaults to locking on browser restart", () => {
    expect(getLockPolicy()).toBe("restart");
    local.setItem("memos-e2ee-lock-policy", "bogus");
    expect(getLockPolicy()).toBe("restart");
    expect(idleTimeoutMs("restart")).toBeUndefined();
    expect(idleTimeoutMs("never")).toBeUndefined();
    expect(idleTimeoutMs("idle-15m")).toBe(15 * 60 * 1000);
  });

  it("restores secrets after a reload, sealed in sessionStorage", async () => {
    const s = secrets();
    await persistSession("users/a", s);
    const raw = session.getItem("memos-e2ee-session")!;
    expect(raw).toBeTruthy();
    expect(local.getItem("memos-e2ee-session")).toBeNull();
    for (const bytes of Object.values(s)) expect(raw).not.toContain(Buffer.from(bytes).toString("base64"));
    expect(await restoreSession("users/a")).toEqual(s);
  });

  it("does not restore after a browser restart under the default policy", async () => {
    await persistSession("users/a", secrets());
    session.clear(); // what a browser restart does
    expect(await restoreSession("users/a")).toBeUndefined();
  });

  it("keeps the session across restarts when set to never lock", async () => {
    setLockPolicy("never");
    const s = secrets();
    await persistSession("users/a", s);
    session.clear();
    expect(await restoreSession("users/a")).toEqual(s);
  });

  it("refuses another user, tampering, and forgotten sessions", async () => {
    await persistSession("users/a", secrets());
    expect(await restoreSession("users/b")).toBeUndefined();

    const stored = JSON.parse(session.getItem("memos-e2ee-session")!);
    stored.user = "users/b"; // AAD binds the user, so relabelling fails to open
    session.setItem("memos-e2ee-session", JSON.stringify(stored));
    expect(await restoreSession("users/b")).toBeUndefined();
    expect(session.getItem("memos-e2ee-session")).toBeNull();

    await persistSession("users/a", secrets());
    forgetSession();
    expect(await restoreSession("users/a")).toBeUndefined();
  });
});
