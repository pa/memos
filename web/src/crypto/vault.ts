// The vault holds unlocked keys in memory only. Nothing secret is written to
// disk, so closing the browser (or the app) locks everything. It also locks
// after a period of inactivity. Tabs of the same browser share the unlocked
// keys over a same-origin BroadcastChannel, so opening a new tab does not ask
// for the passphrase again while another tab is unlocked.

import { fromB64, toB64 } from "./core";
import type { Secrets } from "./keyring";
import { PERSONAL_KEY_ID } from "./memo";

/** Auto-lock after this much inactivity. */
export const IDLE_LOCK_MS = 30 * 60 * 1000;

type Listener = () => void;

interface WireSecrets {
  ck: string;
  tk: string;
  sk: string;
  pk: string;
  user: string;
}

type ChannelMessage = { type: "ask"; user: string } | { type: "share"; secrets: WireSecrets } | { type: "lock"; user: string };

class Vault {
  private secrets: Secrets | undefined;
  private user: string | undefined;
  private spaceKeys = new Map<string, Uint8Array<ArrayBuffer>>();
  private listeners = new Set<Listener>();
  private idleTimer: ReturnType<typeof setTimeout> | undefined;
  private channel: BroadcastChannel | undefined;
  /** The signed-in user of this tab; shared keys for anyone else are ignored. */
  private expectedUser: string | undefined;

  constructor() {
    if (typeof BroadcastChannel !== "undefined") {
      this.channel = new BroadcastChannel("memos-vault");
      this.channel.onmessage = (event: MessageEvent<ChannelMessage>) => this.onMessage(event.data);
    }
    if (typeof window !== "undefined") {
      for (const name of ["pointerdown", "keydown", "visibilitychange"]) {
        window.addEventListener(name, () => this.touch(), { passive: true });
      }
    }
  }

  get unlocked(): boolean {
    return this.secrets !== undefined;
  }

  /** The user these keys belong to, as a resource name. */
  get owner(): string | undefined {
    return this.user;
  }

  get current(): Secrets | undefined {
    return this.secrets;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Sets who is signed in to this tab. Keys of a different user are dropped,
   * and keys shared by other tabs are accepted only for this user.
   */
  setSignedInUser(user: string | undefined) {
    this.expectedUser = user;
    if (this.user && this.user !== user) this.lock(false);
  }

  /** Stores unlocked secrets for `user` and tells other tabs. */
  unlock(user: string, secrets: Secrets, broadcast = true) {
    this.user = user;
    this.secrets = secrets;
    this.spaceKeys.clear();
    this.touch();
    if (broadcast) this.post({ type: "share", secrets: this.toWire() });
    this.emit();
  }

  /** Forgets every key in this tab and in other tabs of this user. */
  lock(broadcast = true) {
    const user = this.user;
    this.secrets = undefined;
    this.user = undefined;
    this.spaceKeys.clear();
    if (this.idleTimer) clearTimeout(this.idleTimer);
    if (broadcast && user) this.post({ type: "lock", user });
    this.emit();
  }

  /** Asks other open tabs for keys. Resolves true if one answered in time. */
  requestFromOtherTabs(user: string, timeoutMs = 300): Promise<boolean> {
    if (!this.channel || this.unlocked) return Promise.resolve(this.unlocked);
    return new Promise((resolve) => {
      const unsubscribe = this.subscribe(() => {
        if (this.unlocked) {
          unsubscribe();
          resolve(true);
        }
      });
      this.post({ type: "ask", user });
      setTimeout(() => {
        unsubscribe();
        resolve(this.unlocked);
      }, timeoutMs);
    });
  }

  /** Raw key bytes for a key id: the personal key, or an opened Space key. */
  resolveKey = (keyId: string): Uint8Array<ArrayBuffer> | undefined => {
    if (!this.secrets) return undefined;
    if (keyId === PERSONAL_KEY_ID) return this.secrets.contentKey;
    return this.spaceKeys.get(keyId);
  };

  /** Remembers an opened Space key for this session. */
  addSpaceKey(keyId: string, key: Uint8Array<ArrayBuffer>) {
    this.spaceKeys.set(keyId, key);
  }

  private touch() {
    if (!this.secrets) return;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.lock(), IDLE_LOCK_MS);
  }

  private emit() {
    for (const listener of this.listeners) listener();
  }

  private post(message: ChannelMessage) {
    this.channel?.postMessage(message);
  }

  private toWire(): WireSecrets {
    const s = this.secrets!;
    return { ck: toB64(s.contentKey), tk: toB64(s.tagKey), sk: toB64(s.privateKey), pk: toB64(s.publicKey), user: this.user! };
  }

  private onMessage(message: ChannelMessage) {
    switch (message.type) {
      case "ask":
        if (this.secrets && this.user === message.user) this.post({ type: "share", secrets: this.toWire() });
        break;
      case "share":
        if (!this.secrets && this.expectedUser && message.secrets.user === this.expectedUser) {
          const w = message.secrets;
          this.unlock(
            w.user,
            { contentKey: fromB64(w.ck), tagKey: fromB64(w.tk), privateKey: fromB64(w.sk), publicKey: fromB64(w.pk) },
            false,
          );
        }
        break;
      case "lock":
        if (this.user === message.user) this.lock(false);
        break;
    }
  }
}

export const vault = new Vault();
