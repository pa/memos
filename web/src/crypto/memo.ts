// Memo content encryption. A memo is stored as
//   memos-e2ee:v1:{"k":<key id>,"iv":..,"ct":..,"t":[blind tags],"p":{flags}}
// The ciphertext holds the full markdown. The blind tags and flags are the only
// things the server learns, and they exist so server-side filters keep working.
//
// AAD binds the ciphertext to the memo uid and key id, so the server cannot
// move one memo's ciphertext onto another memo or under another key.

import { aesKey, fromB64, fromUtf8, open, randomBytes, seal, toB64, utf8 } from "./core";

export const ENCRYPTED_PREFIX = "memos-e2ee:v1:";

/** Key id for the personal content key. Space keys use "sk:<space uid>:<epoch>". */
export const PERSONAL_KEY_ID = "pk";

export interface ContentFlags {
  hasLink?: boolean;
  hasCode?: boolean;
  hasTaskList?: boolean;
  hasIncompleteTasks?: boolean;
}

interface Envelope {
  k: string;
  iv: string;
  ct: string;
  t?: string[];
  p: { l?: boolean; c?: boolean; t?: boolean; i?: boolean };
}

export const isEncryptedContent = (content: string): boolean => content.startsWith(ENCRYPTED_PREFIX);

function memoAad(memoUid: string, keyId: string): string {
  return `memos:memo:v1:${memoUid}:${keyId}`;
}

/** Returns the key id an encrypted memo was sealed with, or undefined for plaintext. */
export function envelopeKeyId(content: string): string | undefined {
  if (!isEncryptedContent(content)) return undefined;
  try {
    return (JSON.parse(content.slice(ENCRYPTED_PREFIX.length)) as Envelope).k;
  } catch {
    return undefined;
  }
}

/** Encrypts markdown for a memo. `blindTags` must come from `blindTag`. */
export async function encryptMemoContent(
  markdown: string,
  opts: { memoUid: string; keyId: string; key: Uint8Array<ArrayBuffer>; blindTags: string[]; flags: ContentFlags },
): Promise<string> {
  const sealed = await seal(await aesKey(opts.key), utf8(markdown), memoAad(opts.memoUid, opts.keyId));
  const envelope: Envelope = {
    k: opts.keyId,
    iv: sealed.iv,
    ct: sealed.ct,
    p: {
      ...(opts.flags.hasLink ? { l: true } : {}),
      ...(opts.flags.hasCode ? { c: true } : {}),
      ...(opts.flags.hasTaskList ? { t: true } : {}),
      ...(opts.flags.hasIncompleteTasks ? { i: true } : {}),
    },
  };
  if (opts.blindTags.length > 0) envelope.t = [...new Set(opts.blindTags)];
  return ENCRYPTED_PREFIX + JSON.stringify(envelope);
}

/** Decrypts memo content. `resolveKey` maps a key id to raw key bytes. */
export async function decryptMemoContent(
  content: string,
  memoUid: string,
  resolveKey: (keyId: string) => Uint8Array<ArrayBuffer> | undefined,
): Promise<string> {
  const envelope = JSON.parse(content.slice(ENCRYPTED_PREFIX.length)) as Envelope;
  const key = resolveKey(envelope.k);
  if (!key) throw new Error(`No key for ${envelope.k}`);
  const plain = await open(await aesKey(key), { v: 1, iv: envelope.iv, ct: envelope.ct }, memoAad(memoUid, envelope.k));
  return fromUtf8(plain);
}

/**
 * Blind tag index: HMAC-SHA256 of the normalized tag with a key only the user
 * (or the Space) holds, truncated to 128 bits and hex encoded. Equal tags give
 * equal indexes, so the server can filter, but cannot read or guess names.
 */
export async function blindTag(tagKey: Uint8Array<ArrayBuffer>, tag: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", tagKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(`memos:tag:v1:${tag.normalize("NFC")}`)));
  return Array.from(mac.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A short code people can compare to make sure they see the same public key. */
export async function safetyCode(publicKey: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  const digits = Array.from(digest.slice(0, 10), (b) => (b % 100).toString().padStart(2, "0")).join("");
  return digits.match(/.{1,5}/g)!.join(" ");
}

/** A fresh 32-byte content key (for Spaces). */
export const newContentKey = (): Uint8Array<ArrayBuffer> => randomBytes(32);

export { fromB64, toB64 };
