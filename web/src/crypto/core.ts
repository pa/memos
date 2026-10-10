// AES-256-GCM sealing, KDFs and encoding helpers. Everything here runs on the
// device; the server only ever sees the `Sealed` blobs this file produces.

import { argon2id } from "hash-wasm";

/** An AES-256-GCM ciphertext as stored on the server. `v` versions the format. */
export interface Sealed {
  v: 1;
  iv: string; // base64, 12 bytes
  ct: string; // base64, ciphertext + 16-byte tag
}

/** Argon2id parameters, stored next to the salt so they can be raised later. */
export interface KdfParams {
  alg: "argon2id";
  m: number; // memory, KiB
  t: number; // iterations
  p: number; // parallelism
  salt: string; // base64, 16 bytes
}

/** Production Argon2id cost: 64 MiB, 3 passes (OWASP's second recommended profile). */
export const DEFAULT_KDF = { m: 65536, t: 3, p: 1 } as const;

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Returns `n` cryptographically random bytes. */
export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Standard base64 for bytes. */
export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** Decodes standard base64 to bytes. */
export function fromB64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** UTF-8 encode. */
export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return enc.encode(s);
}

/** UTF-8 decode. */
export function fromUtf8(b: Uint8Array): string {
  return dec.decode(b);
}

/** Imports 32 raw bytes as a non-extractable AES-256-GCM key. */
export function aesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error("AES-256 key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/**
 * Encrypts `plain` under `key`. `aad` names what the ciphertext is (record + field)
 * so it cannot be moved to another record without failing to open.
 */
export async function seal(key: CryptoKey, plain: Uint8Array<ArrayBuffer>, aad: string): Promise<Sealed> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, key, plain);
  return { v: 1, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

/** Decrypts a `Sealed` blob. Throws if the key, AAD or bytes are wrong. */
export async function open(key: CryptoKey, blob: Sealed, aad: string): Promise<Uint8Array<ArrayBuffer>> {
  if (blob.v !== 1) throw new Error(`unsupported blob version ${blob.v}`);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(blob.iv), additionalData: utf8(aad) }, key, fromB64(blob.ct));
  return new Uint8Array(plain);
}

/** Seals a UTF-8 string. */
export function sealText(key: CryptoKey, text: string, aad: string): Promise<Sealed> {
  return seal(key, utf8(text), aad);
}

/** Opens a sealed UTF-8 string. */
export async function openText(key: CryptoKey, blob: Sealed, aad: string): Promise<string> {
  return fromUtf8(await open(key, blob, aad));
}

/** Derives a 32-byte key from a passphrase with Argon2id. */
export async function deriveFromPassphrase(passphrase: string, params: KdfParams): Promise<Uint8Array<ArrayBuffer>> {
  const out = await argon2id({
    password: passphrase.normalize("NFKC"),
    salt: fromB64(params.salt),
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: 32,
    outputType: "binary",
  });
  return new Uint8Array(out);
}

/** HKDF-SHA256 from high-entropy input to a 32-byte key, separated by `info`. */
export async function hkdf32(ikm: Uint8Array<ArrayBuffer>, info: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: utf8(info) }, base, 256);
  return new Uint8Array(bits);
}
