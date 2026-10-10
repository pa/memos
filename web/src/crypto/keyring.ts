// The keyring holds the user's secrets, sealed twice: once with a key derived
// from the passphrase, once with the recovery key. The server stores it and can
// open neither copy. Inside: the personal content key, the tag index key, and
// the X25519 private key used to receive Space keys.

import {
  aesKey,
  DEFAULT_KDF,
  deriveFromPassphrase,
  fromB64,
  fromUtf8,
  hkdf32,
  type KdfParams,
  open,
  randomBytes,
  type Sealed,
  seal,
  toB64,
  utf8,
} from "./core";
import { decodeRecoveryKey, encodeRecoveryKey } from "./recovery";

/** What the server stores per user (opaque JSON in the ENCRYPTION setting). */
export interface Keyring {
  v: 1;
  kdf: KdfParams;
  /** The secrets bundle sealed with the passphrase key. */
  wrapped: Sealed;
  /** The same bundle sealed with the recovery key. */
  wrapped_recovery: Sealed;
}

/** The user's secrets once unlocked. Raw bytes never leave this device. */
export interface Secrets {
  /** Personal content key: encrypts memos not shared to a Space. */
  contentKey: Uint8Array<ArrayBuffer>;
  /** Keyed-hash key for blind tag indexes. */
  tagKey: Uint8Array<ArrayBuffer>;
  /** X25519 private key, PKCS#8. */
  privateKey: Uint8Array<ArrayBuffer>;
  /** X25519 public key, raw 32 bytes. */
  publicKey: Uint8Array<ArrayBuffer>;
}

const AAD_PASS = "memos:keyring:v1:passphrase";
const AAD_RECOVERY = "memos:keyring:v1:recovery";
const RECOVERY_INFO = "memos recovery v1";

/** Minimum passphrase length enforced on setup. */
export const MIN_PASSPHRASE = 10;

/** A fresh keyring plus the secrets and the recovery key the user sees once. */
export interface NewKeyring {
  keyring: Keyring;
  secrets: Secrets;
  recoveryKey: string;
}

async function generateX25519(): Promise<{ privateKey: Uint8Array<ArrayBuffer>; publicKey: Uint8Array<ArrayBuffer> }> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const privateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey, publicKey };
}

function encodeSecrets(secrets: Secrets): Uint8Array<ArrayBuffer> {
  return utf8(
    JSON.stringify({
      ck: toB64(secrets.contentKey),
      tk: toB64(secrets.tagKey),
      sk: toB64(secrets.privateKey),
      pk: toB64(secrets.publicKey),
    }),
  );
}

function decodeSecrets(bytes: Uint8Array): Secrets {
  const json = JSON.parse(fromUtf8(bytes)) as Record<string, string>;
  const secrets: Secrets = {
    contentKey: fromB64(json.ck),
    tagKey: fromB64(json.tk),
    privateKey: fromB64(json.sk),
    publicKey: fromB64(json.pk),
  };
  if (secrets.contentKey.length !== 32 || secrets.tagKey.length !== 32 || secrets.publicKey.length !== 32) {
    throw new Error("This keyring is damaged.");
  }
  return secrets;
}

async function recoveryWrappingKey(recovery: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return aesKey(await hkdf32(recovery, RECOVERY_INFO));
}

async function sealKeyring(
  secrets: Secrets,
  passphrase: string,
  recovery: Uint8Array<ArrayBuffer>,
  cost: Pick<KdfParams, "m" | "t" | "p">,
) {
  const kdf: KdfParams = { alg: "argon2id", ...cost, salt: toB64(randomBytes(16)) };
  const kek = await aesKey(await deriveFromPassphrase(passphrase, kdf));
  const bundle = encodeSecrets(secrets);
  const keyring: Keyring = {
    v: 1,
    kdf,
    wrapped: await seal(kek, bundle, AAD_PASS),
    wrapped_recovery: await seal(await recoveryWrappingKey(recovery), bundle, AAD_RECOVERY),
  };
  return keyring;
}

/** Creates all secrets and seals them under the passphrase and a new recovery key. */
export async function createKeyring(passphrase: string, cost: Pick<KdfParams, "m" | "t" | "p"> = DEFAULT_KDF): Promise<NewKeyring> {
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Use at least ${MIN_PASSPHRASE} characters.`);
  const { privateKey, publicKey } = await generateX25519();
  const secrets: Secrets = { contentKey: randomBytes(32), tagKey: randomBytes(32), privateKey, publicKey };
  const recovery = randomBytes(32);
  return { keyring: await sealKeyring(secrets, passphrase, recovery, cost), secrets, recoveryKey: encodeRecoveryKey(recovery) };
}

/**
 * Seals existing secrets under a new passphrase and a new recovery key. Content
 * keys do not change, so no memo needs re-encrypting.
 */
export async function rewrapKeyring(
  secrets: Secrets,
  passphrase: string,
  cost: Pick<KdfParams, "m" | "t" | "p"> = DEFAULT_KDF,
): Promise<{ keyring: Keyring; recoveryKey: string }> {
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Use at least ${MIN_PASSPHRASE} characters.`);
  const recovery = randomBytes(32);
  return { keyring: await sealKeyring(secrets, passphrase, recovery, cost), recoveryKey: encodeRecoveryKey(recovery) };
}

/**
 * Refuses KDF params outside what this client would ever create, so a hostile
 * server can't make the device burn gigabytes of memory, or a weak setting slip in.
 */
export function assertSaneKdf(kdf: KdfParams): void {
  const ok = kdf.alg === "argon2id" && kdf.m >= 19456 && kdf.m <= 262144 && kdf.t >= 2 && kdf.t <= 10 && kdf.p >= 1 && kdf.p <= 4;
  if (!ok) throw new Error("This keyring's settings look wrong. Refusing to unlock.");
}

function isDecryptFailure(err: unknown): boolean {
  return err instanceof DOMException && err.name === "OperationError";
}

/** Opens the keyring with the passphrase. Throws "Wrong passphrase." on failure. */
export async function unlockWithPassphrase(keyring: Keyring, passphrase: string): Promise<Secrets> {
  assertSaneKdf(keyring.kdf);
  const kek = await aesKey(await deriveFromPassphrase(passphrase, keyring.kdf));
  try {
    return decodeSecrets(await open(kek, keyring.wrapped, AAD_PASS));
  } catch (err) {
    if (isDecryptFailure(err)) throw new Error("Wrong passphrase.");
    throw err;
  }
}

/** Opens the keyring with the recovery key. Throws "Wrong recovery key." on failure. */
export async function unlockWithRecoveryKey(keyring: Keyring, recoveryKey: string): Promise<Secrets> {
  const key = await recoveryWrappingKey(decodeRecoveryKey(recoveryKey));
  try {
    return decodeSecrets(await open(key, keyring.wrapped_recovery, AAD_RECOVERY));
  } catch (err) {
    if (isDecryptFailure(err)) throw new Error("Wrong recovery key.");
    throw err;
  }
}

/** Parses a stored keyring, rejecting anything that is not version 1. */
export function parseKeyring(json: string): Keyring {
  const keyring = JSON.parse(json) as Keyring;
  if (keyring?.v !== 1 || !keyring.kdf || !keyring.wrapped || !keyring.wrapped_recovery) {
    throw new Error("Unsupported keyring format.");
  }
  return keyring;
}
