// @vitest-environment node
// Node's Web Crypto implements X25519, HKDF and AES-GCM natively; jsdom's does not.
import { describe, expect, it } from "vitest";
import { createKeyring, rewrapKeyring, unlockWithPassphrase, unlockWithRecoveryKey } from "@/crypto/keyring";
import {
  blindTag,
  decryptMemoContent,
  encryptMemoContent,
  envelopeKeyId,
  isEncryptedContent,
  PERSONAL_KEY_ID,
  safetyCode,
} from "@/crypto/memo";
import { decodeRecoveryKey, encodeRecoveryKey } from "@/crypto/recovery";

// Cheap Argon2id cost for tests; production uses DEFAULT_KDF (64 MiB, t=3).
const FAST = { m: 19456, t: 2, p: 1 };
const PASS = "correct horse battery";

describe("keyring", () => {
  it("unlocks with the passphrase and with the recovery key", async () => {
    const created = await createKeyring(PASS, FAST);
    expect(created.secrets.publicKey).toHaveLength(32);
    const viaPass = await unlockWithPassphrase(created.keyring, PASS);
    expect(viaPass.contentKey).toEqual(created.secrets.contentKey);
    expect(viaPass.privateKey).toEqual(created.secrets.privateKey);
    const viaRecovery = await unlockWithRecoveryKey(created.keyring, created.recoveryKey);
    expect(viaRecovery.tagKey).toEqual(created.secrets.tagKey);
  });

  it("rejects a wrong passphrase or recovery key", async () => {
    const created = await createKeyring(PASS, FAST);
    await expect(unlockWithPassphrase(created.keyring, "wrong passphrase!")).rejects.toThrow("Wrong passphrase.");
    const other = await createKeyring(PASS, FAST);
    await expect(unlockWithRecoveryKey(created.keyring, other.recoveryKey)).rejects.toThrow("Wrong recovery key.");
  });

  it("rewraps under a new passphrase without changing content keys", async () => {
    const created = await createKeyring(PASS, FAST);
    const rewrapped = await rewrapKeyring(created.secrets, "another long passphrase", FAST);
    await expect(unlockWithPassphrase(rewrapped.keyring, PASS)).rejects.toThrow();
    const opened = await unlockWithPassphrase(rewrapped.keyring, "another long passphrase");
    expect(opened.contentKey).toEqual(created.secrets.contentKey);
    expect(rewrapped.recoveryKey).not.toEqual(created.recoveryKey);
  });

  it("refuses short passphrases and hostile KDF settings", async () => {
    await expect(createKeyring("short", FAST)).rejects.toThrow();
    const created = await createKeyring(PASS, FAST);
    await expect(unlockWithPassphrase({ ...created.keyring, kdf: { ...created.keyring.kdf, m: 4_000_000 } }, PASS)).rejects.toThrow(
      "settings look wrong",
    );
  });
});

describe("recovery key encoding", () => {
  it("round-trips and tolerates look-alike characters", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const text = encodeRecoveryKey(bytes);
    expect(decodeRecoveryKey(text)).toEqual(bytes);
    expect(decodeRecoveryKey(text.toLowerCase().replaceAll("0", "o"))).toEqual(bytes);
  });
});

describe("memo envelope", () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const resolve = (id: string) => (id === PERSONAL_KEY_ID ? key : undefined);

  it("round-trips and exposes only the index", async () => {
    const tag = await blindTag(key, "work");
    const content = await encryptMemoContent("secret #work", {
      memoUid: "abc",
      keyId: PERSONAL_KEY_ID,
      key,
      blindTags: [tag],
      flags: { hasTaskList: true },
    });
    expect(isEncryptedContent(content)).toBe(true);
    expect(content).not.toContain("secret");
    expect(content).not.toContain("work");
    expect(envelopeKeyId(content)).toBe(PERSONAL_KEY_ID);
    expect(await decryptMemoContent(content, "abc", resolve)).toBe("secret #work");
  });

  it("cannot be moved to another memo", async () => {
    const content = await encryptMemoContent("x", { memoUid: "abc", keyId: PERSONAL_KEY_ID, key, blindTags: [], flags: {} });
    await expect(decryptMemoContent(content, "other", resolve)).rejects.toThrow();
  });

  it("blind tags are stable per key and differ across keys", async () => {
    const other = crypto.getRandomValues(new Uint8Array(32));
    expect(await blindTag(key, "work")).toBe(await blindTag(key, "work"));
    expect(await blindTag(key, "work")).not.toBe(await blindTag(other, "work"));
    expect(await blindTag(key, "work")).toMatch(/^[0-9a-f]{32}$/);
  });

  it("safety codes are short and deterministic", async () => {
    const pk = crypto.getRandomValues(new Uint8Array(32));
    const code = await safetyCode(pk);
    expect(code).toMatch(/^\d{5} \d{5} \d{5} \d{5}$/);
    expect(await safetyCode(pk)).toBe(code);
  });
});
