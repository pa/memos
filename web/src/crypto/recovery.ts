// Recovery keys: 32 random bytes shown once as Crockford base32 in groups of 4,
// e.g. "7K3Q-M2ZD-…". Crockford skips I, L, O and U, and decoding maps the
// look-alikes back, so a key read off paper still works.

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LOOKALIKES: Record<string, string> = { O: "0", I: "1", L: "1" };

/** Formats 32 bytes as a grouped Crockford base32 string. */
export function encodeRecoveryKey(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error("recovery key must be 32 bytes");
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out.match(/.{1,4}/g)!.join("-");
}

/** Parses a recovery key typed by a person. Throws on a wrong length or character. */
export function decodeRecoveryKey(text: string): Uint8Array<ArrayBuffer> {
  const clean = text
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[OIL]/g, (c) => LOOKALIKES[c]);
  if (clean.length !== 52) throw new Error("A recovery key has 52 characters.");
  const out = new Uint8Array(32);
  let bits = 0;
  let value = 0;
  let i = 0;
  for (const c of clean) {
    const idx = ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`"${c}" isn't used in recovery keys.`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8 && i < 32) {
      out[i++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return out;
}
