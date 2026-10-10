// The tag dictionary maps blind tag indexes back to tag names. It is sealed with
// the personal content key and stored in the ENCRYPTION user setting, so tag
// lists and counts can be labeled on any device without the server ever seeing
// a name. It only grows; unused entries are harmless and never shown, because
// counts come from the server's index of live memos.

import { create } from "@bufbuild/protobuf";
import { FieldMaskSchema } from "@bufbuild/protobuf/wkt";
import { UserSetting_EncryptionSettingSchema, UserSettingSchema } from "@/types/proto/api/user_service_pb";
import { aesKey, fromUtf8, open, type Sealed, seal, utf8 } from "./core";
import { vault } from "./vault";

const AAD = "memos:tag-dictionary:v1";

let names = new Map<string, string>();
let dirty = false;
let saving: Promise<void> | undefined;

/** Readable name for a blind index, if known. */
export const tagNameForIndex = (index: string): string | undefined => names.get(index);

/** Records an index-to-name pair learned while encrypting or decrypting. */
export function rememberTag(index: string, name: string) {
  if (names.get(index) !== name) {
    names.set(index, name);
    dirty = true;
  }
}

/** Loads the dictionary from its sealed form. */
export async function loadTagDictionary(sealedJSON: string) {
  const secrets = vault.current;
  if (!sealedJSON || !secrets) return;
  try {
    const sealed = JSON.parse(sealedJSON) as Sealed;
    const plain = await open(await aesKey(secrets.contentKey), sealed, AAD);
    const entries = JSON.parse(fromUtf8(plain)) as Record<string, string>;
    names = new Map([...Object.entries(entries), ...names]);
  } catch {
    // A damaged dictionary only costs labels; it rebuilds as memos are opened.
  }
}

/** Seals and saves the dictionary if it changed. */
export function flushTagDictionary(
  userName: string,
  update: (request: { userSetting: unknown; updateMask: unknown }) => Promise<unknown>,
): Promise<void> {
  if (!dirty || saving) return saving ?? Promise.resolve();
  const secrets = vault.current;
  if (!secrets) return Promise.resolve();
  dirty = false;
  saving = (async () => {
    try {
      const sealed = await seal(await aesKey(secrets.contentKey), utf8(JSON.stringify(Object.fromEntries(names))), AAD);
      await update({
        userSetting: create(UserSettingSchema, {
          name: `${userName}/settings/ENCRYPTION`,
          value: {
            case: "encryptionSetting",
            value: create(UserSetting_EncryptionSettingSchema, { tagDictionary: JSON.stringify(sealed) }),
          },
        }),
        updateMask: create(FieldMaskSchema, { paths: ["tag_dictionary"] }),
      });
    } catch {
      dirty = true;
    } finally {
      saving = undefined;
    }
  })();
  return saving;
}

/** Replaces blind-index keys of a tag count map with names; unknown indexes are dropped. */
export function labelTagCounts(counts: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, count] of Object.entries(counts)) {
    const name = /^[0-9a-f]{32}$/.test(key) ? names.get(key) : key;
    if (name) out[name] = (out[name] ?? 0) + count;
  }
  return out;
}

/** Clears names when the vault locks. */
vault.subscribe(() => {
  if (!vault.unlocked) {
    names = new Map();
    dirty = false;
  }
});
