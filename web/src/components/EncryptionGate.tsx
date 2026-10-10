import { create } from "@bufbuild/protobuf";
import { FieldMaskSchema } from "@bufbuild/protobuf/wkt";
import { useQueryClient } from "@tanstack/react-query";
import copy from "copy-to-clipboard";
import { KeyRoundIcon, LoaderIcon, LockIcon } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { toast } from "react-hot-toast";
import AuthPageLayout, { AuthChip } from "@/components/AuthPageLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { userServiceClient } from "@/connect";
import { useIsRequireE2ee } from "@/contexts/InstanceContext";
import { toB64 } from "@/crypto/core";
import {
  createKeyring,
  type Keyring,
  MIN_PASSPHRASE,
  parseKeyring,
  rewrapKeyring,
  type Secrets,
  unlockWithPassphrase,
  unlockWithRecoveryKey,
} from "@/crypto/keyring";
import { restoreSession } from "@/crypto/session";
import { loadTagDictionary } from "@/crypto/tags";
import { vault } from "@/crypto/vault";
import useCurrentUser from "@/hooks/useCurrentUser";
import { UserSetting_EncryptionSettingSchema, UserSettingSchema } from "@/types/proto/api/user_service_pb";
import { useTranslate } from "@/utils/i18n";

/** Live view of whether the vault is unlocked. */
export const useVaultUnlocked = (): boolean =>
  useSyncExternalStore(
    (listener) => vault.subscribe(listener),
    () => vault.unlocked,
  );

type KeyringState =
  | { status: "loading" }
  | { status: "missing" }
  | { status: "ready"; keyring: Keyring; tagDictionary: string }
  | { status: "error"; message: string };

const encryptionSettingName = (userName: string) => `${userName}/settings/ENCRYPTION`;

/** Loads the sealed tag dictionary for an already unlocked vault. */
async function loadTagDictionaryFor(userName: string) {
  try {
    const setting = await userServiceClient.getUserSetting({ name: encryptionSettingName(userName) });
    if (setting.value.case === "encryptionSetting") await loadTagDictionary(setting.value.value.tagDictionary);
  } catch {
    // Labels rebuild as memos are opened.
  }
}

async function saveKeyring(userName: string, keyring: Keyring, publicKey?: Uint8Array) {
  const paths = ["keyring"];
  if (publicKey) paths.push("public_key");
  await userServiceClient.updateUserSetting({
    userSetting: create(UserSettingSchema, {
      name: encryptionSettingName(userName),
      value: {
        case: "encryptionSetting",
        value: create(UserSetting_EncryptionSettingSchema, {
          keyring: JSON.stringify(keyring),
          publicKey: publicKey ? toB64(publicKey) : "",
        }),
      },
    }),
    updateMask: create(FieldMaskSchema, { paths }),
  });
}

/**
 * Blocks the app until the user's notes are unlocked, on instances that require
 * end-to-end encryption. First run creates the passphrase and shows the
 * recovery key once. Keys stay in memory, so a browser restart asks again.
 */
const EncryptionGate = ({ children }: { children: ReactNode }) => {
  const requireE2ee = useIsRequireE2ee();
  const currentUser = useCurrentUser();
  const unlocked = useVaultUnlocked();
  const [askedOtherTabs, setAskedOtherTabs] = useState(false);

  useEffect(() => {
    vault.setSignedInUser(currentUser?.name);
  }, [currentUser?.name]);

  // Restore this tab's own unlocked session (survives reloads, not restarts),
  // otherwise borrow keys from another open tab of the same user.
  useEffect(() => {
    if (!requireE2ee || !currentUser || unlocked) return;
    let cancelled = false;
    (async () => {
      const restored = await restoreSession(currentUser.name);
      if (cancelled) return;
      if (restored) {
        vault.unlock(currentUser.name, restored, false);
        await loadTagDictionaryFor(currentUser.name);
        return;
      }
      await vault.requestFromOtherTabs(currentUser.name);
    })().finally(() => {
      if (!cancelled) setAskedOtherTabs(true);
    });
    return () => {
      cancelled = true;
    };
  }, [requireE2ee, currentUser, unlocked]);

  if (!requireE2ee || !currentUser || (unlocked && vault.owner === currentUser.name)) return <>{children}</>;
  if (!askedOtherTabs) return <GateLoading />;
  return <UnlockScreen userName={currentUser.name} />;
};

const GateLoading = () => (
  <div className="flex min-h-dvh w-full items-center justify-center">
    <LoaderIcon className="h-5 w-5 animate-spin text-muted-foreground" />
  </div>
);

const UnlockScreen = ({ userName }: { userName: string }) => {
  const [state, setState] = useState<KeyringState>({ status: "loading" });

  const load = useCallback(async () => {
    try {
      const setting = await userServiceClient.getUserSetting({ name: encryptionSettingName(userName) });
      const encryption = setting.value.case === "encryptionSetting" ? setting.value.value : undefined;
      setState(
        encryption?.keyring
          ? { status: "ready", keyring: parseKeyring(encryption.keyring), tagDictionary: encryption.tagDictionary }
          : { status: "missing" },
      );
    } catch (error) {
      setState({ status: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }, [userName]);

  useEffect(() => {
    void load();
  }, [load]);

  switch (state.status) {
    case "loading":
      return <GateLoading />;
    case "missing":
      return <SetupForm userName={userName} />;
    case "ready":
      return <UnlockForm userName={userName} keyring={state.keyring} tagDictionary={state.tagDictionary} />;
    case "error":
      return (
        <AuthPageLayout title="Could not load your keys" subtitle={state.message} hideExplore>
          <Button onClick={() => void load()}>Try again</Button>
        </AuthPageLayout>
      );
  }
};

const PassphraseFields = ({
  passphrase,
  confirm,
  onPassphrase,
  onConfirm,
  disabled,
}: {
  passphrase: string;
  confirm: string;
  onPassphrase: (value: string) => void;
  onConfirm: (value: string) => void;
  disabled: boolean;
}) => {
  const t = useTranslate();
  return (
    <>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="e2ee-passphrase">{t("e2ee.passphrase")}</Label>
        <Input
          id="e2ee-passphrase"
          type="password"
          autoComplete="new-password"
          value={passphrase}
          readOnly={disabled}
          onChange={(e) => onPassphrase(e.target.value)}
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="e2ee-confirm">{t("e2ee.confirm-passphrase")}</Label>
        <Input
          id="e2ee-confirm"
          type="password"
          autoComplete="new-password"
          value={confirm}
          readOnly={disabled}
          onChange={(e) => onConfirm(e.target.value)}
        />
      </div>
    </>
  );
};

const RecoveryKeyStep = ({ recoveryKey, onDone }: { recoveryKey: string; onDone: () => void }) => {
  const t = useTranslate();
  const [saved, setSaved] = useState(false);
  return (
    <AuthPageLayout
      chip={<AuthChip>{t("e2ee.recovery-chip")}</AuthChip>}
      title={t("e2ee.recovery-title")}
      subtitle={t("e2ee.recovery-description")}
      hideExplore
    >
      <div className="flex flex-col gap-4">
        <Textarea value={recoveryKey} readOnly rows={3} className="font-mono text-sm" />
        <Button
          variant="outline"
          onClick={() => {
            copy(recoveryKey);
            toast.success(t("message.copied"));
          }}
        >
          {t("common.copy")}
        </Button>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
          {t("e2ee.recovery-confirm")}
        </label>
        <Button disabled={!saved} onClick={onDone}>
          {t("e2ee.continue")}
        </Button>
      </div>
    </AuthPageLayout>
  );
};

const SetupForm = ({ userName }: { userName: string }) => {
  const t = useTranslate();
  const queryClient = useQueryClient();
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<{ secrets: Secrets; recoveryKey: string } | undefined>();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passphrase.length < MIN_PASSPHRASE) return toast.error(t("e2ee.too-short", { count: MIN_PASSPHRASE }));
    if (passphrase !== confirm) return toast.error(t("e2ee.mismatch"));
    setBusy(true);
    try {
      const created = await createKeyring(passphrase);
      await saveKeyring(userName, created.keyring, created.secrets.publicKey);
      setPending({ secrets: created.secrets, recoveryKey: created.recoveryKey });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  if (pending) {
    return (
      <RecoveryKeyStep
        recoveryKey={pending.recoveryKey}
        onDone={() => {
          vault.unlock(userName, pending.secrets);
          queryClient.invalidateQueries();
        }}
      />
    );
  }

  return (
    <AuthPageLayout
      chip={
        <AuthChip>
          <KeyRoundIcon className="h-3 w-3" />
          {t("e2ee.setup-chip")}
        </AuthChip>
      }
      title={t("e2ee.setup-title")}
      subtitle={t("e2ee.setup-description")}
      hideExplore
    >
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <PassphraseFields passphrase={passphrase} confirm={confirm} onPassphrase={setPassphrase} onConfirm={setConfirm} disabled={busy} />
        <Button type="submit" disabled={busy}>
          {t("e2ee.create")}
          {busy && <LoaderIcon className="ml-1 h-4 w-4 animate-spin" />}
        </Button>
      </form>
    </AuthPageLayout>
  );
};

const UnlockForm = ({ userName, keyring, tagDictionary }: { userName: string; keyring: Keyring; tagDictionary: string }) => {
  const t = useTranslate();
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<"passphrase" | "recovery">("passphrase");
  const [passphrase, setPassphrase] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<{ secrets: Secrets; recoveryKey: string } | undefined>();

  const finish = async (secrets: Secrets) => {
    vault.unlock(userName, secrets);
    await loadTagDictionary(tagDictionary);
    queryClient.invalidateQueries();
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (mode === "passphrase") {
        await finish(await unlockWithPassphrase(keyring, passphrase));
        return;
      }
      if (newPassphrase.length < MIN_PASSPHRASE) throw new Error(t("e2ee.too-short", { count: MIN_PASSPHRASE }));
      if (newPassphrase !== confirm) throw new Error(t("e2ee.mismatch"));
      const secrets = await unlockWithRecoveryKey(keyring, recoveryKey);
      // A used recovery key is replaced: the old one may have been exposed.
      const rewrapped = await rewrapKeyring(secrets, newPassphrase);
      await saveKeyring(userName, rewrapped.keyring);
      setPending({ secrets, recoveryKey: rewrapped.recoveryKey });
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  if (pending) return <RecoveryKeyStep recoveryKey={pending.recoveryKey} onDone={() => void finish(pending.secrets)} />;

  return (
    <AuthPageLayout
      chip={
        <AuthChip>
          <LockIcon className="h-3 w-3" />
          {t("e2ee.locked-chip")}
        </AuthChip>
      }
      title={t("e2ee.unlock-title")}
      subtitle={mode === "passphrase" ? t("e2ee.unlock-description") : t("e2ee.recover-description")}
      hideExplore
    >
      <form className="flex flex-col gap-4" onSubmit={submit}>
        {mode === "passphrase" ? (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="e2ee-unlock">{t("e2ee.passphrase")}</Label>
            <Input
              id="e2ee-unlock"
              type="password"
              autoComplete="current-password"
              autoFocus
              value={passphrase}
              readOnly={busy}
              onChange={(e) => setPassphrase(e.target.value)}
            />
          </div>
        ) : (
          <>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="e2ee-recovery">{t("e2ee.recovery-key")}</Label>
              <Input
                id="e2ee-recovery"
                className="font-mono"
                autoComplete="off"
                spellCheck={false}
                value={recoveryKey}
                readOnly={busy}
                onChange={(e) => setRecoveryKey(e.target.value)}
              />
            </div>
            <PassphraseFields
              passphrase={newPassphrase}
              confirm={confirm}
              onPassphrase={setNewPassphrase}
              onConfirm={setConfirm}
              disabled={busy}
            />
          </>
        )}
        <Button type="submit" disabled={busy}>
          {t("e2ee.unlock")}
          {busy && <LoaderIcon className="ml-1 h-4 w-4 animate-spin" />}
        </Button>
        <button
          type="button"
          className="text-sm text-muted-foreground underline-offset-4 hover:underline"
          onClick={() => setMode(mode === "passphrase" ? "recovery" : "passphrase")}
        >
          {mode === "passphrase" ? t("e2ee.use-recovery-key") : t("e2ee.use-passphrase")}
        </button>
      </form>
    </AuthPageLayout>
  );
};

export default EncryptionGate;
