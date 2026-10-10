import { LockIcon } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useIsRequireE2ee } from "@/contexts/InstanceContext";
import { getLockPolicy, LOCK_POLICIES, type LockPolicy, setLockPolicy } from "@/crypto/session";
import { vault } from "@/crypto/vault";
import { useTranslate } from "@/utils/i18n";
import SettingGroup from "./SettingGroup";
import { SettingList, SettingListItem } from "./SettingList";

const POLICY_LABEL_KEYS = {
  restart: "e2ee.lock-restart",
  "idle-15m": "e2ee.lock-idle-15m",
  "idle-1h": "e2ee.lock-idle-1h",
  "idle-4h": "e2ee.lock-idle-4h",
  never: "e2ee.lock-never",
} as const satisfies Record<LockPolicy, string>;

/** Per-device choice of when encrypted notes lock again, like a password manager's vault timeout. */
const EncryptionLockSettings = () => {
  const t = useTranslate();
  const requireE2ee = useIsRequireE2ee();
  const [policy, setPolicy] = useState<LockPolicy>(getLockPolicy);

  if (!requireE2ee) return null;

  const items = LOCK_POLICIES.map((value) => ({ value, label: t(POLICY_LABEL_KEYS[value]) }));

  const handleChange = (value: string) => {
    const next = value as LockPolicy;
    setLockPolicy(next);
    setPolicy(next);
    vault.applyPolicy();
  };

  return (
    <SettingGroup title={t("e2ee.security-title")} description={t("e2ee.security-description")} showSeparator>
      <SettingList>
        <SettingListItem
          label={t("e2ee.lock-label")}
          description={policy === "never" ? t("e2ee.lock-never-warning") : t("e2ee.lock-description")}
        >
          <Select value={policy} items={items} onValueChange={(value) => value && handleChange(value)}>
            <SelectTrigger className="min-w-fit">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {items.map((item) => (
                <SelectItem key={item.value} value={item.value} className="whitespace-nowrap">
                  {item.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </SettingListItem>
        <SettingListItem label={t("e2ee.lock-now")} description={t("e2ee.lock-now-description")}>
          <Button variant="outline" onClick={() => vault.lock()}>
            <LockIcon className="mr-2 h-4 w-4" />
            {t("e2ee.lock-now")}
          </Button>
        </SettingListItem>
      </SettingList>
    </SettingGroup>
  );
};

export default EncryptionLockSettings;
