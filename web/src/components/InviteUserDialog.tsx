import copy from "copy-to-clipboard";
import { useEffect, useState } from "react";
import { toast } from "react-hot-toast";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { userServiceClient } from "@/connect";
import useLoading from "@/hooks/useLoading";
import { handleError } from "@/lib/error";
import { ROUTES } from "@/router/routes";
import { useTranslate } from "@/utils/i18n";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Lets an admin create a one-person, expiring sign-up link. */
function InviteUserDialog({ open, onOpenChange }: Props) {
  const t = useTranslate();
  const [username, setUsername] = useState("");
  const [inviteLink, setInviteLink] = useState("");
  const requestState = useLoading(false);

  useEffect(() => {
    if (!open) return;
    setUsername("");
    setInviteLink("");
  }, [open]);

  const handleCreate = async () => {
    const trimmed = username.trim();
    if (!trimmed) {
      return;
    }
    try {
      requestState.setLoading();
      const response = await userServiceClient.createUserInvite({ username: trimmed });
      const url = new URL(ROUTES.AUTH_SIGNUP, window.location.origin);
      url.searchParams.set("invite", response.inviteToken);
      setInviteLink(url.toString());
      requestState.setFinish();
    } catch (error: unknown) {
      handleError(error, toast.error, { context: "Create invite", onError: () => requestState.setError() });
    }
  };

  const handleCopy = () => {
    copy(inviteLink);
    toast.success(t("message.copied"));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t("setting.member.invite-title")}</DialogTitle>
          <DialogDescription>{t("setting.member.invite-description")}</DialogDescription>
        </DialogHeader>
        {inviteLink ? (
          <div className="grid gap-2">
            <Label>{t("setting.member.invite-link")}</Label>
            <Textarea value={inviteLink} readOnly rows={4} className="font-mono text-xs break-all" />
          </div>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="invite-username">{t("common.username")}</Label>
            <Input
              id="invite-username"
              value={username}
              autoCapitalize="off"
              spellCheck={false}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  void handleCreate();
                }
              }}
            />
          </div>
        )}
        <DialogFooter>
          {inviteLink ? (
            <>
              <Button variant="ghost" onClick={handleCopy}>
                {t("common.copy")}
              </Button>
              <Button onClick={() => onOpenChange(false)}>{t("common.close")}</Button>
            </>
          ) : (
            <>
              <Button variant="ghost" disabled={requestState.isLoading} onClick={() => onOpenChange(false)}>
                {t("common.cancel")}
              </Button>
              <Button disabled={requestState.isLoading || !username.trim()} onClick={handleCreate}>
                {t("common.create")}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default InviteUserDialog;
