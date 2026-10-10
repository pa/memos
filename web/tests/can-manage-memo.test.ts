import { describe, expect, it } from "vitest";
import { User, User_Role } from "@/types/proto/api/user_service_pb";
import { canManageMemo } from "@/utils/user";

const user = (name: string, role: User_Role) => ({ name, role }) as User;

describe("canManageMemo", () => {
  const memo = { creator: "users/alice" };

  it("allows the creator", () => {
    expect(canManageMemo(memo, user("users/alice", User_Role.USER))).toBe(true);
  });

  it("gives an instance admin no authority over another user's memo", () => {
    expect(canManageMemo(memo, user("users/root", User_Role.ADMIN))).toBe(false);
  });

  it("denies other users and anonymous viewers", () => {
    expect(canManageMemo(memo, user("users/bob", User_Role.USER))).toBe(false);
    expect(canManageMemo(memo, undefined)).toBe(false);
  });
});
