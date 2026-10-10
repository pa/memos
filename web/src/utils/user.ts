import { User, User_Role } from "@/types/proto/api/user_service_pb";

export const isSuperUser = (user: User | undefined) => {
  return user && user.role === User_Role.ADMIN;
};

/**
 * Whether the user holds author-level authority over a memo: only its creator.
 * The instance admin role grants no access to other users' content.
 */
export const canManageMemo = (memo: { creator: string }, user: User | undefined): boolean => {
  return !!user && memo.creator === user.name;
};
