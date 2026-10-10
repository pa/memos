package test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	apipb "github.com/usememos/memos/proto/gen/api"
	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/store"
)

func newPrivateInstanceTestService(t *testing.T) *TestService {
	t.Helper()
	ts := NewTestService(t)
	ts.Store.SetPrivateInstance(true)
	t.Cleanup(ts.Cleanup)
	return ts
}

func TestPrivateInstanceSignupRequiresInvite(t *testing.T) {
	ctx := context.Background()
	ts := newPrivateInstanceTestService(t)

	admin, err := ts.CreateHostUser(ctx, "private-admin")
	require.NoError(t, err)
	adminCtx := ts.CreateUserContext(ctx, admin.ID)
	regular, err := ts.CreateRegularUser(ctx, "private-regular")
	require.NoError(t, err)
	regularCtx := ts.CreateUserContext(ctx, regular.ID)

	profile, err := ts.Service.GetInstanceProfile(ctx, &apipb.GetInstanceProfileRequest{})
	require.NoError(t, err)
	require.True(t, profile.PrivateInstance)
	require.Equal(t, apipb.InstanceAccessMode_INSTANCE_ACCESS_MODE_PRIVATE, profile.AccessMode,
		"a private instance never reports public access")

	// Open sign-up is closed even though the stored setting allows it.
	_, err = ts.Service.CreateUser(ctx, &apipb.CreateUserRequest{User: &apipb.User{Username: "stranger", Password: "password123"}})
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	// Only an admin can invite.
	_, err = ts.Service.CreateUserInvite(regularCtx, &apipb.CreateUserInviteRequest{Username: "friend"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = ts.Service.CreateUserInvite(ctx, &apipb.CreateUserInviteRequest{Username: "friend"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = ts.Service.CreateUserInvite(adminCtx, &apipb.CreateUserInviteRequest{Username: "private-regular"})
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	_, err = ts.Service.CreateUserInvite(adminCtx, &apipb.CreateUserInviteRequest{Username: "friend", TtlHours: 10000})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	invite, err := ts.Service.CreateUserInvite(adminCtx, &apipb.CreateUserInviteRequest{Username: "friend"})
	require.NoError(t, err)
	require.NotEmpty(t, invite.InviteToken)
	require.NotNil(t, invite.ExpireTime)

	// The invite is bound to its username.
	_, err = ts.Service.CreateUser(ctx, &apipb.CreateUserRequest{
		User:        &apipb.User{Username: "someone-else", Password: "password123"},
		InviteToken: invite.InviteToken,
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = ts.Service.CreateUser(ctx, &apipb.CreateUserRequest{
		User:        &apipb.User{Username: "friend", Password: "password123"},
		InviteToken: "not-a-token",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	created, err := ts.Service.CreateUser(ctx, &apipb.CreateUserRequest{
		User:        &apipb.User{Username: "friend", Password: "password123", Role: apipb.User_ADMIN},
		InviteToken: invite.InviteToken,
	})
	require.NoError(t, err)
	require.Equal(t, apipb.User_USER, created.Role, "an invite never grants the admin role")

	// The same invite cannot create a second account.
	_, err = ts.Service.CreateUser(ctx, &apipb.CreateUserRequest{
		User:        &apipb.User{Username: "friend", Password: "password123"},
		InviteToken: invite.InviteToken,
	})
	require.Error(t, err)
}

func TestPrivateInstanceVisibilityAndShares(t *testing.T) {
	ctx := context.Background()
	ts := newPrivateInstanceTestService(t)

	// A stored PUBLIC access mode is ignored.
	require.NoError(t, ts.SetInstanceAccessMode(ctx, storepb.InstanceAccessMode_INSTANCE_ACCESS_MODE_PUBLIC))
	allowed, err := ts.Store.AllowsAnonymousAccess(ctx)
	require.NoError(t, err)
	require.False(t, allowed)

	user, err := ts.CreateRegularUser(ctx, "private-author")
	require.NoError(t, err)
	userCtx := ts.CreateUserContext(ctx, user.ID)

	for _, visibility := range []apipb.Visibility{apipb.Visibility_PUBLIC, apipb.Visibility_PROTECTED} {
		_, err = ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{Content: "x", Visibility: visibility}})
		require.Equal(t, codes.InvalidArgument, status.Code(err), "%s is rejected on create", visibility)
	}
	memo, err := ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{Content: "mine", Visibility: apipb.Visibility_PRIVATE}})
	require.NoError(t, err)
	_, err = ts.Service.UpdateMemo(userCtx, &apipb.UpdateMemoRequest{
		Memo:       &apipb.Memo{Name: memo.Name, Visibility: apipb.Visibility_PUBLIC},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"visibility"}},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "PUBLIC is rejected on update")

	// Anonymous readers get nothing.
	_, err = ts.Service.GetMemo(ctx, &apipb.GetMemoRequest{Name: memo.Name})
	require.Error(t, err)

	// Share links cannot be created, and existing ones stop working.
	_, err = ts.Service.CreateMemoShare(userCtx, &apipb.CreateMemoShareRequest{Parent: memo.Name, MemoShare: &apipb.MemoShare{}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	ts.Store.SetPrivateInstance(false)
	share, err := ts.Service.CreateMemoShare(userCtx, &apipb.CreateMemoShareRequest{Parent: memo.Name, MemoShare: &apipb.MemoShare{}})
	require.NoError(t, err)
	shareToken := share.Name[len(share.Name)-len(lastSegment(share.Name)):]
	_, err = ts.Service.GetSharedMemo(ctx, &apipb.GetSharedMemoRequest{ShareToken: shareToken})
	require.NoError(t, err, "the share works while the instance is open")
	ts.Store.SetPrivateInstance(true)
	_, err = ts.Service.GetSharedMemo(ctx, &apipb.GetSharedMemoRequest{ShareToken: shareToken})
	require.Equal(t, codes.NotFound, status.Code(err), "the share stops working once the instance is private")

	// Default visibility setting cannot be PUBLIC.
	_, err = ts.Service.UpdateUserSetting(userCtx, &apipb.UpdateUserSettingRequest{
		UserSetting: &apipb.UserSetting{
			Name:  "users/" + user.Username + "/settings/GENERAL",
			Value: &apipb.UserSetting_GeneralSetting_{GeneralSetting: &apipb.UserSetting_GeneralSetting{MemoVisibility: "PUBLIC"}},
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"memo_visibility"}},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestEnforcePrivateMemoVisibility(t *testing.T) {
	ctx := context.Background()
	ts := NewTestService(t)
	defer ts.Cleanup()

	user, err := ts.CreateRegularUser(ctx, "narrow-author")
	require.NoError(t, err)
	public, err := ts.Store.CreateMemo(ctx, &store.Memo{UID: "narrow-public", CreatorID: user.ID, Content: "p", Visibility: store.Public})
	require.NoError(t, err)
	protected, err := ts.Store.CreateMemo(ctx, &store.Memo{UID: "narrow-protected", CreatorID: user.ID, Content: "p", Visibility: store.Protected})
	require.NoError(t, err)

	require.NoError(t, ts.Store.EnforcePrivateMemoVisibility(ctx))
	require.NoError(t, ts.Store.EnforcePrivateMemoVisibility(ctx), "idempotent")
	for _, id := range []int32{public.ID, protected.ID} {
		got, err := ts.Store.GetMemo(ctx, &store.FindMemo{ID: &id})
		require.NoError(t, err)
		require.Equal(t, store.Private, got.Visibility)
		require.Equal(t, "p", got.Content)
	}
}

func lastSegment(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}
