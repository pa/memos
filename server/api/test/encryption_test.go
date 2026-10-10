package test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/usememos/memos/core/memopayload"
	apipb "github.com/usememos/memos/proto/gen/api"
	"github.com/usememos/memos/store"
)

const testKeyring = `{"v":1,"kdf":{"alg":"argon2id","m":65536,"t":3,"p":1,"salt":"AAAA"},"wrapped":{"v":1,"iv":"a","ct":"b"}}`

func encryptionSettingName(username string) string {
	return "users/" + username + "/settings/ENCRYPTION"
}

func publicKeyB64(fill byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return base64.StdEncoding.EncodeToString(key)
}

func updateEncryption(ctx context.Context, ts *TestService, username string, setting *apipb.UserSetting_EncryptionSetting, paths ...string) (*apipb.UserSetting, error) {
	return ts.Service.UpdateUserSetting(ctx, &apipb.UpdateUserSettingRequest{
		UserSetting: &apipb.UserSetting{
			Name:  encryptionSettingName(username),
			Value: &apipb.UserSetting_EncryptionSetting_{EncryptionSetting: setting},
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: paths},
	})
}

func TestEncryptionSettingLifecycle(t *testing.T) {
	ctx := context.Background()
	ts := NewTestService(t)
	defer ts.Cleanup()

	alice, err := ts.CreateRegularUser(ctx, "e2ee-alice")
	require.NoError(t, err)
	aliceCtx := ts.CreateUserContext(ctx, alice.ID)
	bob, err := ts.CreateRegularUser(ctx, "e2ee-bob")
	require.NoError(t, err)
	bobCtx := ts.CreateUserContext(ctx, bob.ID)

	// Unset by default.
	got, err := ts.Service.GetUserSetting(aliceCtx, &apipb.GetUserSettingRequest{Name: encryptionSettingName(alice.Username)})
	require.NoError(t, err)
	require.Empty(t, got.GetEncryptionSetting().GetKeyring())

	_, err = updateEncryption(aliceCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{Keyring: "not json"}, "keyring")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = updateEncryption(aliceCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{Keyring: testKeyring, PublicKey: "short"}, "keyring", "public_key")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = updateEncryption(aliceCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{Keyring: strings.Repeat(" ", 20000) + "{}"}, "keyring")
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	saved, err := updateEncryption(aliceCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{Keyring: testKeyring, PublicKey: publicKeyB64(1)}, "keyring", "public_key")
	require.NoError(t, err)
	require.Equal(t, testKeyring, saved.GetEncryptionSetting().Keyring)
	require.Equal(t, publicKeyB64(1), saved.GetEncryptionSetting().PublicKey)

	// Rewrapping the keyring (passphrase change) keeps the public key.
	rewrapped := strings.Replace(testKeyring, `"b"`, `"c"`, 1)
	saved, err = updateEncryption(aliceCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{Keyring: rewrapped}, "keyring")
	require.NoError(t, err)
	require.Equal(t, rewrapped, saved.GetEncryptionSetting().Keyring)
	require.Equal(t, publicKeyB64(1), saved.GetEncryptionSetting().PublicKey)

	// The public key never changes once published.
	_, err = updateEncryption(aliceCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{PublicKey: publicKeyB64(2)}, "public_key")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Nobody else can read or write it, the admin included.
	_, err = ts.Service.GetUserSetting(bobCtx, &apipb.GetUserSettingRequest{Name: encryptionSettingName(alice.Username)})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = updateEncryption(bobCtx, ts, alice.Username, &apipb.UserSetting_EncryptionSetting{Keyring: testKeyring}, "keyring")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	admin, err := ts.CreateHostUser(ctx, "e2ee-admin")
	require.NoError(t, err)
	_, err = ts.Service.GetUserSetting(ts.CreateUserContext(ctx, admin.ID), &apipb.GetUserSettingRequest{Name: encryptionSettingName(alice.Username)})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func encryptedContent(tags ...string) string {
	tagJSON := ""
	if len(tags) > 0 {
		tagJSON = `,"t":["` + strings.Join(tags, `","`) + `"]`
	}
	return memopayload.EncryptedContentPrefix + `{"k":"pk","iv":"aXY=","ct":"Y2lwaGVy"` + tagJSON + `,"p":{"t":true}}`
}

func TestEncryptedMemoContent(t *testing.T) {
	ctx := context.Background()
	ts := NewTestService(t)
	defer ts.Cleanup()

	user, err := ts.CreateRegularUser(ctx, "e2ee-writer")
	require.NoError(t, err)
	userCtx := ts.CreateUserContext(ctx, user.ID)
	blindTag := strings.Repeat("ab", 16)

	memo, err := ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{
		Content: encryptedContent(blindTag), Visibility: apipb.Visibility_PRIVATE,
	}})
	require.NoError(t, err)
	require.Equal(t, encryptedContent(blindTag), memo.Content, "ciphertext round-trips untouched")
	require.Equal(t, []string{blindTag}, memo.Tags, "tags come from the blind index")
	require.True(t, memo.Property.HasTaskList)
	require.Empty(t, memo.Snippet, "the server cannot build a snippet")

	// The blind tag filter works server side.
	list, err := ts.Service.ListMemos(userCtx, &apipb.ListMemosRequest{Filter: `tag in ["` + blindTag + `"]`})
	require.NoError(t, err)
	require.Len(t, list.Memos, 1)

	// Plain tag names are refused in the index, so a client bug cannot leak them.
	_, err = ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{
		Content: encryptedContent("work"), Visibility: apipb.Visibility_PRIVATE,
	}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{
		Content: memopayload.EncryptedContentPrefix + `{"k":"pk"}`, Visibility: apipb.Visibility_PRIVATE,
	}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Updates go through the same checks.
	updated, err := ts.Service.UpdateMemo(userCtx, &apipb.UpdateMemoRequest{
		Memo:       &apipb.Memo{Name: memo.Name, Content: encryptedContent()},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"content"}},
	})
	require.NoError(t, err)
	require.Empty(t, updated.Tags)

	// With --require-e2ee, plaintext is refused and ciphertext accepted.
	ts.Store.SetRequireE2EE(true)
	_, err = ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{Content: "plain #work", Visibility: apipb.Visibility_PRIVATE}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = ts.Service.UpdateMemo(userCtx, &apipb.UpdateMemoRequest{
		Memo:       &apipb.Memo{Name: memo.Name, Content: "plain again"},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"content"}},
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{Content: encryptedContent(), Visibility: apipb.Visibility_PRIVATE}})
	require.NoError(t, err)

	stored, err := ts.Store.GetMemo(ctx, &store.FindMemo{UID: new(memo.Name[len("memos/"):])})
	require.NoError(t, err)
	require.True(t, memopayload.IsEncryptedContent(stored.Content))
}

func TestFilterAcceptsBareTrue(t *testing.T) {
	ctx := context.Background()
	ts := NewTestService(t)
	defer ts.Cleanup()
	user, err := ts.CreateRegularUser(ctx, "filter-true")
	require.NoError(t, err)
	userCtx := ts.CreateUserContext(ctx, user.ID)
	_, err = ts.Service.CreateMemo(userCtx, &apipb.CreateMemoRequest{Memo: &apipb.Memo{Content: "x", Visibility: apipb.Visibility_PRIVATE}})
	require.NoError(t, err)
	// The web client replaces content searches with `true` before sending.
	list, err := ts.Service.ListMemos(userCtx, &apipb.ListMemosRequest{Filter: "(true) && (true)"})
	require.NoError(t, err)
	require.Len(t, list.Memos, 1)
}
