package api

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usememos/memos/core/memopayload"
	apipb "github.com/usememos/memos/proto/gen/api"
	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/store"
)

const (
	// maxEncryptionKeyringBytes bounds the opaque keyring JSON. A keyring is a
	// few sealed 32-byte keys plus KDF parameters, well under 4 KiB.
	maxEncryptionKeyringBytes = 16 << 10
	// maxEncryptionTagDictionaryBytes bounds the sealed tag dictionary.
	maxEncryptionTagDictionaryBytes = 1 << 20
	// x25519PublicKeyBytes is the raw size of an X25519 public key.
	x25519PublicKeyBytes = 32
)

// mergeEncryptionSetting applies an ENCRYPTION update. The server cannot read
// any of it, so it only enforces shape and one rule that protects teammates:
// once a public key is published it never changes, otherwise a stolen session
// could swap in an attacker key and receive future Space keys.
func (s *APIService) mergeEncryptionSetting(ctx context.Context, userID int32, incoming *apipb.UserSetting_EncryptionSetting, paths []string) (*apipb.UserSetting_EncryptionSetting, error) {
	if incoming == nil {
		return nil, status.Errorf(codes.InvalidArgument, "encryption setting is required")
	}
	existing, err := s.Store.GetUserSetting(ctx, &store.FindUserSetting{UserID: &userID, Key: storepb.UserSetting_ENCRYPTION})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get encryption setting")
	}
	current := existing.GetEncryption()
	merged := &apipb.UserSetting_EncryptionSetting{
		Keyring:       current.GetKeyring(),
		PublicKey:     current.GetPublicKey(),
		TagDictionary: current.GetTagDictionary(),
	}
	for _, path := range paths {
		switch path {
		case "keyring":
			if len(incoming.Keyring) > maxEncryptionKeyringBytes || !json.Valid([]byte(incoming.Keyring)) {
				return nil, status.Errorf(codes.InvalidArgument, "keyring must be JSON under %d bytes", maxEncryptionKeyringBytes)
			}
			merged.Keyring = incoming.Keyring
		case "public_key":
			raw, err := base64.StdEncoding.DecodeString(incoming.PublicKey)
			if err != nil || len(raw) != x25519PublicKeyBytes {
				return nil, status.Errorf(codes.InvalidArgument, "public_key must be a base64 X25519 key")
			}
			if merged.PublicKey != "" && merged.PublicKey != incoming.PublicKey {
				return nil, status.Errorf(codes.FailedPrecondition, "public_key cannot change once set")
			}
			merged.PublicKey = incoming.PublicKey
		case "tag_dictionary":
			if len(incoming.TagDictionary) > maxEncryptionTagDictionaryBytes {
				return nil, status.Errorf(codes.InvalidArgument, "tag_dictionary is too large")
			}
			merged.TagDictionary = incoming.TagDictionary
		default:
			return nil, status.Errorf(codes.InvalidArgument, "unsupported update mask path for encryption setting: %s", path)
		}
	}
	if merged.Keyring == "" {
		return nil, status.Errorf(codes.InvalidArgument, "keyring is required")
	}
	return merged, nil
}

// encryptedContentOverhead allows for base64 and JSON framing: sealed content
// is about 4/3 of the plaintext plus a fixed envelope.
func encryptedContentLimit(plainLimit int) int {
	return plainLimit*4/3 + 4096
}

// validateMemoContent enforces the length limit and, for encrypted content,
// the envelope shape. With --require-e2ee only encrypted content is accepted,
// so plaintext never reaches the database.
func (s *APIService) validateMemoContent(ctx context.Context, content string) error {
	limit, err := s.getContentLengthLimit(ctx)
	if err != nil {
		return status.Error(codes.Internal, "failed to get content length limit")
	}
	if memopayload.IsEncryptedContent(content) {
		if len(content) > encryptedContentLimit(limit) {
			return status.Errorf(codes.InvalidArgument, "content too long (max %d characters)", limit)
		}
		if _, err := memopayload.ParseEnvelope(content); err != nil {
			return status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil
	}
	if s.Store.RequiresEncryptedContent() {
		return status.Errorf(codes.FailedPrecondition, "this instance only stores end-to-end encrypted memos")
	}
	if len(content) > limit {
		return status.Errorf(codes.InvalidArgument, "content too long (max %d characters)", limit)
	}
	return nil
}
