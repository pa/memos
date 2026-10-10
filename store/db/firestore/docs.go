package firestore

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/protobuf/encoding/protojson"

	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/store"
)

// Documents mirror the SQL rows. Proto payloads are kept as protojson text in
// the same shape the SQL drivers store, and the fields that filters or lookups
// need are copied out next to them.

type userDoc struct {
	ID           int32   `bson:"_id"`
	CreatedTs    int64   `bson:"created_ts"`
	UpdatedTs    int64   `bson:"updated_ts"`
	RowStatus    string  `bson:"row_status"`
	Username     string  `bson:"username"`
	Role         string  `bson:"role"`
	Email        *string `bson:"email,omitempty"`
	Nickname     string  `bson:"nickname"`
	PasswordHash string  `bson:"password_hash"`
	AvatarURL    string  `bson:"avatar_url"`
	Description  string  `bson:"description"`
}

func (u *userDoc) toStore() *store.User {
	user := &store.User{
		ID:           u.ID,
		RowStatus:    store.RowStatus(u.RowStatus),
		CreatedTs:    u.CreatedTs,
		UpdatedTs:    u.UpdatedTs,
		Username:     u.Username,
		Role:         store.Role(u.Role),
		Nickname:     u.Nickname,
		PasswordHash: u.PasswordHash,
		AvatarURL:    u.AvatarURL,
		Description:  u.Description,
	}
	if u.Email != nil {
		user.Email = *u.Email
	}
	return user
}

type userSettingDoc struct {
	UserID int32  `bson:"user_id"`
	Key    string `bson:"key"`
	Value  string `bson:"value"`
	// TokenHashes copies personal access token hashes out of the value so a
	// token can be looked up by an index.
	TokenHashes []string `bson:"token_hashes,omitempty"`
}

type systemSettingDoc struct {
	Name        string `bson:"_id"`
	Value       string `bson:"value"`
	Description string `bson:"description"`
}

type spaceDoc struct {
	ID          int32  `bson:"_id"`
	UID         string `bson:"uid"`
	Title       string `bson:"title"`
	Description string `bson:"description"`
	Payload     string `bson:"payload"`
}

func (s *spaceDoc) toStore() (*store.Space, error) {
	space := &store.Space{ID: s.ID, UID: s.UID, Title: s.Title, Description: s.Description, Payload: &storepb.SpacePayload{}}
	if s.Payload != "" {
		if err := protojsonUnmarshaler.Unmarshal([]byte(s.Payload), space.Payload); err != nil {
			return nil, err
		}
	}
	return space, nil
}

type spaceMemberDoc struct {
	Key     string `bson:"_id,omitempty"`
	SpaceID int32  `bson:"space_id"`
	UserID  int32  `bson:"user_id"`
	Status  string `bson:"status"`
	Role    string `bson:"role"`
}

type memoDoc struct {
	ID         int32  `bson:"_id"`
	UID        string `bson:"uid"`
	CreatorID  int32  `bson:"creator_id"`
	CreatedTs  int64  `bson:"created_ts"`
	UpdatedTs  int64  `bson:"updated_ts"`
	RowStatus  string `bson:"row_status"`
	Content    string `bson:"content"`
	Visibility string `bson:"visibility"`
	Pinned     bool   `bson:"pinned"`
	Payload    string `bson:"payload"`
	SpaceID    *int32 `bson:"space_id"`

	// Copied from the payload for filtering.
	Tags               []string `bson:"tags"`
	HasLink            bool     `bson:"has_link"`
	HasTaskList        bool     `bson:"has_task_list"`
	HasCode            bool     `bson:"has_code"`
	HasIncompleteTasks bool     `bson:"has_incomplete_tasks"`
	HasLocation        bool     `bson:"has_location"`
}

// memoPayloadFields returns the filterable fields derived from a payload.
func memoPayloadFields(payload *storepb.MemoPayload) bson.M {
	tags := []string{}
	fields := bson.M{"tags": tags, "has_link": false, "has_task_list": false, "has_code": false, "has_incomplete_tasks": false, "has_location": false}
	if payload == nil {
		return fields
	}
	if len(payload.Tags) > 0 {
		fields["tags"] = payload.Tags
	}
	if p := payload.Property; p != nil {
		fields["has_link"] = p.HasLink
		fields["has_task_list"] = p.HasTaskList
		fields["has_code"] = p.HasCode
		fields["has_incomplete_tasks"] = p.HasIncompleteTasks
	}
	fields["has_location"] = payload.Location != nil
	return fields
}

func marshalMemoPayload(payload *storepb.MemoPayload) (string, error) {
	if payload == nil {
		return "{}", nil
	}
	data, err := protojson.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m *memoDoc) toStore(includeContent bool) (*store.Memo, error) {
	memo := &store.Memo{
		ID:         m.ID,
		UID:        m.UID,
		RowStatus:  store.RowStatus(m.RowStatus),
		CreatorID:  m.CreatorID,
		CreatedTs:  m.CreatedTs,
		UpdatedTs:  m.UpdatedTs,
		Visibility: store.Visibility(m.Visibility),
		Pinned:     m.Pinned,
		SpaceID:    m.SpaceID,
		Payload:    &storepb.MemoPayload{},
	}
	if includeContent {
		memo.Content = m.Content
	}
	if m.Payload != "" {
		if err := protojsonUnmarshaler.Unmarshal([]byte(m.Payload), memo.Payload); err != nil {
			return nil, err
		}
	}
	return memo, nil
}

type memoRelationDoc struct {
	Key           string `bson:"_id,omitempty"`
	MemoID        int32  `bson:"memo_id"`
	RelatedMemoID int32  `bson:"related_memo_id"`
	Type          string `bson:"type"`
}

type attachmentDoc struct {
	ID          int32  `bson:"_id"`
	UID         string `bson:"uid"`
	CreatorID   int32  `bson:"creator_id"`
	CreatedTs   int64  `bson:"created_ts"`
	UpdatedTs   int64  `bson:"updated_ts"`
	Filename    string `bson:"filename"`
	Blob        []byte `bson:"blob,omitempty"`
	Type        string `bson:"type"`
	Size        int64  `bson:"size"`
	MemoID      *int32 `bson:"memo_id"`
	StorageType string `bson:"storage_type"`
	Reference   string `bson:"reference"`
	Payload     string `bson:"payload"`
}

func (a *attachmentDoc) toStore() (*store.Attachment, error) {
	attachment := &store.Attachment{
		ID:          a.ID,
		UID:         a.UID,
		CreatorID:   a.CreatorID,
		CreatedTs:   a.CreatedTs,
		UpdatedTs:   a.UpdatedTs,
		Filename:    a.Filename,
		Blob:        a.Blob,
		Type:        a.Type,
		Size:        a.Size,
		MemoID:      a.MemoID,
		StorageType: storepb.AttachmentStorageType(storepb.AttachmentStorageType_value[a.StorageType]),
		Reference:   a.Reference,
		Payload:     &storepb.AttachmentPayload{},
	}
	if a.Payload != "" {
		if err := protojsonUnmarshaler.Unmarshal([]byte(a.Payload), attachment.Payload); err != nil {
			return nil, err
		}
	}
	return attachment, nil
}

type idpDoc struct {
	ID               int32  `bson:"_id"`
	UID              string `bson:"uid"`
	Name             string `bson:"name"`
	Type             string `bson:"type"`
	IdentifierFilter string `bson:"identifier_filter"`
	Config           string `bson:"config"`
}

func (i *idpDoc) toStore() *store.IdentityProvider {
	return &store.IdentityProvider{
		ID:               i.ID,
		UID:              i.UID,
		Name:             i.Name,
		Type:             storepb.IdentityProvider_Type(storepb.IdentityProvider_Type_value[i.Type]),
		IdentifierFilter: i.IdentifierFilter,
		Config:           i.Config,
	}
}

type inboxDoc struct {
	ID          int32  `bson:"_id"`
	CreatedTs   int64  `bson:"created_ts"`
	SenderID    int32  `bson:"sender_id"`
	ReceiverID  int32  `bson:"receiver_id"`
	Status      string `bson:"status"`
	Message     string `bson:"message"`
	MessageType string `bson:"message_type"`
}

func (i *inboxDoc) toStore() (*store.Inbox, error) {
	message := &storepb.InboxMessage{}
	if i.Message != "" {
		if err := protojsonUnmarshaler.Unmarshal([]byte(i.Message), message); err != nil {
			return nil, err
		}
	}
	return &store.Inbox{
		ID:         i.ID,
		CreatedTs:  i.CreatedTs,
		SenderID:   i.SenderID,
		ReceiverID: i.ReceiverID,
		Status:     store.InboxStatus(i.Status),
		Message:    message,
	}, nil
}

type reactionDoc struct {
	ID           int32  `bson:"_id"`
	CreatedTs    int64  `bson:"created_ts"`
	CreatorID    int32  `bson:"creator_id"`
	MemoID       int32  `bson:"memo_id"`
	ReactionType string `bson:"reaction_type"`
}

func (r *reactionDoc) toStore() *store.Reaction {
	return &store.Reaction{ID: r.ID, CreatedTs: r.CreatedTs, CreatorID: r.CreatorID, MemoID: r.MemoID, ReactionType: r.ReactionType}
}

type memoShareDoc struct {
	ID        int32  `bson:"_id"`
	UID       string `bson:"uid"`
	MemoID    int32  `bson:"memo_id"`
	CreatorID int32  `bson:"creator_id"`
	CreatedTs int64  `bson:"created_ts"`
	ExpiresTs *int64 `bson:"expires_ts"`
}

func (m *memoShareDoc) toStore() *store.MemoShare {
	return &store.MemoShare{ID: m.ID, UID: m.UID, MemoID: m.MemoID, CreatorID: m.CreatorID, CreatedTs: m.CreatedTs, ExpiresTs: m.ExpiresTs}
}

type userIdentityDoc struct {
	ID        int32  `bson:"_id"`
	UserID    int32  `bson:"user_id"`
	Provider  string `bson:"provider"`
	ExternUID string `bson:"extern_uid"`
	CreatedTs int64  `bson:"created_ts"`
	UpdatedTs int64  `bson:"updated_ts"`
}

func (u *userIdentityDoc) toStore() *store.UserIdentity {
	return &store.UserIdentity{ID: u.ID, UserID: u.UserID, Provider: u.Provider, ExternUID: u.ExternUID, CreatedTs: u.CreatedTs, UpdatedTs: u.UpdatedTs}
}
