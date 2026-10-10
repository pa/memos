package firestore

import (
	"context"
	"slices"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"google.golang.org/protobuf/encoding/protojson"

	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/store"
)

func stableSort[T any](values []T, less func(a, b T) bool) {
	slices.SortStableFunc(values, func(a, b T) int {
		switch {
		case less(a, b):
			return -1
		case less(b, a):
			return 1
		default:
			return 0
		}
	})
}

func applyLimit[T any](values []T, limit, offset *int) []T {
	if limit == nil {
		return values
	}
	start := 0
	if offset != nil {
		start = *offset
	}
	if start >= len(values) {
		return []T{}
	}
	end := min(start+*limit, len(values))
	return values[start:end]
}

type idOnly struct {
	ID int32 `bson:"_id"`
}

func (d *DB) listIDs(ctx context.Context, collection string, filter any) ([]int32, error) {
	docs, err := decodeAll[idOnly](ctx)(d.col(collection).Find(ctx, filter, options.Find().SetProjection(bson.M{"_id": 1}).SetSort(bson.D{{Key: "_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	ids := make([]int32, 0, len(docs))
	for _, doc := range docs {
		ids = append(ids, doc.ID)
	}
	return ids, nil
}

func (d *DB) deleteByIDs(ctx context.Context, collection string, ids []int32) error {
	for _, batch := range batches(ids, batchSize) {
		if _, err := d.col(collection).DeleteMany(ctx, bson.M{"_id": int32In(batch)}); err != nil {
			return err
		}
	}
	return nil
}

// listAttachmentSnapshots returns attachment rows without blobs.
func (d *DB) listAttachmentSnapshots(ctx context.Context, filter any) ([]*store.Attachment, error) {
	docs, err := decodeAll[attachmentDoc](ctx)(d.col(colAttachment).Find(ctx, filter, options.Find().SetProjection(bson.M{"blob": 0}).SetSort(bson.D{{Key: "_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	out := make([]*store.Attachment, 0, len(docs))
	for i := range docs {
		attachment, err := docs[i].toStore()
		if err != nil {
			return nil, err
		}
		out = append(out, attachment)
	}
	return out, nil
}

func attachmentIDs(attachments []*store.Attachment) []int32 {
	ids := make([]int32, 0, len(attachments))
	for _, a := range attachments {
		if a != nil {
			ids = append(ids, a.ID)
		}
	}
	return ids
}

// CreateInstanceSettingIfNotExists inserts the setting when absent.
func (d *DB) CreateInstanceSettingIfNotExists(ctx context.Context, create *store.InstanceSetting) (bool, error) {
	res, err := d.col(colSystemSetting).UpdateOne(ctx,
		bson.M{"_id": create.Name},
		bson.M{"$setOnInsert": bson.M{"value": create.Value, "description": create.Description}},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, errors.Wrap(err, "failed to conditionally create instance setting")
	}
	return res.UpsertedCount == 1, nil
}

// UpsertInstanceSetting creates or replaces a setting.
func (d *DB) UpsertInstanceSetting(ctx context.Context, upsert *store.InstanceSetting) (*store.InstanceSetting, error) {
	_, err := d.col(colSystemSetting).UpdateOne(ctx,
		bson.M{"_id": upsert.Name},
		bson.M{"$set": bson.M{"value": upsert.Value, "description": upsert.Description}},
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return nil, err
	}
	return upsert, nil
}

// ListInstanceSettings lists settings.
func (d *DB) ListInstanceSettings(ctx context.Context, find *store.FindInstanceSetting) ([]*store.InstanceSetting, error) {
	filter := bson.M{}
	if find.Name != "" {
		filter["_id"] = find.Name
	}
	docs, err := decodeAll[systemSettingDoc](ctx)(d.col(colSystemSetting).Find(ctx, filter))
	if err != nil {
		return nil, err
	}
	out := make([]*store.InstanceSetting, 0, len(docs))
	for _, doc := range docs {
		out = append(out, &store.InstanceSetting{Name: doc.Name, Value: doc.Value, Description: doc.Description})
	}
	return out, nil
}

// DeleteInstanceSetting deletes a setting.
func (d *DB) DeleteInstanceSetting(ctx context.Context, delete *store.DeleteInstanceSetting) error {
	_, err := d.col(colSystemSetting).DeleteOne(ctx, bson.M{"_id": delete.Name})
	return err
}

// CreateIdentityProvider inserts an identity provider.
func (d *DB) CreateIdentityProvider(ctx context.Context, create *store.IdentityProvider) (*store.IdentityProvider, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		id, err := d.nextID(ctx, colIDP)
		if err != nil {
			return err
		}
		doc := idpDoc{ID: id, UID: create.UID, Name: create.Name, Type: create.Type.String(), IdentifierFilter: create.IdentifierFilter, Config: create.Config}
		if _, err := d.col(colIDP).InsertOne(ctx, doc); err != nil {
			return uniqueErr(err, "idp", map[string]string{"uid": "uid"})
		}
		create.ID = id
		return nil
	})
	if err != nil {
		return nil, err
	}
	return create, nil
}

// ListIdentityProviders lists identity providers.
func (d *DB) ListIdentityProviders(ctx context.Context, find *store.FindIdentityProvider) ([]*store.IdentityProvider, error) {
	filter := bson.M{}
	if v := find.ID; v != nil {
		filter["_id"] = *v
	}
	if v := find.UID; v != nil {
		filter["uid"] = *v
	}
	docs, err := decodeAll[idpDoc](ctx)(d.col(colIDP).Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	var out []*store.IdentityProvider
	for i := range docs {
		out = append(out, docs[i].toStore())
	}
	return out, nil
}

// UpdateIdentityProvider updates an identity provider.
func (d *DB) UpdateIdentityProvider(ctx context.Context, update *store.UpdateIdentityProvider) (*store.IdentityProvider, error) {
	set := bson.M{}
	if v := update.Name; v != nil {
		set["name"] = *v
	}
	if v := update.IdentifierFilter; v != nil {
		set["identifier_filter"] = *v
	}
	if v := update.Config; v != nil {
		set["config"] = *v
	}
	doc := idpDoc{}
	var err error
	if len(set) == 0 {
		var found bool
		found, err = findOne(ctx, d.col(colIDP), bson.M{"_id": update.ID}, &doc)
		if err == nil && !found {
			err = mongo.ErrNoDocuments
		}
	} else {
		err = d.col(colIDP).FindOneAndUpdate(ctx, bson.M{"_id": update.ID}, bson.M{"$set": set}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&doc)
	}
	if err != nil {
		return nil, err
	}
	return doc.toStore(), nil
}

// DeleteIdentityProvider deletes an identity provider.
func (d *DB) DeleteIdentityProvider(ctx context.Context, delete *store.DeleteIdentityProvider) error {
	_, err := d.col(colIDP).DeleteOne(ctx, bson.M{"_id": delete.ID})
	return err
}

// IsRetryableAuthenticationMutationError reports transient transaction
// conflicts.
func (*DB) IsRetryableAuthenticationMutationError(err error) bool {
	var labeled mongo.LabeledError
	if errors.As(err, &labeled) {
		return labeled.HasErrorLabel("TransientTransactionError") || labeled.HasErrorLabel("UnknownTransactionCommitResult")
	}
	return false
}

// ApplyAuthenticationConfigMutation validates and applies an auth mutation
// in one transaction.
func (d *DB) ApplyAuthenticationConfigMutation(ctx context.Context, mutation *store.AuthenticationConfigMutation) error {
	return d.withTx(ctx, func(ctx context.Context) error {
		state := &store.AuthenticationConfigState{}
		general := systemSettingDoc{}
		found, err := findOne(ctx, d.col(colSystemSetting), bson.M{"_id": "GENERAL"}, &general)
		if err != nil {
			return errors.Wrap(err, "failed to read GENERAL setting")
		}
		if found {
			state.GeneralSetting = &store.InstanceSetting{Name: general.Name, Value: general.Value, Description: general.Description}
		}
		providers, err := decodeAll[idpDoc](ctx)(d.col(colIDP).Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})))
		if err != nil {
			return errors.Wrap(err, "failed to read identity providers")
		}
		for _, p := range providers {
			state.IdentityProviders = append(state.IdentityProviders, &store.IdentityProvider{ID: p.ID, UID: p.UID})
		}
		if mutation.Validate != nil {
			if err := mutation.Validate(state); err != nil {
				return err
			}
		}
		switch {
		case mutation.UpsertGeneralSetting != nil:
			s := mutation.UpsertGeneralSetting
			_, err = d.col(colSystemSetting).UpdateOne(ctx, bson.M{"_id": s.Name},
				bson.M{"$set": bson.M{"value": s.Value, "description": s.Description}}, options.UpdateOne().SetUpsert(true))
		case mutation.DeleteIdentityProviderID != nil:
			_, err = d.col(colIDP).DeleteOne(ctx, bson.M{"_id": *mutation.DeleteIdentityProviderID})
		default:
			return errors.New("authentication configuration mutation has no operation")
		}
		if err != nil {
			return errors.Wrap(err, "failed to apply authentication configuration mutation")
		}
		return nil
	})
}

// CreateInbox inserts an inbox message.
func (d *DB) CreateInbox(ctx context.Context, create *store.Inbox) (*store.Inbox, error) {
	message := "{}"
	messageType := storepb.InboxMessage_TYPE_UNSPECIFIED.String()
	if create.Message != nil {
		data, err := protojson.Marshal(create.Message)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal inbox message")
		}
		message = string(data)
		messageType = create.Message.Type.String()
	}
	err := d.withTx(ctx, func(ctx context.Context) error {
		id, err := d.nextID(ctx, colInbox)
		if err != nil {
			return err
		}
		ts := now()
		doc := inboxDoc{ID: id, CreatedTs: ts, SenderID: create.SenderID, ReceiverID: create.ReceiverID, Status: string(create.Status), Message: message, MessageType: messageType}
		if _, err := d.col(colInbox).InsertOne(ctx, doc); err != nil {
			return err
		}
		create.ID, create.CreatedTs = id, ts
		return nil
	})
	if err != nil {
		return nil, err
	}
	return create, nil
}

// ListInboxes lists inbox messages, newest first.
func (d *DB) ListInboxes(ctx context.Context, find *store.FindInbox) ([]*store.Inbox, error) {
	filter := bson.M{}
	if find.ID != nil {
		filter["_id"] = *find.ID
	}
	if find.SenderID != nil {
		filter["sender_id"] = *find.SenderID
	}
	if find.ReceiverID != nil {
		filter["receiver_id"] = *find.ReceiverID
	}
	if find.Status != nil {
		filter["status"] = string(*find.Status)
	}
	if find.MessageType != nil {
		filter["message_type"] = find.MessageType.String()
	}
	docs, err := decodeAll[inboxDoc](ctx)(d.col(colInbox).Find(ctx, filter, findOpts(find.Limit, find.Offset).SetSort(bson.D{{Key: "created_ts", Value: -1}, {Key: "_id", Value: -1}})))
	if err != nil {
		return nil, err
	}
	out := []*store.Inbox{}
	for i := range docs {
		inbox, err := docs[i].toStore()
		if err != nil {
			return nil, err
		}
		out = append(out, inbox)
	}
	return out, nil
}

// UpdateInbox updates the status of an inbox message.
func (d *DB) UpdateInbox(ctx context.Context, update *store.UpdateInbox) (*store.Inbox, error) {
	doc := inboxDoc{}
	err := d.col(colInbox).FindOneAndUpdate(ctx, bson.M{"_id": update.ID},
		bson.M{"$set": bson.M{"status": update.Status.String()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&doc)
	if err != nil {
		return nil, err
	}
	return doc.toStore()
}

// DeleteInbox deletes an inbox message.
func (d *DB) DeleteInbox(ctx context.Context, delete *store.DeleteInbox) error {
	_, err := d.col(colInbox).DeleteOne(ctx, bson.M{"_id": delete.ID})
	return err
}
