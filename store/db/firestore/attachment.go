package firestore

import (
	"context"
	"regexp"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/usememos/memos/filter"
	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/store"
)

func isNoDocuments(err error) bool {
	return errors.Is(err, mongo.ErrNoDocuments)
}

func (d *DB) insertAttachment(ctx context.Context, create *store.Attachment) error {
	id, err := d.nextID(ctx, colAttachment)
	if err != nil {
		return err
	}
	storageType := ""
	if create.StorageType != storepb.AttachmentStorageType_ATTACHMENT_STORAGE_TYPE_UNSPECIFIED {
		storageType = create.StorageType.String()
	}
	payload := "{}"
	if create.Payload != nil {
		data, err := protojson.Marshal(create.Payload)
		if err != nil {
			return errors.Wrap(err, "failed to marshal attachment payload")
		}
		payload = string(data)
	}
	ts := now()
	doc := attachmentDoc{
		ID: id, UID: create.UID, CreatorID: create.CreatorID, CreatedTs: ts, UpdatedTs: ts,
		Filename: create.Filename, Blob: create.Blob, Type: create.Type, Size: create.Size,
		MemoID: create.MemoID, StorageType: storageType, Reference: create.Reference, Payload: payload,
	}
	if _, err := d.col(colAttachment).InsertOne(ctx, doc); err != nil {
		return err
	}
	if err := d.claim(ctx, colAttachment, "uid", create.UID, id); err != nil {
		return err
	}
	create.ID, create.CreatedTs, create.UpdatedTs = id, ts, ts
	return nil
}

// CreateAttachment inserts an attachment, enforcing the write policy when present.
func (d *DB) CreateAttachment(ctx context.Context, create *store.Attachment) (*store.Attachment, error) {
	if create.Policy != nil && (create.MemoID == nil || create.CreatorID != create.Policy.ActorUserID) {
		return nil, store.ErrMemoPermissionDenied
	}
	err := d.withTx(ctx, func(ctx context.Context) error {
		if create.Policy != nil {
			if _, err := d.validateMemoWritePolicy(ctx, *create.MemoID, create.Policy, nil); err != nil {
				return err
			}
		}
		return d.insertAttachment(ctx, create)
	})
	if err != nil {
		return nil, err
	}
	return create, nil
}

const attachmentMemoField = "_memo"

// ListAttachments lists attachments, newest update first.
func (d *DB) ListAttachments(ctx context.Context, find *store.FindAttachment) ([]*store.Attachment, error) {
	and := bson.A{}
	if v := find.ID; v != nil {
		and = append(and, bson.M{"_id": *v})
	}
	if v := find.UID; v != nil {
		and = append(and, bson.M{"uid": *v})
	}
	if v := find.CreatorID; v != nil {
		and = append(and, bson.M{"creator_id": *v})
	}
	if v := find.Filename; v != nil {
		and = append(and, bson.M{"filename": *v})
	}
	if v := find.FilenameSearch; v != nil {
		and = append(and, bson.M{"filename": bson.M{"$regex": regexp.QuoteMeta(*v), "$options": "i"}})
	}
	if v := find.MemoID; v != nil {
		and = append(and, bson.M{"memo_id": *v})
	}
	if len(find.MemoIDList) > 0 {
		and = append(and, bson.M{"memo_id": int32In(find.MemoIDList)})
	}
	if find.HasRelatedMemo {
		and = append(and, bson.M{"memo_id": bson.M{"$ne": nil}})
	}
	needsMemo := len(find.Filters) > 0 || find.Access != nil
	if len(find.Filters) > 0 {
		engine, err := filter.DefaultAttachmentEngine()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get filter engine")
		}
		filters, err := compileFilters(ctx, engine, find.Filters, filter.MongoRenderOptions{Resolver: resolver{d}, MemoPrefix: attachmentMemoField + "."})
		if err != nil {
			return nil, errors.Wrap(err, "failed to append filter conditions")
		}
		for _, f := range filters {
			and = append(and, f)
		}
	}
	if access := find.Access; access != nil {
		scope := bson.A{}
		if access.UserID != nil {
			active, err := d.userActive(ctx, *access.UserID)
			if err != nil {
				return nil, err
			}
			if active {
				scope = append(scope, bson.M{"memo_id": nil, "creator_id": *access.UserID})
			}
		}
		memoAccess, err := d.memoAccessFilter(ctx, access, attachmentMemoField+".")
		if err != nil {
			return nil, err
		}
		scope = append(scope, bson.M{"$and": bson.A{bson.M{"memo_id": bson.M{"$ne": nil}}, memoAccess}})
		and = append(and, bson.M{"$or": scope})
	}
	match := bson.M{}
	if len(and) > 0 {
		match = bson.M{"$and": and}
	}

	pipeline := mongo.Pipeline{}
	if needsMemo {
		pipeline = append(pipeline,
			bson.D{{Key: "$lookup", Value: bson.M{"from": colMemo, "localField": "memo_id", "foreignField": "_id", "as": attachmentMemoField}}},
			bson.D{{Key: "$set", Value: bson.M{attachmentMemoField: bson.M{"$first": "$" + attachmentMemoField}}}},
		)
	}
	pipeline = append(pipeline,
		bson.D{{Key: "$match", Value: match}},
		bson.D{{Key: "$sort", Value: bson.D{{Key: "updated_ts", Value: -1}, {Key: "_id", Value: -1}}}},
	)
	if find.Limit != nil {
		if find.Offset != nil {
			pipeline = append(pipeline, bson.D{{Key: "$skip", Value: int64(*find.Offset)}})
		}
		pipeline = append(pipeline, bson.D{{Key: "$limit", Value: int64(*find.Limit)}})
	}
	projection := bson.M{attachmentMemoField: 0}
	if !find.GetBlob {
		projection["blob"] = 0
	}
	if !needsMemo {
		delete(projection, attachmentMemoField)
	}
	if len(projection) > 0 {
		pipeline = append(pipeline, bson.D{{Key: "$project", Value: projection}})
	}
	docs, err := decodeAll[attachmentDoc](ctx)(d.col(colAttachment).Aggregate(ctx, pipeline))
	if err != nil {
		return nil, err
	}
	out := make([]*store.Attachment, 0, len(docs))
	memoIDs, creatorIDs := []int32{}, []int32{}
	for i := range docs {
		attachment, err := docs[i].toStore()
		if err != nil {
			return nil, err
		}
		out = append(out, attachment)
		if attachment.MemoID != nil {
			memoIDs = append(memoIDs, *attachment.MemoID)
		}
		creatorIDs = append(creatorIDs, attachment.CreatorID)
	}
	if err := d.fillAttachmentNames(ctx, out, memoIDs, creatorIDs); err != nil {
		return nil, err
	}
	return out, nil
}

// fillAttachmentNames sets the memo UID and creator username.
func (d *DB) fillAttachmentNames(ctx context.Context, attachments []*store.Attachment, memoIDs, creatorIDs []int32) error {
	type uidDoc struct {
		ID  int32  `bson:"_id"`
		UID string `bson:"uid"`
	}
	type nameDoc struct {
		ID       int32  `bson:"_id"`
		Username string `bson:"username"`
	}
	memoUID := map[int32]string{}
	for _, batch := range batches(memoIDs, batchSize) {
		docs, err := decodeAll[uidDoc](ctx)(d.col(colMemo).Find(ctx, bson.M{"_id": int32In(batch)}, options.Find().SetProjection(bson.M{"uid": 1})))
		if err != nil {
			return err
		}
		for _, doc := range docs {
			memoUID[doc.ID] = doc.UID
		}
	}
	username := map[int32]string{}
	for _, batch := range batches(creatorIDs, batchSize) {
		docs, err := decodeAll[nameDoc](ctx)(d.col(colUser).Find(ctx, bson.M{"_id": int32In(batch)}, options.Find().SetProjection(bson.M{"username": 1})))
		if err != nil {
			return err
		}
		for _, doc := range docs {
			username[doc.ID] = doc.Username
		}
	}
	for _, a := range attachments {
		if a.MemoID != nil {
			if uid, ok := memoUID[*a.MemoID]; ok {
				uid := uid
				a.MemoUID = &uid
			}
		}
		if name, ok := username[a.CreatorID]; ok {
			name := name
			a.CreatorUsername = &name
		}
	}
	return nil
}

func (d *DB) applyAttachmentUpdate(ctx context.Context, update *store.UpdateAttachment) error {
	set := bson.M{}
	if v := update.UID; v != nil {
		set["uid"] = *v
	}
	if v := update.UpdatedTs; v != nil {
		set["updated_ts"] = *v
	}
	if v := update.Filename; v != nil {
		set["filename"] = *v
	}
	if v := update.MemoID; v != nil {
		set["memo_id"] = *v
	}
	if v := update.Payload; v != nil {
		data, err := protojson.Marshal(v)
		if err != nil {
			return errors.Wrap(err, "failed to marshal attachment payload")
		}
		set["payload"] = string(data)
	}
	if len(set) == 0 {
		return nil
	}
	if _, err := d.col(colAttachment).UpdateOne(ctx, bson.M{"_id": update.ID}, bson.M{"$set": set}); err != nil {
		return errors.Wrap(err, "failed to update attachment")
	}
	if v := update.UID; v != nil {
		if err := d.reclaim(ctx, colAttachment, "uid", *v, update.ID); err != nil {
			return err
		}
	}
	return nil
}

// UpdateAttachment updates an attachment, enforcing the policy when present.
func (d *DB) UpdateAttachment(ctx context.Context, update *store.UpdateAttachment) error {
	if update.Policy != nil && update.MemoID != nil {
		return store.ErrMemoMutationConflict
	}
	return d.withTx(ctx, func(ctx context.Context) error {
		if update.Policy != nil {
			if err := d.authorizeAttachmentTargets(ctx, update.Policy.ActorUserID, []int32{update.ID}, nil); err != nil {
				return err
			}
		}
		return d.applyAttachmentUpdate(ctx, update)
	})
}

// authorizeAttachmentTargets validates that the actor may mutate the
// attachments and their memos.
func (d *DB) authorizeAttachmentTargets(ctx context.Context, actorUserID int32, attachmentIDs []int32, expectedMemoContents map[int32]string) error {
	actor, err := d.requireActiveMemoActor(ctx, actorUserID)
	if err != nil {
		return err
	}
	attachments, err := d.listAttachmentSnapshots(ctx, bson.M{"_id": int32In(attachmentIDs)})
	if err != nil {
		return errors.Wrap(err, "failed to read attachment targets")
	}
	memoIDs, err := store.ValidateAttachmentMutationTargets(actorUserID, actor.Admin, attachmentIDs, attachments)
	if err != nil {
		return err
	}
	if expectedMemoContents != nil {
		if err := store.ValidateAttachmentDeletionMemoSnapshots(memoIDs, expectedMemoContents); err != nil {
			return err
		}
	}
	for _, memoID := range memoIDs {
		memo, found, err := d.getMemoDoc(ctx, memoID)
		if err != nil {
			return errors.Wrap(err, "failed to read attachment memo")
		}
		if !found {
			return store.ErrMemoMutationConflict
		}
		if expectedMemoContents != nil && memo.Content != expectedMemoContents[memoID] {
			return store.ErrMemoMutationConflict
		}
		snapshot := &store.MemoWriteSnapshot{
			ActorIsAdmin: actor.Admin, CreatorID: memo.CreatorID, RowStatus: store.RowStatus(memo.RowStatus),
			SpaceID: memo.SpaceID, Visibility: store.Visibility(memo.Visibility),
		}
		if memo.SpaceID != nil {
			if snapshot.SourceSpaceExists, err = d.spaceExists(ctx, *memo.SpaceID); err != nil {
				return err
			}
			if snapshot.SourceSpaceExists && !actor.Admin {
				if snapshot.SourceMemberActive, err = d.spaceMemberActive(ctx, *memo.SpaceID, actorUserID); err != nil {
					return err
				}
			}
		}
		if err := store.ValidateMemoWriteSnapshot(&store.MemoWritePolicy{ActorUserID: actorUserID}, nil, snapshot); err != nil {
			return err
		}
	}
	return nil
}

// DeleteAttachment deletes one attachment.
func (d *DB) DeleteAttachment(ctx context.Context, delete *store.DeleteAttachment) error {
	return d.DeleteAttachments(ctx, []*store.DeleteAttachment{delete})
}

// DeleteAttachments deletes attachments.
func (d *DB) DeleteAttachments(ctx context.Context, deletes []*store.DeleteAttachment) error {
	if len(deletes) == 0 {
		return nil
	}
	ids := make([]int32, 0, len(deletes))
	for _, del := range deletes {
		ids = append(ids, del.ID)
	}
	return d.withTx(ctx, func(ctx context.Context) error {
		return d.deleteByIDs(ctx, colAttachment, ids)
	})
}

// DeleteAttachmentsWithPolicy authorizes and deletes attachments.
func (d *DB) DeleteAttachmentsWithPolicy(ctx context.Context, policy *store.AttachmentDeletionPolicy, attachmentIDs []int32) error {
	if policy == nil || policy.ActorUserID <= 0 {
		return store.ErrMemoPermissionDenied
	}
	return d.withTx(ctx, func(ctx context.Context) error {
		expected := policy.ExpectedMemoContents
		if expected == nil {
			expected = map[int32]string{}
		}
		if err := d.authorizeAttachmentTargets(ctx, policy.ActorUserID, attachmentIDs, expected); err != nil {
			return err
		}
		for _, id := range attachmentIDs {
			n, err := d.deleteRows(ctx, colAttachment, bson.M{"_id": id})
			if err != nil {
				return errors.Wrap(err, "failed to delete attachment")
			}
			if n != 1 {
				return store.ErrMemoMutationConflict
			}
		}
		return nil
	})
}

// GetAttachmentStorageUsage sums attachment sizes for a creator.
func (d *DB) GetAttachmentStorageUsage(ctx context.Context, creatorID int32) (int64, error) {
	cur, err := d.col(colAttachment).Aggregate(ctx, mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{"creator_id": creatorID}}},
		bson.D{{Key: "$group", Value: bson.M{"_id": nil, "total": bson.M{"$sum": "$size"}}}},
	})
	if err != nil {
		return 0, errors.Wrap(err, "failed to sum attachment sizes")
	}
	type total struct {
		Total int64 `bson:"total"`
	}
	rows, err := decodeAll[total](ctx)(cur, nil)
	if err != nil {
		return 0, errors.Wrap(err, "failed to sum attachment sizes")
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Total, nil
}

// ApplyMemoMutation atomically updates a memo, its attachments, and its
// reference relations.
func (d *DB) ApplyMemoMutation(ctx context.Context, mutation *store.MemoMutation) error {
	return d.withTx(ctx, func(ctx context.Context) error {
		if err := d.validateRelationEndpoints(ctx, mutation); err != nil {
			return err
		}
		if create := mutation.MemoCreate; create != nil {
			if err := d.validateMemoCreate(ctx, create); err != nil {
				return err
			}
			if mutation.CommentContextMemoID != nil {
				if err := d.authorizeComment(ctx, *mutation.CommentContextMemoID, create.CreatorID); err != nil {
					return err
				}
			}
			if err := d.insertMemo(ctx, create); err != nil {
				return err
			}
			mutation.MemoID = create.ID
			mutation.MemoCreatorID = create.CreatorID
			mutation.ExpectedMemoContent = create.Content
			for _, relation := range mutation.ReferenceRelations {
				if relation != nil {
					relation.MemoID = create.ID
				}
			}
			if mutation.CommentContextMemoID != nil {
				if err := d.insertCommentRelation(ctx, create.ID, *mutation.CommentContextMemoID); err != nil {
					return err
				}
			}
		}
		actorUserID := mutation.ActorUserID()
		actorIsAdmin := false
		if _, err := d.touchParent(ctx, colMemo, mutation.MemoID); err != nil {
			return err
		}
		if policy := mutation.WritePolicy(); policy != nil {
			snapshot, err := d.validateMemoWritePolicy(ctx, mutation.MemoID, policy, mutation.MemoUpdate)
			if err != nil {
				return err
			}
			actorIsAdmin = snapshot.ActorIsAdmin
		}
		memo, found, err := d.getMemoDoc(ctx, mutation.MemoID)
		if err != nil {
			return errors.Wrap(err, "failed to lock memo")
		}
		if !found {
			return errors.Wrap(store.ErrMemoMutationConflict, "memo no longer exists")
		}
		if memo.CreatorID != mutation.MemoCreatorID || memo.Content != mutation.ExpectedMemoContent {
			return errors.Wrap(store.ErrMemoMutationConflict, "memo changed while applying mutation")
		}
		removed := []*store.Attachment{}
		if len(mutation.RemovedAttachmentIDs) > 0 {
			if removed, err = d.listAttachmentSnapshots(ctx, bson.M{"_id": int32In(mutation.RemovedAttachmentIDs)}); err != nil {
				return errors.Wrap(err, "failed to read removed attachments")
			}
		}
		if len(removed) != len(mutation.RemovedAttachmentIDs) {
			return errors.Wrap(store.ErrMemoMutationConflict, "removed attachment no longer exists")
		}
		for _, a := range removed {
			if !store.MemoAttachmentRemovalAllowed(a, mutation.MemoID, actorUserID, actorIsAdmin) {
				return errors.Wrap(store.ErrMemoMutationConflict, "attachment is no longer removable from the memo")
			}
		}
		for _, binding := range mutation.Bindings {
			current := attachmentDoc{}
			found, err := findOne(ctx, d.col(colAttachment), bson.M{"_id": binding.ID}, &current, options.FindOne().SetProjection(bson.M{"blob": 0}))
			if err != nil {
				return errors.Wrap(err, "failed to lock attachment")
			}
			if !found {
				return errors.Wrapf(store.ErrMemoMutationConflict, "attachment %s no longer exists", binding.UID)
			}
			if binding.WasBoundToMemo {
				if current.MemoID == nil || *current.MemoID != mutation.MemoID {
					return errors.Wrapf(store.ErrMemoMutationConflict, "attachment %s is no longer bound to the memo", binding.UID)
				}
			} else if !store.MemoAttachmentBindingOwnerAllowed(current.CreatorID, mutation.MemoCreatorID, actorUserID, actorIsAdmin) || current.MemoID != nil {
				return errors.Wrapf(store.ErrMemoMutationConflict, "attachment %s is no longer available", binding.UID)
			}
			if _, err := d.col(colAttachment).UpdateOne(ctx, bson.M{"_id": binding.ID}, bson.M{"$set": bson.M{"memo_id": mutation.MemoID, "updated_ts": binding.UpdatedTs}}); err != nil {
				return errors.Wrap(err, "failed to bind attachment")
			}
		}
		for _, a := range removed {
			n, err := d.deleteRows(ctx, colAttachment, bson.M{"_id": a.ID, "memo_id": mutation.MemoID})
			if err != nil {
				return errors.Wrap(err, "failed to delete removed attachment")
			}
			if n != 1 {
				return errors.Wrap(store.ErrMemoMutationConflict, "attachment is no longer bound to the memo")
			}
		}
		for _, id := range mutation.RequiredAttachmentIDs {
			ok, err := exists(ctx, d.col(colAttachment), bson.M{"_id": id, "memo_id": mutation.MemoID})
			if err != nil {
				return errors.Wrap(err, "failed to verify referenced attachment")
			}
			if !ok {
				return errors.Wrap(store.ErrMemoMutationConflict, "a referenced attachment is no longer bound to the memo")
			}
		}
		if mutation.MemoUpdate != nil {
			if mutation.MemoUpdate.ID != mutation.MemoID {
				return errors.New("memo update target does not match attachment mutation")
			}
			if err := d.applyMemoUpdate(ctx, mutation.MemoUpdate); err != nil {
				return err
			}
		}
		if mutation.ReplaceReferenceRelations {
			if err := d.replaceReferenceRelations(ctx, mutation.MemoID, mutation.ReferenceRelations); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *DB) authorizeComment(ctx context.Context, contextMemoID, actorUserID int32) error {
	snapshot, found, err := d.memoParticipation(ctx, contextMemoID, actorUserID)
	if err != nil {
		return err
	}
	if !found {
		return store.ErrMemoSpaceNotWritable
	}
	return store.ValidateMemoCommentAuthorization(snapshot)
}

func (d *DB) insertCommentRelation(ctx context.Context, memoID, contextMemoID int32) error {
	if memoID <= 0 || contextMemoID <= 0 || memoID == contextMemoID {
		return errors.New("invalid COMMENT relation")
	}
	if _, err := d.col(colMemoRelation).InsertOne(ctx, memoRelationDoc{Key: memoRelationKey(memoID, contextMemoID, string(store.MemoRelationComment)), MemoID: memoID, RelatedMemoID: contextMemoID, Type: string(store.MemoRelationComment)}); err != nil {
		return errors.Wrap(err, "failed to insert COMMENT relation")
	}
	return nil
}

func (d *DB) upsertRelation(ctx context.Context, relation *store.MemoRelation) error {
	key := bson.M{"memo_id": relation.MemoID, "related_memo_id": relation.RelatedMemoID, "type": string(relation.Type)}
	_, err := d.col(colMemoRelation).UpdateOne(ctx,
		bson.M{"_id": memoRelationKey(relation.MemoID, relation.RelatedMemoID, string(relation.Type))},
		bson.M{"$setOnInsert": key}, options.UpdateOne().SetUpsert(true))
	return err
}

func (d *DB) replaceReferenceRelations(ctx context.Context, memoID int32, relations []*store.MemoRelation) error {
	if _, err := d.col(colMemoRelation).DeleteMany(ctx, bson.M{"memo_id": memoID, "type": string(store.MemoRelationReference)}); err != nil {
		return errors.Wrap(err, "failed to delete memo reference relations")
	}
	for _, relation := range relations {
		if relation == nil || relation.MemoID != memoID || relation.Type != store.MemoRelationReference {
			return errors.New("invalid memo reference relation mutation")
		}
		if err := d.upsertRelation(ctx, relation); err != nil {
			return errors.Wrap(err, "failed to insert memo reference relation")
		}
	}
	return nil
}

// validateRelationEndpoints checks that the actor can read every endpoint
// of the relations the mutation writes.
func (d *DB) validateRelationEndpoints(ctx context.Context, mutation *store.MemoMutation) error {
	if !mutation.ReplaceReferenceRelations && mutation.CommentContextMemoID == nil {
		return nil
	}
	actorUserID := mutation.ActorUserID()
	actor, err := d.memoActor(ctx, actorUserID)
	if err != nil {
		return err
	}
	unique := map[int32]struct{}{}
	if mutation.MemoCreate == nil && mutation.MemoID > 0 {
		unique[mutation.MemoID] = struct{}{}
	} else if mutation.CommentContextMemoID != nil {
		unique[*mutation.CommentContextMemoID] = struct{}{}
	}
	for _, relation := range mutation.ReferenceRelations {
		if relation != nil {
			unique[relation.RelatedMemoID] = struct{}{}
		}
	}
	ids := make([]int32, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	stableSort(ids, func(a, b int32) bool { return a < b })
	for _, id := range ids {
		memo, found, err := d.getMemoDoc(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return store.ErrMemoMutationConflict
		}
		snapshot := &store.MemoRelationEndpointSnapshot{
			ActorUserID: actorUserID, Actor: actor, EndpointID: memo.ID, EndpointCreatorID: memo.CreatorID,
			EndpointRowStatus: store.RowStatus(memo.RowStatus), EndpointVisibility: store.Visibility(memo.Visibility), EndpointSpaceID: memo.SpaceID,
		}
		if memo.SpaceID != nil {
			if snapshot.EndpointSpaceExists, err = d.spaceExists(ctx, *memo.SpaceID); err != nil {
				return err
			}
			if snapshot.EndpointSpaceExists && !actor.Admin {
				if snapshot.EndpointMemberActive, err = d.spaceMemberActive(ctx, *memo.SpaceID, actorUserID); err != nil {
					return err
				}
			}
		}
		if err := store.ValidateMemoRelationEndpointRead(snapshot); err != nil {
			return err
		}
	}
	return nil
}

// UpsertMemoRelation creates a relation if absent.
func (d *DB) UpsertMemoRelation(ctx context.Context, create *store.MemoRelation) (*store.MemoRelation, error) {
	if err := d.upsertRelation(ctx, create); err != nil {
		return nil, err
	}
	return &store.MemoRelation{MemoID: create.MemoID, RelatedMemoID: create.RelatedMemoID, Type: create.Type}, nil
}

// ListMemoRelations lists relations, newest source memo first.
func (d *DB) ListMemoRelations(ctx context.Context, find *store.FindMemoRelation) ([]*store.MemoRelation, error) {
	and := bson.A{}
	if find.MemoID != nil {
		and = append(and, bson.M{"memo_id": *find.MemoID})
	}
	if find.RelatedMemoID != nil {
		and = append(and, bson.M{"related_memo_id": *find.RelatedMemoID})
	}
	if find.Type != nil {
		and = append(and, bson.M{"type": string(*find.Type)})
	}
	if len(find.MemoIDList) > 0 {
		and = append(and, bson.M{"$or": bson.A{bson.M{"memo_id": int32In(find.MemoIDList)}, bson.M{"related_memo_id": int32In(find.MemoIDList)}}})
	}
	if len(find.SourceMemoIDList) > 0 {
		and = append(and, bson.M{"memo_id": int32In(find.SourceMemoIDList)})
	}
	if len(find.RelatedMemoIDList) > 0 {
		and = append(and, bson.M{"related_memo_id": int32In(find.RelatedMemoIDList)})
	}
	if find.SourceMemoRowStatus != nil {
		ids, err := d.listIDs(ctx, colMemo, bson.M{"row_status": string(*find.SourceMemoRowStatus)})
		if err != nil {
			return nil, err
		}
		and = append(and, bson.M{"memo_id": int32In(ids)})
	}
	if find.MemoFilter != nil {
		engine, err := filter.DefaultEngine()
		if err != nil {
			return nil, err
		}
		doc, err := engine.CompileToMongo(ctx, *find.MemoFilter, filter.MongoRenderOptions{Resolver: resolver{d}})
		if err != nil {
			return nil, err
		}
		if len(doc) > 0 {
			ids, err := d.listIDs(ctx, colMemo, doc)
			if err != nil {
				return nil, err
			}
			and = append(and, bson.M{"memo_id": int32In(ids)}, bson.M{"related_memo_id": int32In(ids)})
		}
	}
	query := bson.M{}
	if len(and) > 0 {
		query = bson.M{"$and": and}
	}
	docs, err := decodeAll[memoRelationDoc](ctx)(d.col(colMemoRelation).Find(ctx, query, findOpts(find.Limit, find.Offset).SetSort(bson.D{{Key: "memo_id", Value: -1}, {Key: "related_memo_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	out := []*store.MemoRelation{}
	for _, doc := range docs {
		out = append(out, &store.MemoRelation{MemoID: doc.MemoID, RelatedMemoID: doc.RelatedMemoID, Type: store.MemoRelationType(doc.Type)})
	}
	return out, nil
}

// DeleteMemoRelation deletes reference relations.
func (d *DB) DeleteMemoRelation(ctx context.Context, delete *store.DeleteMemoRelation) error {
	if err := store.ValidateMemoRelationDelete(delete); err != nil {
		return err
	}
	f := bson.M{"type": string(*delete.Type)}
	if delete.MemoID != nil {
		f["memo_id"] = *delete.MemoID
	}
	if delete.RelatedMemoID != nil {
		f["related_memo_id"] = *delete.RelatedMemoID
	}
	_, err := d.col(colMemoRelation).DeleteMany(ctx, f)
	return err
}

// UpsertReaction adds a reaction, enforcing the policy when present.
func (d *DB) UpsertReaction(ctx context.Context, upsert *store.Reaction) (*store.Reaction, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		if upsert.Policy != nil {
			snapshot, found, err := d.memoParticipation(ctx, upsert.MemoID, upsert.Policy.ActorUserID)
			if err != nil {
				return errors.Wrap(err, "failed to read reaction participation")
			}
			if !found {
				return store.ErrReactionMemoNotFound
			}
			if err := store.ValidateReactionWriteParticipation(upsert, snapshot); err != nil {
				return err
			}
		}
		ok, err := d.touchParent(ctx, colMemo, upsert.MemoID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.Wrap(store.ErrReactionMemoNotFound, "failed to create reaction")
		}
		id, err := d.nextID(ctx, colReaction)
		if err != nil {
			return err
		}
		ts := now()
		doc := reactionDoc{ID: id, CreatedTs: ts, CreatorID: upsert.CreatorID, MemoID: upsert.MemoID, ReactionType: upsert.ReactionType}
		if _, err := d.col(colReaction).InsertOne(ctx, doc); err != nil {
			return err
		}
		if err := d.claim(ctx, colReaction, "creator_memo_type", reactionClaim(upsert.CreatorID, upsert.MemoID, upsert.ReactionType), id); err != nil {
			return err
		}
		upsert.ID, upsert.CreatedTs = id, ts
		return nil
	})
	if err != nil {
		return nil, err
	}
	return upsert, nil
}

// ListReactions lists reactions in id order.
func (d *DB) ListReactions(ctx context.Context, find *store.FindReaction) ([]*store.Reaction, error) {
	f := bson.M{}
	if find.ID != nil {
		f["_id"] = *find.ID
	}
	if find.CreatorID != nil {
		f["creator_id"] = *find.CreatorID
	}
	if find.MemoID != nil {
		f["memo_id"] = *find.MemoID
	}
	if len(find.MemoIDList) > 0 {
		f["memo_id"] = int32In(find.MemoIDList)
	}
	docs, err := decodeAll[reactionDoc](ctx)(d.col(colReaction).Find(ctx, f, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	out := []*store.Reaction{}
	for i := range docs {
		out = append(out, docs[i].toStore())
	}
	return out, nil
}

// GetReaction returns the first matching reaction or nil.
func (d *DB) GetReaction(ctx context.Context, find *store.FindReaction) (*store.Reaction, error) {
	list, err := d.ListReactions(ctx, find)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return list[0], nil
}

// DeleteReaction deletes reactions; with an actor it checks ownership.
func (d *DB) DeleteReaction(ctx context.Context, delete *store.DeleteReaction) error {
	if delete.ActorUserID != nil {
		return d.withTx(ctx, func(ctx context.Context) error {
			actorIsAdmin := false
			if delete.Policy != nil {
				reaction := &store.Reaction{CreatorID: *delete.ActorUserID, MemoID: *delete.MemoID, Policy: delete.Policy}
				snapshot, found, err := d.memoParticipation(ctx, reaction.MemoID, delete.Policy.ActorUserID)
				if err != nil {
					return errors.Wrap(err, "failed to read reaction participation")
				}
				if !found {
					return store.ErrReactionMemoNotFound
				}
				if err := store.ValidateReactionWithdrawal(reaction, snapshot); err != nil {
					return err
				}
				actorIsAdmin = snapshot.Actor.Admin
			}
			current := reactionDoc{}
			found, err := findOne(ctx, d.col(colReaction), bson.M{"_id": *delete.ID}, &current)
			if err != nil {
				return errors.Wrap(err, "failed to read reaction for deletion")
			}
			if !found {
				return nil
			}
			if (current.CreatorID != *delete.ActorUserID && !actorIsAdmin) || (delete.MemoID != nil && current.MemoID != *delete.MemoID) {
				return store.ErrReactionPermissionDenied
			}
			_, err = d.deleteRows(ctx, colReaction, bson.M{"_id": *delete.ID})
			return errors.Wrap(err, "failed to delete reaction")
		})
	}
	f := bson.M{}
	if delete.ID != nil {
		f["_id"] = *delete.ID
	}
	if delete.MemoID != nil {
		f["memo_id"] = *delete.MemoID
	}
	if len(f) == 0 {
		return nil
	}
	_, err := d.deleteRows(ctx, colReaction, f)
	return err
}

// CreateMemoShare creates a share link, enforcing the policy when present.
func (d *DB) CreateMemoShare(ctx context.Context, create *store.MemoShare) (*store.MemoShare, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		if create.Policy != nil {
			if _, err := d.validateMemoWritePolicy(ctx, create.MemoID, create.Policy, nil); err != nil {
				return err
			}
		}
		id, err := d.nextID(ctx, colMemoShare)
		if err != nil {
			return err
		}
		ts := now()
		doc := memoShareDoc{ID: id, UID: create.UID, MemoID: create.MemoID, CreatorID: create.CreatorID, CreatedTs: ts, ExpiresTs: create.ExpiresTs}
		if _, err := d.col(colMemoShare).InsertOne(ctx, doc); err != nil {
			return err
		}
		if err := d.claim(ctx, colMemoShare, "uid", create.UID, id); err != nil {
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

func memoShareFilter(id *int32, uid *string, memoID *int32, creatorID *int32) bson.M {
	f := bson.M{}
	if id != nil {
		f["_id"] = *id
	}
	if uid != nil {
		f["uid"] = *uid
	}
	if memoID != nil {
		f["memo_id"] = *memoID
	}
	if creatorID != nil {
		f["creator_id"] = *creatorID
	}
	return f
}

// ListMemoShares lists share links.
func (d *DB) ListMemoShares(ctx context.Context, find *store.FindMemoShare) ([]*store.MemoShare, error) {
	docs, err := decodeAll[memoShareDoc](ctx)(d.col(colMemoShare).Find(ctx, memoShareFilter(find.ID, find.UID, find.MemoID, find.CreatorID), options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	out := []*store.MemoShare{}
	for i := range docs {
		out = append(out, docs[i].toStore())
	}
	return out, nil
}

// GetMemoShare returns one share link or nil.
func (d *DB) GetMemoShare(ctx context.Context, find *store.FindMemoShare) (*store.MemoShare, error) {
	doc := memoShareDoc{}
	found, err := findOne(ctx, d.col(colMemoShare), memoShareFilter(find.ID, find.UID, find.MemoID, find.CreatorID), &doc)
	if err != nil || !found {
		return nil, err
	}
	return doc.toStore(), nil
}

// DeleteMemoShare deletes a share link, enforcing the policy when present.
func (d *DB) DeleteMemoShare(ctx context.Context, delete *store.DeleteMemoShare) error {
	f := memoShareFilter(delete.ID, delete.UID, nil, nil)
	if delete.Policy == nil {
		_, err := d.deleteRows(ctx, colMemoShare, f)
		return err
	}
	return d.withTx(ctx, func(ctx context.Context) error {
		if _, err := d.validateMemoWritePolicy(ctx, *delete.MemoID, delete.Policy, nil); err != nil {
			return err
		}
		f["memo_id"] = *delete.MemoID
		n, err := d.deleteRows(ctx, colMemoShare, f)
		if err != nil {
			return err
		}
		if n != 1 {
			return store.ErrMemoMutationConflict
		}
		return nil
	})
}
