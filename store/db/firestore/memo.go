package firestore

import (
	"context"
	"maps"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/usememos/memos/filter"
	"github.com/usememos/memos/store"
)

// resolver lets the filter renderer look up ids by public names.
type resolver struct{ d *DB }

func (r resolver) UserIDByUsername(ctx context.Context, username string) (int32, bool, error) {
	doc := idOnly{}
	found, err := findOne(ctx, r.d.col(colUser), bson.M{"username": username}, &doc, options.FindOne().SetProjection(bson.M{"_id": 1}))
	return doc.ID, found, err
}

func (r resolver) SpaceIDByUID(ctx context.Context, uid string) (int32, bool, error) {
	doc := idOnly{}
	found, err := findOne(ctx, r.d.col(colSpace), bson.M{"uid": uid}, &doc, options.FindOne().SetProjection(bson.M{"_id": 1}))
	return doc.ID, found, err
}

func compileFilters(ctx context.Context, engine *filter.Engine, filters []string, opts filter.MongoRenderOptions) ([]bson.M, error) {
	out := []bson.M{}
	for _, f := range filters {
		doc, err := engine.CompileToMongo(ctx, f, opts)
		if err != nil {
			return nil, err
		}
		if len(doc) > 0 {
			out = append(out, doc)
		}
	}
	return out, nil
}

// memoActor reads the actor's lifecycle state and instance role.
func (d *DB) memoActor(ctx context.Context, userID int32) (store.MemoActorState, error) {
	user := userDoc{}
	found, err := findOne(ctx, d.col(colUser), bson.M{"_id": userID}, &user)
	if err != nil || !found {
		return store.MemoActorState{}, err
	}
	return store.NewMemoActorState(store.RowStatus(user.RowStatus), store.Role(user.Role)), nil
}

func (d *DB) requireActiveMemoActor(ctx context.Context, userID int32) (store.MemoActorState, error) {
	actor, err := d.memoActor(ctx, userID)
	if err != nil {
		return store.MemoActorState{}, err
	}
	if !actor.Active {
		return store.MemoActorState{}, store.ErrMemoPermissionDenied
	}
	return actor, nil
}

func (d *DB) getMemoDoc(ctx context.Context, memoID int32) (*memoDoc, bool, error) {
	doc := &memoDoc{}
	found, err := findOne(ctx, d.col(colMemo), bson.M{"_id": memoID}, doc)
	return doc, found, err
}

func (d *DB) validateMemoCreate(ctx context.Context, create *store.Memo) error {
	if _, err := d.touchParent(ctx, colUser, create.CreatorID); err != nil {
		return err
	}
	actor, err := d.memoActor(ctx, create.CreatorID)
	if err != nil {
		return err
	}
	if !actor.Active {
		return store.ErrMemoSpaceMembershipRequired
	}
	if create.SpaceID == nil {
		return nil
	}
	exists, err := d.touchParent(ctx, colSpace, *create.SpaceID)
	if err != nil {
		return err
	}
	if !exists {
		return store.ErrMemoSpaceNotWritable
	}
	if actor.Admin {
		return nil
	}
	member, err := d.activeMemberOfNormalUser(ctx, *create.SpaceID, create.CreatorID)
	if err != nil {
		return err
	}
	if !member {
		return store.ErrMemoSpaceMembershipRequired
	}
	return nil
}

// activeMemberOfNormalUser checks an ACTIVE ADMIN/USER membership whose user
// is NORMAL.
func (d *DB) activeMemberOfNormalUser(ctx context.Context, spaceID, userID int32) (bool, error) {
	member, err := d.spaceMemberActive(ctx, spaceID, userID)
	if err != nil || !member {
		return false, err
	}
	return d.userActive(ctx, userID)
}

func (d *DB) insertMemo(ctx context.Context, create *store.Memo) error {
	id, err := d.nextID(ctx, colMemo)
	if err != nil {
		return err
	}
	payload, err := marshalMemoPayload(create.Payload)
	if err != nil {
		return err
	}
	ts := now()
	createdTs, updatedTs := ts, ts
	if create.CreatedTs != 0 {
		createdTs = create.CreatedTs
	}
	if create.UpdatedTs != 0 {
		updatedTs = create.UpdatedTs
	}
	visibility := string(create.Visibility)
	if visibility == "" {
		visibility = string(store.Private)
	}
	doc := bson.M{
		"_id":        id,
		"uid":        create.UID,
		"creator_id": create.CreatorID,
		"created_ts": createdTs,
		"updated_ts": updatedTs,
		"row_status": string(store.Normal),
		"content":    create.Content,
		"visibility": visibility,
		"pinned":     false,
		"payload":    payload,
		"space_id":   create.SpaceID,
	}
	maps.Copy(doc, memoPayloadFields(create.Payload))
	if _, err := d.col(colMemo).InsertOne(ctx, doc); err != nil {
		return err
	}
	if err := d.claim(ctx, colMemo, "uid", create.UID, id); err != nil {
		return err
	}
	create.ID, create.CreatedTs, create.UpdatedTs, create.RowStatus = id, createdTs, updatedTs, store.Normal
	return nil
}

// CreateMemo inserts a memo.
func (d *DB) CreateMemo(ctx context.Context, create *store.Memo) (*store.Memo, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.validateMemoCreate(ctx, create); err != nil {
			return err
		}
		return d.insertMemo(ctx, create)
	})
	if err != nil {
		return nil, err
	}
	return create, nil
}

// memoAccessFilter builds the canonical memo read predicate.
func (d *DB) memoAccessFilter(ctx context.Context, access *store.MemoAccessScope, prefix string) (bson.M, error) {
	clauses := bson.A{}
	if access.AllowPublic {
		clauses = append(clauses, bson.M{prefix + "visibility": string(store.Public)})
	}
	archivedOwner := bson.M{}
	if access.UserID != nil {
		userID := *access.UserID
		active, err := d.userActive(ctx, userID)
		if err != nil {
			return nil, err
		}
		if active {
			auth := bson.A{bson.M{prefix + "visibility": string(store.Private), prefix + "creator_id": userID}}
			if access.AllowProtected {
				auth = append(auth, bson.M{prefix + "visibility": string(store.Protected)})
			}
			members, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, bson.M{
				"user_id": userID, "status": string(store.SpaceMemberStatusActive), "role": activeMemberRoles,
			}))
			if err != nil {
				return nil, err
			}
			spaceIDs := make([]int32, 0, len(members))
			for _, m := range members {
				spaceIDs = append(spaceIDs, m.SpaceID)
			}
			if len(spaceIDs) > 0 {
				auth = append(auth, bson.M{prefix + "visibility": string(store.SpaceAudience), prefix + "space_id": int32In(spaceIDs)})
			}
			clauses = append(clauses, bson.M{"$or": auth})
		}
		archivedOwner = bson.M{prefix + "row_status": string(store.Archived), prefix + "creator_id": userID}
	}
	if len(clauses) == 0 {
		return filter.MongoNoMatch(), nil
	}

	// Validity: the creator exists (NORMAL or ARCHIVED) and a SPACE memo's
	// Space exists. Deleted users and Spaces take their memos with them in
	// this driver, so only orphaned SPACE placement needs a check.
	spaceIDs, err := d.listIDs(ctx, colSpace, bson.M{})
	if err != nil {
		return nil, err
	}
	valid := bson.M{"$or": bson.A{
		bson.M{prefix + "visibility": bson.M{"$in": bson.A{string(store.Public), string(store.Protected), string(store.Private)}}},
		bson.M{prefix + "visibility": string(store.SpaceAudience), prefix + "space_id": int32In(spaceIDs)},
	}}
	state := bson.M{prefix + "row_status": string(store.Normal)}
	if len(archivedOwner) > 0 {
		state = bson.M{"$or": bson.A{state, archivedOwner}}
	}
	return bson.M{"$and": bson.A{bson.M{"$or": clauses}, valid, state}}, nil
}

// commentMemoIDs returns the ids of memos that have a COMMENT relation.
func (d *DB) commentMemoIDs(ctx context.Context, relatedTo *int32) ([]int32, error) {
	f := bson.M{"type": string(store.MemoRelationComment)}
	if relatedTo != nil {
		f["related_memo_id"] = *relatedTo
	}
	rels, err := decodeAll[memoRelationDoc](ctx)(d.col(colMemoRelation).Find(ctx, f, options.Find().SetProjection(bson.M{"memo_id": 1})))
	if err != nil {
		return nil, err
	}
	ids := make([]int32, 0, len(rels))
	for _, r := range rels {
		ids = append(ids, r.MemoID)
	}
	return ids, nil
}

// ListMemos lists memos matching find.
func (d *DB) ListMemos(ctx context.Context, find *store.FindMemo) ([]*store.Memo, error) {
	and := bson.A{}
	engine, err := filter.DefaultEngine()
	if err != nil {
		return nil, err
	}
	filters, err := compileFilters(ctx, engine, find.Filters, filter.MongoRenderOptions{Resolver: resolver{d}})
	if err != nil {
		return nil, err
	}
	for _, f := range filters {
		and = append(and, f)
	}
	if v := find.ID; v != nil {
		and = append(and, bson.M{"_id": *v})
	}
	if len(find.IDList) > 0 {
		and = append(and, bson.M{"_id": int32In(find.IDList)})
	}
	if v := find.UID; v != nil {
		and = append(and, bson.M{"uid": *v})
	}
	if len(find.UIDList) > 0 {
		and = append(and, bson.M{"uid": bson.M{"$in": find.UIDList}})
	}
	if v := find.CreatorID; v != nil {
		and = append(and, bson.M{"creator_id": *v})
	}
	if v := find.RowStatus; v != nil {
		and = append(and, bson.M{"row_status": string(*v)})
	}
	if len(find.VisibilityList) > 0 {
		vs := bson.A{}
		for _, v := range find.VisibilityList {
			vs = append(vs, v.String())
		}
		and = append(and, bson.M{"visibility": bson.M{"$in": vs}})
	}
	if v := find.CommentContextMemoID; v != nil {
		ids, err := d.commentMemoIDs(ctx, v)
		if err != nil {
			return nil, err
		}
		and = append(and, bson.M{"_id": int32In(ids)})
	}
	if access := find.Access; access != nil {
		f, err := d.memoAccessFilter(ctx, access, "")
		if err != nil {
			return nil, err
		}
		and = append(and, f)
	}
	if find.ExcludeComments {
		ids, err := d.commentMemoIDs(ctx, nil)
		if err != nil {
			return nil, err
		}
		if len(ids) > 0 {
			and = append(and, bson.M{"_id": bson.M{"$nin": ids}})
		}
	}
	query := bson.M{}
	if len(and) > 0 {
		query = bson.M{"$and": and}
	}

	order := -1
	if find.OrderByTimeAsc {
		order = 1
	}
	sortDoc := bson.D{}
	if find.OrderByPinned {
		sortDoc = append(sortDoc, bson.E{Key: "pinned", Value: -1})
	}
	if find.OrderByUpdatedTs {
		sortDoc = append(sortDoc, bson.E{Key: "updated_ts", Value: order})
	} else {
		sortDoc = append(sortDoc, bson.E{Key: "created_ts", Value: order})
	}
	sortDoc = append(sortDoc, bson.E{Key: "_id", Value: -1})
	opts := findOpts(find.Limit, find.Offset).SetSort(sortDoc)
	if find.ExcludeContent {
		opts.SetProjection(bson.M{"content": 0})
	}
	docs, err := decodeAll[memoDoc](ctx)(d.col(colMemo).Find(ctx, query, opts))
	if err != nil {
		return nil, err
	}
	memos := make([]*store.Memo, 0, len(docs))
	ids := make([]int32, 0, len(docs))
	for i := range docs {
		memo, err := docs[i].toStore(!find.ExcludeContent)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal payload")
		}
		memos = append(memos, memo)
		ids = append(ids, memo.ID)
	}
	if err := d.fillParentUIDs(ctx, memos, ids); err != nil {
		return nil, err
	}
	return memos, nil
}

// fillParentUIDs sets ParentUID from each memo's COMMENT relation.
func (d *DB) fillParentUIDs(ctx context.Context, memos []*store.Memo, ids []int32) error {
	if len(ids) == 0 {
		return nil
	}
	parentOf := map[int32]int32{}
	for _, batch := range batches(ids, batchSize) {
		rels, err := decodeAll[memoRelationDoc](ctx)(d.col(colMemoRelation).Find(ctx, bson.M{"type": string(store.MemoRelationComment), "memo_id": int32In(batch)}))
		if err != nil {
			return err
		}
		for _, r := range rels {
			if current, ok := parentOf[r.MemoID]; !ok || r.RelatedMemoID < current {
				parentOf[r.MemoID] = r.RelatedMemoID
			}
		}
	}
	if len(parentOf) == 0 {
		return nil
	}
	parentIDs := make([]int32, 0, len(parentOf))
	for _, p := range parentOf {
		parentIDs = append(parentIDs, p)
	}
	uidByID := map[int32]string{}
	for _, batch := range batches(parentIDs, batchSize) {
		type uidDoc struct {
			ID  int32  `bson:"_id"`
			UID string `bson:"uid"`
		}
		docs, err := decodeAll[uidDoc](ctx)(d.col(colMemo).Find(ctx, bson.M{"_id": int32In(batch)}, options.Find().SetProjection(bson.M{"uid": 1})))
		if err != nil {
			return err
		}
		for _, doc := range docs {
			uidByID[doc.ID] = doc.UID
		}
	}
	for _, memo := range memos {
		if parent, ok := parentOf[memo.ID]; ok {
			if uid, ok := uidByID[parent]; ok {
				uid := uid
				memo.ParentUID = &uid
			}
		}
	}
	return nil
}

// applyMemoUpdate writes the update's fields.
func (d *DB) applyMemoUpdate(ctx context.Context, update *store.UpdateMemo) error {
	set, unset := bson.M{}, bson.M{}
	if v := update.UID; v != nil {
		set["uid"] = *v
	}
	if v := update.CreatedTs; v != nil {
		set["created_ts"] = *v
	}
	if v := update.UpdatedTs; v != nil {
		set["updated_ts"] = *v
	}
	if v := update.RowStatus; v != nil {
		set["row_status"] = string(*v)
	}
	if v := update.Content; v != nil {
		set["content"] = *v
	}
	if v := update.Visibility; v != nil {
		set["visibility"] = string(*v)
	}
	if v := update.Pinned; v != nil {
		set["pinned"] = *v
	}
	if v := update.Payload; v != nil {
		payload, err := marshalMemoPayload(v)
		if err != nil {
			return errors.Wrap(err, "failed to marshal memo payload")
		}
		set["payload"] = payload
		maps.Copy(set, memoPayloadFields(v))
	}
	if update.ClearSpace {
		set["space_id"] = nil
	} else if v := update.SpaceID; v != nil {
		set["space_id"] = *v
	}
	if len(set) == 0 && len(unset) == 0 {
		return nil
	}
	ops := bson.M{"$set": set}
	if _, err := d.col(colMemo).UpdateOne(ctx, bson.M{"_id": update.ID}, ops); err != nil {
		return errors.Wrap(err, "failed to update memo")
	}
	if v := update.UID; v != nil {
		if err := d.reclaim(ctx, colMemo, "uid", *v, update.ID); err != nil {
			return err
		}
	}
	return nil
}

// UpdateMemo updates a memo, enforcing the write policy when present.
func (d *DB) UpdateMemo(ctx context.Context, update *store.UpdateMemo) error {
	return d.withTx(ctx, func(ctx context.Context) error {
		if update.Policy != nil {
			if _, err := d.validateMemoWritePolicy(ctx, update.ID, update.Policy, update); err != nil {
				return err
			}
		}
		return d.applyMemoUpdate(ctx, update)
	})
}

// DeleteMemo deletes a memo and its reactions.
func (d *DB) DeleteMemo(ctx context.Context, delete *store.DeleteMemo) error {
	return d.withTx(ctx, func(ctx context.Context) error {
		if _, err := d.deleteRows(ctx, colMemo, bson.M{"_id": delete.ID}); err != nil {
			return errors.Wrap(err, "failed to delete memo")
		}
		if _, err := d.deleteRows(ctx, colReaction, bson.M{"memo_id": delete.ID}); err != nil {
			return errors.Wrap(err, "failed to delete memo reactions")
		}
		return nil
	})
}

// DeleteMemoWithPolicy deletes a memo and its comment subtree as its author.
func (d *DB) DeleteMemoWithPolicy(ctx context.Context, delete *store.DeleteMemoWithPolicy) (*store.DeleteMemoWithPolicyResult, error) {
	var result *store.DeleteMemoWithPolicyResult
	err := d.withTx(ctx, func(ctx context.Context) error {
		actor, err := d.requireActiveMemoActor(ctx, delete.ActorUserID)
		if err != nil {
			return err
		}
		memo, found, err := d.getMemoDoc(ctx, delete.MemoID)
		if err != nil {
			return errors.Wrap(err, "failed to read memo")
		}
		if !found {
			return store.ErrMemoMutationConflict
		}
		if memo.CreatorID != delete.ActorUserID && !actor.Admin {
			return store.ErrMemoPermissionDenied
		}
		spaceExists, actorMember := false, false
		if memo.SpaceID != nil {
			if spaceExists, err = d.spaceExists(ctx, *memo.SpaceID); err != nil {
				return errors.Wrap(err, "failed to read memo space")
			}
			if spaceExists && !actor.Admin {
				if actorMember, err = d.spaceMemberActive(ctx, *memo.SpaceID, delete.ActorUserID); err != nil {
					return errors.Wrap(err, "failed to read memo membership")
				}
			}
		}
		canRead := store.MemoDeleteActorCanRead(store.RowStatus(memo.RowStatus), store.Visibility(memo.Visibility), memo.SpaceID, spaceExists, actorMember || actor.Admin)
		ids, err := d.commentSubtree(ctx, delete.MemoID)
		if err != nil {
			return errors.Wrap(err, "failed to collect comment memos")
		}
		attachments, err := d.deleteMemoSet(ctx, ids)
		if err != nil {
			return errors.Wrap(err, "failed to delete memo set")
		}
		result = &store.DeleteMemoWithPolicyResult{ActorCanRead: canRead, Attachments: attachments}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// commentSubtree returns the memo plus every memo commenting on it,
// transitively.
func (d *DB) commentSubtree(ctx context.Context, rootID int32) ([]int32, error) {
	ids := []int32{rootID}
	seen := map[int32]struct{}{rootID: {}}
	frontier := []int32{rootID}
	for len(frontier) > 0 {
		var next []int32
		for _, batch := range batches(frontier, batchSize) {
			rels, err := decodeAll[memoRelationDoc](ctx)(d.col(colMemoRelation).Find(ctx, bson.M{"type": string(store.MemoRelationComment), "related_memo_id": int32In(batch)}))
			if err != nil {
				return nil, err
			}
			for _, r := range rels {
				if _, ok := seen[r.MemoID]; ok {
					continue
				}
				seen[r.MemoID] = struct{}{}
				ids = append(ids, r.MemoID)
				next = append(next, r.MemoID)
			}
		}
		frontier = next
	}
	return ids, nil
}

// validateMemoWritePolicy authorizes a transport-facing memo mutation.
func (d *DB) validateMemoWritePolicy(ctx context.Context, memoID int32, policy *store.MemoWritePolicy, update *store.UpdateMemo) (*store.MemoWriteSnapshot, error) {
	actor, err := d.memoActor(ctx, policy.ActorUserID)
	if err != nil {
		return nil, err
	}
	if !actor.Active {
		return nil, store.ErrMemoSpaceMembershipRequired
	}
	memo, found, err := d.getMemoDoc(ctx, memoID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, store.ErrMemoMutationConflict
	}
	snapshot := &store.MemoWriteSnapshot{
		ActorIsAdmin: actor.Admin,
		CreatorID:    memo.CreatorID,
		RowStatus:    store.RowStatus(memo.RowStatus),
		SpaceID:      memo.SpaceID,
		Visibility:   store.Visibility(memo.Visibility),
	}
	if snapshot.SpaceID != nil {
		if snapshot.SourceSpaceExists, snapshot.SourceMemberActive, err = d.policySpaceState(ctx, *snapshot.SpaceID, policy.ActorUserID, actor); err != nil {
			return nil, err
		}
	}
	if update != nil && update.SpaceID != nil {
		if _, err := d.touchParent(ctx, colSpace, *update.SpaceID); err != nil {
			return nil, err
		}
		if snapshot.TargetSpaceExists, snapshot.TargetMemberActive, err = d.policySpaceState(ctx, *update.SpaceID, policy.ActorUserID, actor); err != nil {
			return nil, err
		}
	}
	if update != nil && update.Visibility != nil && *update.Visibility == store.SpaceAudience {
		if snapshot.HasActiveShare, err = exists(ctx, d.col(colMemoShare), bson.M{"memo_id": memoID, "$or": bson.A{
			bson.M{"expires_ts": nil}, bson.M{"expires_ts": bson.M{"$gt": now()}},
		}}); err != nil {
			return nil, err
		}
	}
	if err := store.ValidateMemoWriteSnapshot(policy, update, snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (d *DB) policySpaceState(ctx context.Context, spaceID, actorUserID int32, actor store.MemoActorState) (bool, bool, error) {
	exists, err := d.spaceExists(ctx, spaceID)
	if err != nil || !exists || actor.Admin {
		return exists, false, err
	}
	member, err := d.spaceMemberActive(ctx, spaceID, actorUserID)
	return true, member, err
}

// memoParticipation resolves the state shared by comment and reaction checks.
func (d *DB) memoParticipation(ctx context.Context, memoID, actorUserID int32) (*store.MemoCommentAuthorizationSnapshot, bool, error) {
	actor, err := d.memoActor(ctx, actorUserID)
	if err != nil {
		return nil, false, err
	}
	snapshot := &store.MemoCommentAuthorizationSnapshot{ActorUserID: actorUserID, Actor: actor, ContextID: memoID}
	if _, err := d.touchParent(ctx, colMemo, memoID); err != nil {
		return nil, false, err
	}
	memo, found, err := d.getMemoDoc(ctx, memoID)
	if err != nil || !found {
		return nil, found, err
	}
	snapshot.ContextCreatorID = memo.CreatorID
	snapshot.ContextRowStatus = store.RowStatus(memo.RowStatus)
	snapshot.ContextVisibility = store.Visibility(memo.Visibility)
	snapshot.ContextSpaceID = memo.SpaceID
	if memo.SpaceID != nil {
		if snapshot.ContextSpaceExists, err = d.spaceExists(ctx, *memo.SpaceID); err != nil {
			return nil, true, err
		}
		if actor.Admin {
			return snapshot, true, nil
		}
		if snapshot.ContextMemberActive, err = d.spaceMemberActive(ctx, *memo.SpaceID, actorUserID); err != nil {
			return nil, true, err
		}
	}
	return snapshot, true, nil
}
