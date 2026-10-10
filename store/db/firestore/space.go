package firestore

import (
	"context"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/usememos/memos/store"
)

var activeMemberRoles = bson.M{"$in": bson.A{string(store.SpaceMemberRoleAdmin), string(store.SpaceMemberRoleUser)}}

// userActive reports whether the user exists and is NORMAL.
func (d *DB) userActive(ctx context.Context, userID int32) (bool, error) {
	return exists(ctx, d.col(colUser), bson.M{"_id": userID, "row_status": string(store.Normal)})
}

// activeUserIDs returns the subset of ids belonging to NORMAL users.
func (d *DB) activeUserIDs(ctx context.Context, ids []int32) (map[int32]bool, error) {
	out := map[int32]bool{}
	for _, batch := range batches(ids, batchSize) {
		active, err := d.listIDs(ctx, colUser, bson.M{"_id": int32In(batch), "row_status": string(store.Normal)})
		if err != nil {
			return nil, err
		}
		for _, id := range active {
			out[id] = true
		}
	}
	return out, nil
}

func (d *DB) spaceExists(ctx context.Context, spaceID int32) (bool, error) {
	return exists(ctx, d.col(colSpace), bson.M{"_id": spaceID})
}

// spaceMemberActive reports an ACTIVE ADMIN/USER membership, regardless of the
// user's own row status (matching the SQL drivers' membership check).
func (d *DB) spaceMemberActive(ctx context.Context, spaceID, userID int32) (bool, error) {
	return exists(ctx, d.col(colSpaceMember), bson.M{
		"space_id": spaceID, "user_id": userID, "status": string(store.SpaceMemberStatusActive), "role": activeMemberRoles,
	})
}

// activeMemberRole returns the role of an active member whose user is NORMAL.
func (d *DB) activeMemberRole(ctx context.Context, spaceID, userID int32) (store.SpaceMemberRole, bool, error) {
	member := spaceMemberDoc{}
	found, err := findOne(ctx, d.col(colSpaceMember), bson.M{"space_id": spaceID, "user_id": userID, "status": string(store.SpaceMemberStatusActive)}, &member)
	if err != nil || !found {
		return "", false, err
	}
	active, err := d.userActive(ctx, userID)
	if err != nil || !active {
		return "", false, err
	}
	return store.SpaceMemberRole(member.Role), true, nil
}

// countActiveAdmins counts ACTIVE ADMIN members whose user is NORMAL,
// optionally excluding one user.
func (d *DB) countActiveAdmins(ctx context.Context, spaceID int32, exclude *int32) (int, error) {
	filter := bson.M{"space_id": spaceID, "status": string(store.SpaceMemberStatusActive), "role": string(store.SpaceMemberRoleAdmin)}
	if exclude != nil {
		filter["user_id"] = bson.M{"$ne": *exclude}
	}
	members, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, filter))
	if err != nil {
		return 0, err
	}
	ids := make([]int32, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID)
	}
	active, err := d.activeUserIDs(ctx, ids)
	if err != nil {
		return 0, err
	}
	return len(active), nil
}

// spaceSummary returns the viewer's role and the active member count.
func (d *DB) spaceSummary(ctx context.Context, spaceID, viewerID int32) (store.SpaceMemberRole, int32, bool, error) {
	role, ok, err := d.activeMemberRole(ctx, spaceID, viewerID)
	if err != nil || !ok || !role.IsActiveMember() {
		return "", 0, false, err
	}
	members, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, bson.M{
		"space_id": spaceID, "status": string(store.SpaceMemberStatusActive), "role": activeMemberRoles,
	}))
	if err != nil {
		return "", 0, false, err
	}
	ids := make([]int32, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID)
	}
	active, err := d.activeUserIDs(ctx, ids)
	if err != nil {
		return "", 0, false, err
	}
	return role, int32(len(active)), true, nil
}

func (d *DB) authorizeSpaceAdmin(ctx context.Context, spaceID, actorUserID int32) error {
	ok, err := d.spaceExists(ctx, spaceID)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrSpaceNotFound
	}
	role, found, err := d.activeMemberRole(ctx, spaceID, actorUserID)
	if err != nil {
		return err
	}
	if !found || role != store.SpaceMemberRoleAdmin {
		return store.ErrSpacePermissionDenied
	}
	return nil
}

func (d *DB) requireActiveUser(ctx context.Context, userID int32) error {
	ok, err := d.userActive(ctx, userID)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrSpaceMemberNotActive
	}
	return nil
}

// touchParents bumps the Space and user documents a membership row depends
// on, so a concurrent delete of either conflicts with this transaction.
func (d *DB) touchParents(ctx context.Context, spaceID, userID int32) error {
	ok, err := d.touchParent(ctx, colSpace, spaceID)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrSpaceNotFound
	}
	ok, err = d.touchParent(ctx, colUser, userID)
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrSpaceMemberNotActive
	}
	return nil
}

// CreateSpace creates a Space and its first admin.
func (d *DB) CreateSpace(ctx context.Context, create *store.Space, creatorID int32) (*store.Space, error) {
	payload := "{}"
	if create.Payload != nil {
		data, err := protojson.Marshal(create.Payload)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal space payload")
		}
		payload = string(data)
	}
	var space *store.Space
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.requireActiveUser(ctx, creatorID); err != nil {
			return err
		}
		id, err := d.nextID(ctx, colSpace)
		if err != nil {
			return err
		}
		doc := spaceDoc{ID: id, UID: create.UID, Title: create.Title, Description: create.Description, Payload: payload}
		if _, err := d.col(colSpace).InsertOne(ctx, doc); err != nil {
			return errors.Wrap(err, "failed to create space")
		}
		if err := d.claim(ctx, colSpace, "uid", create.UID, id); err != nil {
			if isUniqueViolation(err) {
				return store.ErrSpaceAlreadyExists
			}
			return err
		}
		if _, err := d.col(colSpaceMember).InsertOne(ctx, spaceMemberDoc{Key: spaceMemberKey(id, creatorID), SpaceID: id, UserID: creatorID, Status: string(store.SpaceMemberStatusActive), Role: string(store.SpaceMemberRoleAdmin)}); err != nil {
			return errors.Wrap(err, "failed to create initial space admin")
		}
		space, err = doc.toStore()
		if err != nil {
			return err
		}
		space.CurrentUserRole = store.SpaceMemberRoleAdmin
		space.MemberCount = 1
		return nil
	})
	if err != nil {
		return nil, err
	}
	return space, nil
}

// ListSpaces lists Spaces, newest first.
func (d *DB) ListSpaces(ctx context.Context, find *store.FindSpace) ([]*store.Space, error) {
	filter := bson.M{}
	if find.ID != nil {
		filter["_id"] = *find.ID
	}
	if len(find.IDList) > 0 {
		filter["_id"] = int32In(find.IDList)
	}
	if find.UID != nil {
		filter["uid"] = *find.UID
	}
	if find.MemberUserID != nil {
		active, err := d.userActive(ctx, *find.MemberUserID)
		if err != nil {
			return nil, err
		}
		if !active {
			return []*store.Space{}, nil
		}
		members, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, bson.M{
			"user_id": *find.MemberUserID, "status": string(store.SpaceMemberStatusActive), "role": activeMemberRoles,
		}))
		if err != nil {
			return nil, err
		}
		ids := make([]int32, 0, len(members))
		for _, m := range members {
			ids = append(ids, m.SpaceID)
		}
		if existing, ok := filter["_id"]; ok {
			filter["$and"] = bson.A{bson.M{"_id": existing}, bson.M{"_id": int32In(ids)}}
			delete(filter, "_id")
		} else {
			filter["_id"] = int32In(ids)
		}
	}
	opts := options.Find().SetSort(bson.D{{Key: "_id", Value: -1}})
	if find.MemberUserID == nil {
		opts = findOpts(find.Limit, find.Offset).SetSort(bson.D{{Key: "_id", Value: -1}})
	}
	docs, err := decodeAll[spaceDoc](ctx)(d.col(colSpace).Find(ctx, filter, opts))
	if err != nil {
		return nil, err
	}
	spaces := []*store.Space{}
	for i := range docs {
		space, err := docs[i].toStore()
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal space payload")
		}
		if find.MemberUserID != nil {
			role, count, ok, err := d.spaceSummary(ctx, space.ID, *find.MemberUserID)
			if err != nil {
				return nil, err
			}
			if !ok || count == 0 {
				continue
			}
			space.CurrentUserRole, space.MemberCount = role, count
		}
		spaces = append(spaces, space)
	}
	if find.MemberUserID != nil {
		spaces = applyLimit(spaces, find.Limit, find.Offset)
	}
	return spaces, nil
}

// UpdateSpace updates Space metadata as a Space admin.
func (d *DB) UpdateSpace(ctx context.Context, update *store.UpdateSpace, actorUserID int32) (*store.Space, error) {
	var space *store.Space
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.authorizeSpaceAdmin(ctx, update.ID, actorUserID); err != nil {
			return err
		}
		set := bson.M{}
		if update.Title != nil {
			set["title"] = *update.Title
		}
		if update.Description != nil {
			set["description"] = *update.Description
		}
		if update.Payload != nil {
			data, err := protojson.Marshal(update.Payload)
			if err != nil {
				return errors.Wrap(err, "failed to marshal space payload")
			}
			set["payload"] = string(data)
		}
		if len(set) > 0 {
			if _, err := d.col(colSpace).UpdateOne(ctx, bson.M{"_id": update.ID}, bson.M{"$set": set}); err != nil {
				return err
			}
		}
		doc := spaceDoc{}
		if _, err := findOne(ctx, d.col(colSpace), bson.M{"_id": update.ID}, &doc); err != nil {
			return err
		}
		var err error
		space, err = doc.toStore()
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal space payload")
		}
		role, count, ok, err := d.spaceSummary(ctx, space.ID, actorUserID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("failed to populate space summary: sql: no rows in result set")
		}
		space.CurrentUserRole, space.MemberCount = role, count
		return nil
	})
	if err != nil {
		return nil, err
	}
	return space, nil
}

// DeleteSpace hard-deletes a Space, its memberships, and its memos.
func (d *DB) DeleteSpace(ctx context.Context, delete *store.DeleteSpace) (*store.DeleteSpaceResult, error) {
	var result *store.DeleteSpaceResult
	err := d.withTx(ctx, func(ctx context.Context) error {
		active, err := d.userActive(ctx, delete.ActorUserID)
		if err != nil {
			return errors.Wrap(err, "failed to read space deletion actor")
		}
		if !active {
			return store.ErrSpacePermissionDenied
		}
		ok, err := d.spaceExists(ctx, delete.ID)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrSpaceNotFound
		}
		if _, err := d.touchParent(ctx, colSpace, delete.ID); err != nil {
			return err
		}
		member := spaceMemberDoc{}
		found, err := findOne(ctx, d.col(colSpaceMember), bson.M{"space_id": delete.ID, "user_id": delete.ActorUserID, "status": string(store.SpaceMemberStatusActive)}, &member)
		if err != nil {
			return errors.Wrap(err, "failed to read space administrator membership")
		}
		if !found || store.SpaceMemberRole(member.Role) != store.SpaceMemberRoleAdmin {
			return store.ErrSpacePermissionDenied
		}
		memoIDs, err := d.listIDs(ctx, colMemo, bson.M{"space_id": delete.ID})
		if err != nil {
			return errors.Wrap(err, "failed to collect assigned memos")
		}
		attachments, err := d.deleteMemoSet(ctx, memoIDs)
		if err != nil {
			return errors.Wrap(err, "failed to delete assigned memo set")
		}
		if _, err := d.col(colSpaceMember).DeleteMany(ctx, bson.M{"space_id": delete.ID}); err != nil {
			return errors.Wrap(err, "failed to delete space memberships")
		}
		res, err := d.col(colSpace).DeleteOne(ctx, bson.M{"_id": delete.ID})
		if err != nil {
			return errors.Wrap(err, "failed to delete space")
		}
		if _, err := d.col(colUniques).DeleteMany(ctx, bson.M{"col": colSpace, "ref": delete.ID}); err != nil {
			return errors.Wrap(err, "failed to release space claims")
		}
		if res.DeletedCount != 1 {
			return store.ErrSpaceNotFound
		}
		result = &store.DeleteSpaceResult{Attachments: attachments}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// deleteMemoSet deletes memos with their shares, reactions, attachments, and
// incident relations, returning the deleted attachments.
func (d *DB) deleteMemoSet(ctx context.Context, memoIDs []int32) ([]*store.Attachment, error) {
	// Touch the memos first so concurrent writers adding reactions,
	// comments, or attachments conflict with this delete.
	for _, batch := range batches(memoIDs, batchSize) {
		if _, err := d.col(colMemo).UpdateMany(ctx, bson.M{"_id": int32In(batch)}, bson.M{"$inc": bson.M{"_v": int64(1)}}); err != nil {
			return nil, errors.Wrap(err, "failed to lock memos")
		}
	}
	attachments := []*store.Attachment{}
	for _, batch := range batches(memoIDs, batchSize) {
		found, err := d.listAttachmentSnapshots(ctx, bson.M{"memo_id": int32In(batch)})
		if err != nil {
			return nil, errors.Wrap(err, "failed to collect memo attachments")
		}
		attachments = append(attachments, found...)
	}
	for _, batch := range batches(memoIDs, batchSize) {
		in := int32In(batch)
		if _, err := d.deleteRows(ctx, colMemoShare, bson.M{"memo_id": in}); err != nil {
			return nil, errors.Wrap(err, "failed to delete memo shares")
		}
		if _, err := d.deleteRows(ctx, colMemo, bson.M{"_id": in}); err != nil {
			return nil, errors.Wrap(err, "failed to delete memos")
		}
		if _, err := d.deleteRows(ctx, colReaction, bson.M{"memo_id": in}); err != nil {
			return nil, errors.Wrap(err, "failed to delete memo reactions")
		}
		if _, err := d.col(colMemoRelation).DeleteMany(ctx, bson.M{"$or": bson.A{bson.M{"memo_id": in}, bson.M{"related_memo_id": in}}}); err != nil {
			return nil, errors.Wrap(err, "failed to delete incident memo relations")
		}
	}
	if err := d.deleteByIDs(ctx, colAttachment, attachmentIDs(attachments)); err != nil {
		return nil, errors.Wrap(err, "failed to delete memo attachments")
	}
	return attachments, nil
}

// ListSpaceMembers lists active members.
func (d *DB) ListSpaceMembers(ctx context.Context, find *store.FindSpaceMember) ([]*store.SpaceMember, error) {
	filter := bson.M{"status": string(store.SpaceMemberStatusActive), "role": activeMemberRoles}
	if find.SpaceID != nil {
		filter["space_id"] = *find.SpaceID
	}
	if find.UserID != nil {
		filter["user_id"] = *find.UserID
	}
	docs, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, filter))
	if err != nil {
		return nil, err
	}
	members := []*store.SpaceMember{}
	viewerCache := map[int32]bool{}
	for _, doc := range docs {
		ok, err := d.spaceExists(ctx, doc.SpaceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		active, err := d.userActive(ctx, doc.UserID)
		if err != nil {
			return nil, err
		}
		if !active {
			continue
		}
		if find.ViewerUserID != nil {
			visible, cached := viewerCache[doc.SpaceID]
			if !cached {
				_, visible, err = d.activeMemberRole(ctx, doc.SpaceID, *find.ViewerUserID)
				if err != nil {
					return nil, err
				}
				viewerCache[doc.SpaceID] = visible
			}
			if !visible {
				continue
			}
		}
		members = append(members, &store.SpaceMember{SpaceID: doc.SpaceID, UserID: doc.UserID, Role: store.SpaceMemberRole(doc.Role)})
	}
	stableSort(members, func(a, b *store.SpaceMember) bool { return a.UserID < b.UserID })
	return applyLimit(members, find.Limit, find.Offset), nil
}

// UpdateSpaceMember changes an active member's role as a Space admin.
func (d *DB) UpdateSpaceMember(ctx context.Context, update *store.UpdateSpaceMember, actorUserID int32) (*store.SpaceMember, error) {
	var member *store.SpaceMember
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.authorizeSpaceAdmin(ctx, update.SpaceID, actorUserID); err != nil {
			return err
		}
		if err := d.requireActiveUser(ctx, update.UserID); err != nil {
			return err
		}
		key := bson.M{"space_id": update.SpaceID, "user_id": update.UserID, "status": string(store.SpaceMemberStatusActive)}
		current := spaceMemberDoc{}
		found, err := findOne(ctx, d.col(colSpaceMember), key, &current)
		if err != nil {
			return err
		}
		if !found {
			return store.ErrSpaceMemberNotFound
		}
		if store.SpaceMemberRole(current.Role) == store.SpaceMemberRoleAdmin && update.Role != nil && *update.Role != store.SpaceMemberRoleAdmin {
			count, err := d.countActiveAdmins(ctx, update.SpaceID, nil)
			if err != nil {
				return err
			}
			if count <= 1 {
				return store.ErrLastSpaceAdmin
			}
		}
		if update.Role != nil {
			if _, err := d.col(colSpaceMember).UpdateOne(ctx, key, bson.M{"$set": bson.M{"role": string(*update.Role)}}); err != nil {
				return err
			}
			current.Role = string(*update.Role)
		}
		member = &store.SpaceMember{SpaceID: current.SpaceID, UserID: current.UserID, Role: store.SpaceMemberRole(current.Role)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return member, nil
}

// DeleteSpaceMember removes a member (or lets a member leave).
func (d *DB) DeleteSpaceMember(ctx context.Context, delete *store.DeleteSpaceMember, actorUserID int32) error {
	return d.withTx(ctx, func(ctx context.Context) error {
		ok, err := d.spaceExists(ctx, delete.SpaceID)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrSpaceNotFound
		}
		if actorUserID != delete.UserID {
			role, found, err := d.activeMemberRole(ctx, delete.SpaceID, actorUserID)
			if err != nil {
				return err
			}
			if !found || role != store.SpaceMemberRoleAdmin {
				return store.ErrSpacePermissionDenied
			}
		}
		key := bson.M{"space_id": delete.SpaceID, "user_id": delete.UserID, "status": string(store.SpaceMemberStatusActive)}
		target := spaceMemberDoc{}
		found, err := findOne(ctx, d.col(colSpaceMember), key, &target)
		if err != nil {
			return err
		}
		if !found {
			return store.ErrSpaceMemberNotFound
		}
		if store.SpaceMemberRole(target.Role) == store.SpaceMemberRoleAdmin {
			targetActive, err := d.userActive(ctx, delete.UserID)
			if err != nil {
				return err
			}
			if targetActive {
				count, err := d.countActiveAdmins(ctx, delete.SpaceID, nil)
				if err != nil {
					return err
				}
				if count <= 1 {
					return store.ErrLastSpaceAdmin
				}
			}
		}
		_, err = d.col(colSpaceMember).DeleteOne(ctx, key)
		return err
	})
}

// CreateSpaceInvitation invites an existing active user.
func (d *DB) CreateSpaceInvitation(ctx context.Context, create *store.SpaceInvitation, actorUserID int32) (*store.SpaceInvitation, error) {
	var invitation *store.SpaceInvitation
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.authorizeSpaceAdmin(ctx, create.SpaceID, actorUserID); err != nil {
			return err
		}
		if err := d.requireActiveUser(ctx, create.UserID); err != nil {
			return err
		}
		if err := d.touchParents(ctx, create.SpaceID, create.UserID); err != nil {
			return err
		}
		doc := spaceMemberDoc{Key: spaceMemberKey(create.SpaceID, create.UserID), SpaceID: create.SpaceID, UserID: create.UserID, Status: string(store.SpaceMemberStatusInvited), Role: string(create.Role)}
		if _, err := d.col(colSpaceMember).InsertOne(ctx, doc); err != nil {
			if isUniqueViolation(err) {
				return store.ErrSpaceMemberAlreadyExists
			}
			return err
		}
		invitation = &store.SpaceInvitation{SpaceID: create.SpaceID, UserID: create.UserID, Role: create.Role}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return invitation, nil
}

// ListSpaceInvitations lists pending invitations.
func (d *DB) ListSpaceInvitations(ctx context.Context, find *store.FindSpaceInvitation) ([]*store.SpaceInvitation, error) {
	filter := bson.M{"status": string(store.SpaceMemberStatusInvited), "role": activeMemberRoles}
	if find.SpaceID != nil {
		filter["space_id"] = *find.SpaceID
	}
	if find.UserID != nil {
		filter["user_id"] = *find.UserID
	}
	docs, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, filter))
	if err != nil {
		return nil, err
	}
	viewerActive := false
	if find.ViewerUserID != nil {
		if viewerActive, err = d.userActive(ctx, *find.ViewerUserID); err != nil {
			return nil, err
		}
	}
	out := []*store.SpaceInvitation{}
	for _, doc := range docs {
		ok, err := d.spaceExists(ctx, doc.SpaceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		ok, err = exists(ctx, d.col(colUser), bson.M{"_id": doc.UserID})
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if find.ViewerUserID != nil {
			visible := doc.UserID == *find.ViewerUserID && viewerActive
			if !visible {
				role, found, err := d.activeMemberRole(ctx, doc.SpaceID, *find.ViewerUserID)
				if err != nil {
					return nil, err
				}
				visible = found && role == store.SpaceMemberRoleAdmin
			}
			if !visible {
				continue
			}
		}
		out = append(out, &store.SpaceInvitation{SpaceID: doc.SpaceID, UserID: doc.UserID, Role: store.SpaceMemberRole(doc.Role)})
	}
	stableSort(out, func(a, b *store.SpaceInvitation) bool {
		if a.SpaceID != b.SpaceID {
			return a.SpaceID > b.SpaceID
		}
		return a.UserID < b.UserID
	})
	return applyLimit(out, find.Limit, find.Offset), nil
}

// AcceptSpaceInvitation turns the actor's invitation into a membership.
func (d *DB) AcceptSpaceInvitation(ctx context.Context, accept *store.AcceptSpaceInvitation, actorUserID int32) (*store.SpaceMember, error) {
	if accept.UserID != actorUserID {
		return nil, store.ErrSpacePermissionDenied
	}
	var member *store.SpaceMember
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.requireActiveUser(ctx, accept.UserID); err != nil {
			return err
		}
		if err := d.touchParents(ctx, accept.SpaceID, accept.UserID); err != nil {
			if errors.Is(err, store.ErrSpaceNotFound) {
				return store.ErrSpaceInvitationNotFound
			}
			return err
		}
		doc := spaceMemberDoc{}
		err := d.col(colSpaceMember).FindOneAndUpdate(ctx,
			bson.M{"space_id": accept.SpaceID, "user_id": accept.UserID, "status": string(store.SpaceMemberStatusInvited), "role": activeMemberRoles},
			bson.M{"$set": bson.M{"status": string(store.SpaceMemberStatusActive)}},
			options.FindOneAndUpdate().SetReturnDocument(options.After),
		).Decode(&doc)
		if err != nil {
			if isNoDocuments(err) {
				return store.ErrSpaceInvitationNotFound
			}
			return err
		}
		member = &store.SpaceMember{SpaceID: doc.SpaceID, UserID: doc.UserID, Role: store.SpaceMemberRole(doc.Role)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return member, nil
}

// DeclineSpaceInvitation removes the actor's own pending invitation.
func (d *DB) DeclineSpaceInvitation(ctx context.Context, decline *store.DeclineSpaceInvitation, actorUserID int32) error {
	if decline.UserID != actorUserID {
		return store.ErrSpacePermissionDenied
	}
	return d.withTx(ctx, func(ctx context.Context) error {
		if err := d.requireActiveUser(ctx, decline.UserID); err != nil {
			return err
		}
		return d.deleteInvitation(ctx, decline.SpaceID, decline.UserID)
	})
}

// RevokeSpaceInvitation removes a pending invitation as a Space admin.
func (d *DB) RevokeSpaceInvitation(ctx context.Context, revoke *store.RevokeSpaceInvitation, actorUserID int32) error {
	return d.withTx(ctx, func(ctx context.Context) error {
		if err := d.authorizeSpaceAdmin(ctx, revoke.SpaceID, actorUserID); err != nil {
			return err
		}
		return d.deleteInvitation(ctx, revoke.SpaceID, revoke.UserID)
	})
}

func (d *DB) deleteInvitation(ctx context.Context, spaceID, userID int32) error {
	res, err := d.col(colSpaceMember).DeleteOne(ctx, bson.M{"space_id": spaceID, "user_id": userID, "status": string(store.SpaceMemberStatusInvited)})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return store.ErrSpaceInvitationNotFound
	}
	return nil
}
