package firestore

import (
	"context"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/store"
)

var userUniqueIndexes = map[string]string{"username": "username", "email": "email"}

func (d *DB) insertUser(ctx context.Context, create *store.User) error {
	id, err := d.nextID(ctx, colUser)
	if err != nil {
		return err
	}
	ts := now()
	doc := userDoc{
		ID:           id,
		CreatedTs:    ts,
		UpdatedTs:    ts,
		RowStatus:    string(store.Normal),
		Username:     create.Username,
		Role:         string(create.Role),
		Nickname:     create.Nickname,
		PasswordHash: create.PasswordHash,
		AvatarURL:    create.AvatarURL,
	}
	if doc.Role == "" {
		doc.Role = string(store.RoleUser)
	}
	if create.Email != "" {
		email := create.Email
		doc.Email = &email
	}
	if _, err := d.col(colUser).InsertOne(ctx, doc); err != nil {
		return uniqueErr(err, "user", userUniqueIndexes)
	}
	create.ID = id
	create.CreatedTs = ts
	create.UpdatedTs = ts
	create.RowStatus = store.Normal
	create.Description = ""
	return nil
}

// CreateUser inserts a user.
func (d *DB) CreateUser(ctx context.Context, create *store.User) (*store.User, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		return d.insertUser(ctx, create)
	})
	if err != nil {
		return nil, err
	}
	return create, nil
}

// UpdateUser updates the given fields and returns the stored user.
func (d *DB) UpdateUser(ctx context.Context, update *store.UpdateUser) (*store.User, error) {
	var result *store.User
	err := d.withTx(ctx, func(ctx context.Context) error {
		if update.RowStatus != nil && *update.RowStatus == store.Archived {
			if err := d.validateUserArchive(ctx, update.ID); err != nil {
				return err
			}
		}
		set, unset := bson.M{}, bson.M{}
		if v := update.UpdatedTs; v != nil {
			set["updated_ts"] = *v
		}
		if v := update.RowStatus; v != nil {
			set["row_status"] = string(*v)
		}
		if v := update.Username; v != nil {
			set["username"] = *v
		}
		if v := update.Email; v != nil {
			if *v == "" {
				unset["email"] = ""
			} else {
				set["email"] = *v
			}
		}
		if v := update.Nickname; v != nil {
			set["nickname"] = *v
		}
		if v := update.AvatarURL; v != nil {
			set["avatar_url"] = *v
		}
		if v := update.PasswordHash; v != nil {
			set["password_hash"] = *v
		}
		if v := update.Description; v != nil {
			set["description"] = *v
		}
		if v := update.Role; v != nil {
			set["role"] = string(*v)
		}
		ops := bson.M{}
		if len(set) > 0 {
			ops["$set"] = set
		}
		if len(unset) > 0 {
			ops["$unset"] = unset
		}
		if len(ops) > 0 {
			res, err := d.col(colUser).UpdateOne(ctx, bson.M{"_id": update.ID}, ops)
			if err != nil {
				return uniqueErr(err, "user", userUniqueIndexes)
			}
			if res.MatchedCount == 0 {
				return errors.New("sql: no rows in result set")
			}
		}
		doc := userDoc{}
		found, err := findOne(ctx, d.col(colUser), bson.M{"_id": update.ID}, &doc)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("sql: no rows in result set")
		}
		result = doc.toStore()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// validateUserArchive rejects archiving the last active admin of any Space.
func (d *DB) validateUserArchive(ctx context.Context, userID int32) error {
	user := userDoc{}
	found, err := findOne(ctx, d.col(colUser), bson.M{"_id": userID}, &user)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("sql: no rows in result set")
	}
	if store.RowStatus(user.RowStatus) != store.Normal {
		return nil
	}
	adminRows, err := decodeAll[spaceMemberDoc](ctx)(d.col(colSpaceMember).Find(ctx, bson.M{
		"user_id": userID, "status": string(store.SpaceMemberStatusActive), "role": string(store.SpaceMemberRoleAdmin),
	}))
	if err != nil {
		return err
	}
	for _, row := range adminRows {
		count, err := d.countActiveAdmins(ctx, row.SpaceID, &userID)
		if err != nil {
			return err
		}
		if count == 0 {
			return store.ErrLastSpaceAdmin
		}
	}
	return nil
}

// ListUsers lists users matching find.
func (d *DB) ListUsers(ctx context.Context, find *store.FindUser) ([]*store.User, error) {
	if len(find.Filters) > 0 {
		return nil, errors.Errorf("user filters are not supported")
	}
	filter := bson.M{}
	if v := find.ID; v != nil {
		filter["_id"] = *v
	}
	if len(find.IDList) > 0 {
		filter["_id"] = int32In(find.IDList)
	}
	if len(find.UsernameList) > 0 {
		filter["username"] = bson.M{"$in": find.UsernameList}
	}
	if v := find.RowStatus; v != nil {
		filter["row_status"] = string(*v)
	}
	if v := find.Username; v != nil {
		filter["username"] = *v
	}
	if v := find.Role; v != nil {
		filter["role"] = string(*v)
	}
	if v := find.Email; v != nil {
		filter["email"] = *v
	}
	if v := find.Nickname; v != nil {
		filter["nickname"] = *v
	}
	search := ""
	if v := find.Search; v != nil {
		search = strings.ToLower(strings.TrimSpace(*v))
	}
	if search != "" {
		pattern := regexp.QuoteMeta(search)
		filter["$or"] = bson.A{
			bson.M{"username": bson.M{"$regex": pattern, "$options": "i"}},
			bson.M{"nickname": bson.M{"$regex": pattern, "$options": "i"}},
		}
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_ts", Value: -1}, {Key: "row_status", Value: -1}, {Key: "_id", Value: -1}})
	if search == "" {
		opts = findOpts(find.Limit, find.Offset).SetSort(bson.D{{Key: "created_ts", Value: -1}, {Key: "row_status", Value: -1}, {Key: "_id", Value: -1}})
	}
	docs, err := decodeAll[userDoc](ctx)(d.col(colUser).Find(ctx, filter, opts))
	if err != nil {
		return nil, err
	}
	users := make([]*store.User, 0, len(docs))
	for i := range docs {
		users = append(users, docs[i].toStore())
	}
	if search != "" {
		users = rankUserSearch(users, search)
		users = applyLimit(users, find.Limit, find.Offset)
	}
	return users, nil
}

// rankUserSearch orders search hits the way the SQL drivers do: exact
// username, username prefix, nickname prefix, then the rest; shorter
// usernames first within a rank.
func rankUserSearch(users []*store.User, query string) []*store.User {
	rank := func(u *store.User) int {
		username, nickname := strings.ToLower(u.Username), strings.ToLower(u.Nickname)
		switch {
		case username == query:
			return 0
		case strings.HasPrefix(username, query):
			return 1
		case strings.HasPrefix(nickname, query):
			return 2
		default:
			return 3
		}
	}
	sorted := append([]*store.User(nil), users...)
	stableSort(sorted, func(a, b *store.User) bool {
		ra, rb := rank(a), rank(b)
		if ra != rb {
			return ra < rb
		}
		if len(a.Username) != len(b.Username) {
			return len(a.Username) < len(b.Username)
		}
		if a.CreatedTs != b.CreatedTs {
			return a.CreatedTs > b.CreatedTs
		}
		return a.RowStatus > b.RowStatus
	})
	return sorted
}

// DeleteUser deletes the user and everything it owns.
func (d *DB) DeleteUser(ctx context.Context, delete *store.DeleteUser) (*store.DeleteUserResult, error) {
	var result *store.DeleteUserResult
	err := d.withTx(ctx, func(ctx context.Context) error {
		result = &store.DeleteUserResult{}
		found, err := exists(ctx, d.col(colUser), bson.M{"_id": delete.ID})
		if err != nil {
			return errors.Wrap(err, "failed to read user")
		}
		if !found {
			return nil
		}
		if _, err := d.touchParent(ctx, colUser, delete.ID); err != nil {
			return err
		}
		memberships, err := d.col(colSpaceMember).CountDocuments(ctx, bson.M{"user_id": delete.ID, "status": bson.M{"$ne": string(store.SpaceMemberStatusInvited)}})
		if err != nil {
			return errors.Wrap(err, "failed to check user space memberships")
		}
		if memberships != 0 {
			return store.ErrUserHasSpaceMembership
		}
		if _, err := d.col(colSpaceMember).DeleteMany(ctx, bson.M{"user_id": delete.ID, "status": string(store.SpaceMemberStatusInvited)}); err != nil {
			return errors.Wrap(err, "failed to delete user space invitations")
		}

		memoIDs, err := d.listIDs(ctx, colMemo, bson.M{"creator_id": delete.ID})
		if err != nil {
			return err
		}
		attachments, err := d.listAttachmentSnapshots(ctx, bson.M{"creator_id": delete.ID})
		if err != nil {
			return err
		}
		seen := map[int32]struct{}{}
		for _, a := range attachments {
			seen[a.ID] = struct{}{}
		}
		for _, batch := range batches(memoIDs, batchSize) {
			more, err := d.listAttachmentSnapshots(ctx, bson.M{"memo_id": int32In(batch)})
			if err != nil {
				return err
			}
			for _, a := range more {
				if _, ok := seen[a.ID]; !ok {
					seen[a.ID] = struct{}{}
					attachments = append(attachments, a)
				}
			}
		}
		settings, err := decodeAll[userSettingDoc](ctx)(d.col(colUserSetting).Find(ctx, bson.M{"user_id": delete.ID}))
		if err != nil {
			return err
		}
		keys := make([]storepb.UserSetting_Key, 0, len(settings))
		for _, s := range settings {
			keys = append(keys, storepb.UserSetting_Key(storepb.UserSetting_Key_value[s.Key]))
		}

		if err := d.deleteByIDs(ctx, colMemo, memoIDs); err != nil {
			return err
		}
		for _, batch := range batches(memoIDs, batchSize) {
			if _, err := d.col(colReaction).DeleteMany(ctx, bson.M{"memo_id": int32In(batch)}); err != nil {
				return err
			}
			if _, err := d.col(colMemoShare).DeleteMany(ctx, bson.M{"memo_id": int32In(batch)}); err != nil {
				return err
			}
			if _, err := d.col(colMemoRelation).DeleteMany(ctx, bson.M{"$or": bson.A{bson.M{"memo_id": int32In(batch)}, bson.M{"related_memo_id": int32In(batch)}}}); err != nil {
				return err
			}
		}
		if err := d.deleteByIDs(ctx, colAttachment, attachmentIDs(attachments)); err != nil {
			return err
		}
		for _, step := range []struct {
			col    string
			filter bson.M
		}{
			{colReaction, bson.M{"creator_id": delete.ID}},
			{colMemoShare, bson.M{"creator_id": delete.ID}},
			{colInbox, bson.M{"$or": bson.A{bson.M{"sender_id": delete.ID}, bson.M{"receiver_id": delete.ID}}}},
			{colUserIdentity, bson.M{"user_id": delete.ID}},
			{colUserSetting, bson.M{"user_id": delete.ID}},
			{colUser, bson.M{"_id": delete.ID}},
		} {
			if _, err := d.col(step.col).DeleteMany(ctx, step.filter); err != nil {
				return err
			}
		}
		if store.GetDeleteUserFailpoint(ctx) == store.DeleteUserFailpointBeforeCommit {
			return errors.New("delete user failpoint before commit")
		}
		result = &store.DeleteUserResult{Attachments: attachments, UserSettingKeys: keys}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpsertUserSetting creates or replaces one setting.
func (d *DB) UpsertUserSetting(ctx context.Context, upsert *store.UserSetting) (*store.UserSetting, error) {
	set := bson.M{"user_id": upsert.UserID, "key": upsert.Key.String(), "value": upsert.Value}
	update := bson.M{"$set": set}
	hashes := patTokenHashes(upsert.Key, upsert.Value)
	if hashes != nil {
		set["token_hashes"] = hashes
	} else {
		update["$unset"] = bson.M{"token_hashes": ""}
	}
	_, err := d.col(colUserSetting).UpdateOne(ctx,
		bson.M{"user_id": upsert.UserID, "key": upsert.Key.String()},
		update,
		options.UpdateOne().SetUpsert(true),
	)
	if err != nil {
		return nil, err
	}
	return upsert, nil
}

func patTokenHashes(key storepb.UserSetting_Key, value string) []string {
	if key != storepb.UserSetting_PERSONAL_ACCESS_TOKENS {
		return nil
	}
	setting := &storepb.PersonalAccessTokensUserSetting{}
	if err := protojsonUnmarshaler.Unmarshal([]byte(value), setting); err != nil {
		return []string{}
	}
	hashes := make([]string, 0, len(setting.Tokens))
	for _, token := range setting.Tokens {
		hashes = append(hashes, token.TokenHash)
	}
	return hashes
}

// ListUserSettings lists settings matching find.
func (d *DB) ListUserSettings(ctx context.Context, find *store.FindUserSetting) ([]*store.UserSetting, error) {
	filter := bson.M{}
	if v := find.Key; v != storepb.UserSetting_KEY_UNSPECIFIED {
		filter["key"] = v.String()
	}
	if v := find.UserID; v != nil {
		filter["user_id"] = *v
	}
	docs, err := decodeAll[userSettingDoc](ctx)(d.col(colUserSetting).Find(ctx, filter))
	if err != nil {
		return nil, err
	}
	out := make([]*store.UserSetting, 0, len(docs))
	for _, doc := range docs {
		out = append(out, &store.UserSetting{UserID: doc.UserID, Key: storepb.UserSetting_Key(storepb.UserSetting_Key_value[doc.Key]), Value: doc.Value})
	}
	return out, nil
}

// DeleteUserSettings deletes settings matching delete.
func (d *DB) DeleteUserSettings(ctx context.Context, delete *store.DeleteUserSetting) error {
	filter := bson.M{}
	if v := delete.Key; v != storepb.UserSetting_KEY_UNSPECIFIED {
		filter["key"] = v.String()
	}
	if v := delete.UserID; v != nil {
		filter["user_id"] = *v
	}
	_, err := d.col(colUserSetting).DeleteMany(ctx, filter)
	return err
}

// GetUserByPATHash finds the user owning a personal access token.
func (d *DB) GetUserByPATHash(ctx context.Context, tokenHash string) (*store.PATQueryResult, error) {
	doc := userSettingDoc{}
	found, err := findOne(ctx, d.col(colUserSetting), bson.M{"key": storepb.UserSetting_PERSONAL_ACCESS_TOKENS.String(), "token_hashes": tokenHash}, &doc)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("sql: no rows in result set")
	}
	setting := &storepb.PersonalAccessTokensUserSetting{}
	if err := protojsonUnmarshaler.Unmarshal([]byte(doc.Value), setting); err != nil {
		return nil, err
	}
	for _, pat := range setting.Tokens {
		if pat.TokenHash == tokenHash {
			return &store.PATQueryResult{UserID: doc.UserID, PAT: pat}, nil
		}
	}
	return nil, errors.New("PAT not found")
}

var userIdentityUniqueIndexes = map[string]string{"provider_extern": "provider", "user_provider": "user_id"}

func (d *DB) insertUserIdentity(ctx context.Context, create *store.UserIdentity) error {
	id, err := d.nextID(ctx, colUserIdentity)
	if err != nil {
		return err
	}
	ts := now()
	doc := userIdentityDoc{ID: id, UserID: create.UserID, Provider: create.Provider, ExternUID: create.ExternUID, CreatedTs: ts, UpdatedTs: ts}
	if _, err := d.col(colUserIdentity).InsertOne(ctx, doc); err != nil {
		return uniqueErr(err, "user_identity", userIdentityUniqueIndexes)
	}
	create.ID, create.CreatedTs, create.UpdatedTs = id, ts, ts
	return nil
}

// CreateUserIdentity links an external identity to a user.
func (d *DB) CreateUserIdentity(ctx context.Context, create *store.UserIdentity) (*store.UserIdentity, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		return d.insertUserIdentity(ctx, create)
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create user identity")
	}
	return create, nil
}

// CreateUserWithIdentity creates a user and its identity atomically.
func (d *DB) CreateUserWithIdentity(ctx context.Context, createUser *store.User, createIdentity *store.UserIdentity) (*store.User, error) {
	err := d.withTx(ctx, func(ctx context.Context) error {
		if err := d.insertUser(ctx, createUser); err != nil {
			return errors.Wrap(err, "failed to create user")
		}
		createIdentity.UserID = createUser.ID
		if err := d.insertUserIdentity(ctx, createIdentity); err != nil {
			return errors.Wrap(err, "failed to create user identity")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return createUser, nil
}

// ListUserIdentities lists identities matching find.
func (d *DB) ListUserIdentities(ctx context.Context, find *store.FindUserIdentity) ([]*store.UserIdentity, error) {
	filter := bson.M{}
	if find.ID != nil {
		filter["_id"] = *find.ID
	}
	if find.UserID != nil {
		filter["user_id"] = *find.UserID
	}
	if find.Provider != nil {
		filter["provider"] = *find.Provider
	}
	if find.ExternUID != nil {
		filter["extern_uid"] = *find.ExternUID
	}
	docs, err := decodeAll[userIdentityDoc](ctx)(d.col(colUserIdentity).Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})))
	if err != nil {
		return nil, err
	}
	out := make([]*store.UserIdentity, 0, len(docs))
	for i := range docs {
		out = append(out, docs[i].toStore())
	}
	return out, nil
}

// DeleteUserIdentities deletes identities matching delete.
func (d *DB) DeleteUserIdentities(ctx context.Context, delete *store.DeleteUserIdentity) error {
	filter := bson.M{}
	if delete.ID != nil {
		filter["_id"] = *delete.ID
	}
	if delete.UserID != nil {
		filter["user_id"] = *delete.UserID
	}
	if delete.Provider != nil {
		filter["provider"] = *delete.Provider
	}
	_, err := d.col(colUserIdentity).DeleteMany(ctx, filter)
	return err
}
