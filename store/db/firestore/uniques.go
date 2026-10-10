package firestore

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Uniqueness without unique indexes.
//
// Creating indexes needs datastore.indexes.create, which an app's runtime
// identity may not hold. So uniqueness never depends on an index:
//
//   - Rows identified by a composite key (space_member, memo_relation,
//     user_setting) use that key as their _id.
//   - Unique columns of rows with an integer id (usernames, uids, ...) are
//     claimed in the `uniques` collection, whose _id is the claimed value,
//     inside the same transaction as the row write.
//
// _id is unique on every collection, so a duplicate fails the transaction.
// Claims are released whenever their row is deleted or the value changes.

const colUniques = "uniques"

type claimDoc struct {
	Key   string `bson:"_id"`
	Col   string `bson:"col"`
	Field string `bson:"field"`
	Ref   int32  `bson:"ref"`
}

// claimedCollections lists, per collection, the unique fields and how to
// read them from a raw document.
var claimedCollections = map[string][]string{
	colUser:         {"username", "email"},
	colSpace:        {"uid"},
	colMemo:         {"uid"},
	colAttachment:   {"uid"},
	colIDP:          {"uid"},
	colMemoShare:    {"uid"},
	colReaction:     {"creator_memo_type"},
	colUserIdentity: {"provider_extern", "user_provider"},
}

func claimKey(col, field, value string) string {
	return col + "." + field + ":" + value
}

// claim reserves value for (col, field) on behalf of row ref.
func (d *DB) claim(ctx context.Context, col, field, value string, ref int32) error {
	if value == "" {
		return nil
	}
	_, err := d.col(colUniques).InsertOne(ctx, claimDoc{Key: claimKey(col, field, value), Col: col, Field: field, Ref: ref})
	if mongo.IsDuplicateKeyError(err) {
		return errors.Errorf("UNIQUE constraint failed: %s.%s", col, field)
	}
	return err
}

// reclaim moves row ref's claim on (col, field) to a new value.
func (d *DB) reclaim(ctx context.Context, col, field, value string, ref int32) error {
	if _, err := d.col(colUniques).DeleteMany(ctx, bson.M{"col": col, "field": field, "ref": ref}); err != nil {
		return err
	}
	return d.claim(ctx, col, field, value, ref)
}

// deleteRows deletes the rows matching filter and releases their claims.
// Every delete of a claimed collection goes through here.
func (d *DB) deleteRows(ctx context.Context, col string, filter any) (int64, error) {
	if _, claimed := claimedCollections[col]; !claimed {
		res, err := d.col(col).DeleteMany(ctx, filter)
		if err != nil {
			return 0, err
		}
		return res.DeletedCount, nil
	}
	ids, err := d.listIDs(ctx, col, filter)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	var deleted int64
	for _, batch := range batches(ids, batchSize) {
		res, err := d.col(col).DeleteMany(ctx, bson.M{"_id": int32In(batch)})
		if err != nil {
			return 0, err
		}
		deleted += res.DeletedCount
		if _, err := d.col(colUniques).DeleteMany(ctx, bson.M{"col": col, "ref": int32In(batch)}); err != nil {
			return 0, errors.Wrap(err, "failed to release unique claims")
		}
	}
	return deleted, nil
}

// Composite keys used as _id.

func spaceMemberKey(spaceID, userID int32) string {
	return fmt.Sprintf("%d:%d", spaceID, userID)
}

func memoRelationKey(memoID, relatedMemoID int32, relationType string) string {
	return fmt.Sprintf("%d:%d:%s", memoID, relatedMemoID, relationType)
}

func userSettingKey(userID int32, key string) string {
	return fmt.Sprintf("%d:%s", userID, key)
}

func reactionClaim(creatorID, memoID int32, reactionType string) string {
	return fmt.Sprintf("%d:%d:%s", creatorID, memoID, reactionType)
}

func identityClaims(userID int32, provider, externUID string) (string, string) {
	return provider + "\x00" + externUID, fmt.Sprintf("%d\x00%s", userID, provider)
}

// ensureIndexes creates query indexes. They only speed queries up, and the
// runtime identity may lack permission to create them, so failures are
// logged and ignored.
func (d *DB) ensureIndexes(ctx context.Context) {
	specs := []struct {
		col  string
		keys bson.D
		name string
	}{
		{colUser, bson.D{{Key: "created_ts", Value: -1}, {Key: "_id", Value: -1}}, "created"},
		{colUserSetting, bson.D{{Key: "key", Value: 1}, {Key: "token_hashes", Value: 1}}, "token_hashes"},
		{colSpaceMember, bson.D{{Key: "user_id", Value: 1}, {Key: "space_id", Value: 1}}, "user_space"},
		{colSpaceMember, bson.D{{Key: "space_id", Value: 1}, {Key: "status", Value: 1}}, "space_status"},
		{colMemo, bson.D{{Key: "creator_id", Value: 1}, {Key: "created_ts", Value: -1}}, "creator"},
		{colMemo, bson.D{{Key: "space_id", Value: 1}, {Key: "row_status", Value: 1}, {Key: "created_ts", Value: -1}, {Key: "_id", Value: -1}}, "space"},
		{colMemo, bson.D{{Key: "created_ts", Value: -1}, {Key: "_id", Value: -1}}, "created"},
		{colMemoRelation, bson.D{{Key: "related_memo_id", Value: 1}, {Key: "type", Value: 1}, {Key: "memo_id", Value: 1}}, "related_type"},
		{colMemoRelation, bson.D{{Key: "memo_id", Value: 1}, {Key: "type", Value: 1}}, "memo_type"},
		{colAttachment, bson.D{{Key: "memo_id", Value: 1}}, "memo"},
		{colAttachment, bson.D{{Key: "creator_id", Value: 1}}, "creator"},
		{colInbox, bson.D{{Key: "receiver_id", Value: 1}, {Key: "created_ts", Value: -1}}, "receiver"},
		{colReaction, bson.D{{Key: "memo_id", Value: 1}}, "memo"},
		{colMemoShare, bson.D{{Key: "memo_id", Value: 1}}, "memo"},
		{colUserIdentity, bson.D{{Key: "user_id", Value: 1}}, "user"},
		{colUniques, bson.D{{Key: "col", Value: 1}, {Key: "ref", Value: 1}}, "col_ref"},
	}
	for _, spec := range specs {
		if ctx.Err() != nil {
			return
		}
		_, err := d.col(spec.col).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: spec.keys, Options: options.Index().SetName(spec.name)})
		if err == nil || isIndexAlreadyExists(err) {
			continue
		}
		d.indexWarning.Do(func() {
			logIndexWarning(err)
		})
		if strings.Contains(err.Error(), "PermissionDenied") || strings.Contains(err.Error(), "permission") {
			return
		}
	}
}
