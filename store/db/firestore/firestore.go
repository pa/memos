// Package firestore implements the store driver on Firestore with MongoDB
// compatibility (and any MongoDB 7+ server) through the official Go driver.
//
// Tables map to collections of the same name. Every document keeps its
// integer id in `_id` so the rest of the store, which passes int32 ids, needs
// no change. Ids come from a `counters` collection incremented inside the
// same transaction as the insert. Unique columns are enforced by unique
// indexes; their violations are reported with the same "UNIQUE constraint
// failed: <table>.<column>" text SQLite uses, so the store and API layers
// classify them without a driver-specific branch.
//
// All multi-document writes run in a transaction. Firestore uses optimistic
// concurrency, so a conflicting transaction aborts with a transient error and
// is retried by withTx.
package firestore

import (
	"context"
	"database/sql"
	stderrors "errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/usememos/memos/internal/profile"
	"github.com/usememos/memos/store"
)

// Collection names. They match the SQL table names.
const (
	colSystemSetting = "system_setting"
	colUser          = "user"
	colUserSetting   = "user_setting"
	colSpace         = "space"
	colSpaceMember   = "space_member"
	colMemo          = "memo"
	colMemoRelation  = "memo_relation"
	colAttachment    = "attachment"
	colIDP           = "idp"
	colInbox         = "inbox"
	colReaction      = "reaction"
	colMemoShare     = "memo_share"
	colUserIdentity  = "user_identity"
	colCounters      = "counters"
)

var protojsonUnmarshaler = protojson.UnmarshalOptions{DiscardUnknown: true}

// DB is the Firestore store driver.
type DB struct {
	client  *mongo.Client
	db      *mongo.Database
	profile *profile.Profile

	indexWarning sync.Once
}

func logIndexWarning(err error) {
	slog.Warn("firestore: could not create query index; queries still work but may be slower", slog.String("error", err.Error()))
}

// NewDB connects to the database named by profile.DSN, a MongoDB connection
// string whose path names the database.
func NewDB(profile *profile.Profile) (store.Driver, error) {
	if profile.DSN == "" {
		return nil, errors.New("dsn required")
	}
	dbName, err := databaseNameFromDSN(profile.DSN)
	if err != nil {
		return nil, err
	}
	opts := options.Client().ApplyURI(profile.DSN).
		SetRetryWrites(false).
		SetMaxConnIdleTime(15 * time.Second).
		SetReadConcern(readconcern.Majority()).
		SetWriteConcern(writeconcern.Majority())
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to firestore")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, errors.Wrap(err, "failed to ping firestore")
	}
	slog.Info("firestore: connected", slog.String("database", dbName), slog.Duration("ping", time.Since(started)))
	d := &DB{client: client, db: client.Database(dbName), profile: profile}
	// Indexes only speed queries up. Creating them can take long on
	// Firestore, so do it in the background and never delay startup.
	go func() {
		indexCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		d.ensureIndexes(indexCtx)
	}()
	return d, nil
}

// databaseNameFromDSN returns the database named in the URI path. Firestore
// accepts only its own database id there.
func databaseNameFromDSN(dsn string) (string, error) {
	rest := dsn
	if _, after, ok := strings.Cut(rest, "://"); ok {
		rest = after
	}
	_, path, ok := strings.Cut(rest, "/")
	if !ok {
		return "", errors.New("dsn must name the database in its path, for example mongodb://host/memos")
	}
	name, _, _ := strings.Cut(path, "?")
	if name == "" {
		return "", errors.New("dsn must name the database in its path, for example mongodb://host/memos")
	}
	return name, nil
}

// GetDB is unused by this driver. The migrator detects a nil handle and
// initializes the schema through the driver's own index setup.
func (*DB) GetDB() *sql.DB {
	return nil
}

// Close disconnects the client.
func (d *DB) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.client.Disconnect(ctx)
}

// IsInitialized reports whether the database already holds memos data. Like
// the SQL drivers, which look for the memo table, it does not depend on the
// schema marker, so a database that lost its marker is rejected instead of
// silently re-initialized.
func (d *DB) IsInitialized(ctx context.Context) (bool, error) {
	for _, name := range []string{colSystemSetting, colUser, colMemo} {
		n, err := d.db.Collection(name).EstimatedDocumentCount(ctx)
		if err != nil {
			return false, errors.Wrap(err, "failed to check if database is initialized")
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// CountDocuments counts raw documents in a collection. It exists for store
// tests that verify persisted state below the store API.
func (d *DB) CountDocuments(ctx context.Context, collection string, filter map[string]any) (int64, error) {
	return d.db.Collection(collection).CountDocuments(ctx, bson.M(filter))
}

// RawDocument returns one raw document as a map, for store tests.
func (d *DB) RawDocument(ctx context.Context, collection string, filter map[string]any) (map[string]any, error) {
	out := bson.M{}
	if err := d.db.Collection(collection).FindOne(ctx, bson.M(filter)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// InsertRawDocument inserts a raw document, for store tests that inject
// states the store API cannot produce.
func (d *DB) InsertRawDocument(ctx context.Context, collection string, doc map[string]any) error {
	_, err := d.db.Collection(collection).InsertOne(ctx, bson.M(doc))
	return err
}

// DropIndexes removes every secondary index, for store tests that prove
// correctness does not depend on indexes.
func (d *DB) DropIndexes(ctx context.Context) error {
	names, err := d.db.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := d.db.Collection(name).Indexes().DropAll(ctx); err != nil {
			return err
		}
	}
	return nil
}

// GetDatabaseSize is not reported by Firestore.
func (*DB) GetDatabaseSize(context.Context) (int64, error) {
	return -1, nil
}

// InitializeSchema prepares a fresh database. Collections are created on first
// write and query indexes in the background by NewDB, so there is nothing to
// do. The migrator calls it instead of executing LATEST.sql.
func (*DB) InitializeSchema(context.Context) error {
	return nil
}

func isIndexAlreadyExists(err error) bool {
	if cmdErr, ok := stderrors.AsType[mongo.CommandError](err); ok {
		// IndexOptionsConflict, IndexKeySpecsConflict, IndexAlreadyExists.
		return cmdErr.Code == 85 || cmdErr.Code == 86 || cmdErr.Code == 68
	}
	return false
}

// col returns a collection handle.
func (d *DB) col(name string) *mongo.Collection {
	return d.db.Collection(name)
}

// touchParent writes a version bump to a parent document inside the caller's
// transaction and reports whether the parent exists. Snapshot isolation only
// detects conflicts between overlapping writes, so a transaction that adds a
// child row (an invitation, a memo in a Space, a reaction) touches the parent
// it validated. A concurrent delete of that parent then conflicts, and one
// transaction retries and sees the other's result, the role row locks play in
// the SQL drivers.
func (d *DB) touchParent(ctx context.Context, collection string, id int32) (bool, error) {
	res, err := d.col(collection).UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$inc": bson.M{"_v": int64(1)}})
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

// withTx runs fn in a transaction, retrying transient conflicts. Firestore
// and MongoDB abort conflicting transactions instead of blocking.
func (d *DB) withTx(ctx context.Context, fn func(ctx context.Context) error) error {
	session, err := d.client.StartSession()
	if err != nil {
		return errors.Wrap(err, "failed to start session")
	}
	defer session.EndSession(context.WithoutCancel(ctx))
	txOpts := options.Transaction().
		SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority())
	_, err = session.WithTransaction(ctx, func(sc context.Context) (any, error) {
		return nil, fn(sc)
	}, txOpts)
	return err
}

// nextID allocates the next integer id for a collection inside the caller's
// transaction.
func (d *DB) nextID(ctx context.Context, collection string) (int32, error) {
	var out struct {
		Seq int64 `bson:"seq"`
	}
	err := d.col(colCounters).FindOneAndUpdate(ctx,
		bson.M{"_id": collection},
		bson.M{"$inc": bson.M{"seq": 1}},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	).Decode(&out)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to allocate id for %s", collection)
	}
	return int32(out.Seq), nil
}

func isUniqueViolation(err error) bool {
	return err != nil && (mongo.IsDuplicateKeyError(err) || strings.Contains(err.Error(), "UNIQUE constraint failed"))
}

func now() int64 {
	return time.Now().Unix()
}

// findOne decodes a single document into out, reporting found=false when
// there is none.
func findOne(ctx context.Context, c *mongo.Collection, filter any, out any, opts ...options.Lister[options.FindOneOptions]) (bool, error) {
	err := c.FindOne(ctx, filter, opts...).Decode(out)
	if stderrors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func exists(ctx context.Context, c *mongo.Collection, filter any) (bool, error) {
	n, err := c.CountDocuments(ctx, filter, options.Count().SetLimit(1))
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func findOpts(limit, offset *int) *options.FindOptionsBuilder {
	opts := options.Find()
	if limit != nil {
		opts.SetLimit(int64(*limit))
		if offset != nil {
			opts.SetSkip(int64(*offset))
		}
	}
	return opts
}

// decodeAll drains a cursor. Callers pass a Find or Aggregate call directly:
// decodeAll[T](ctx)(coll.Find(...)).
func decodeAll[T any](ctx context.Context) func(*mongo.Cursor, error) ([]T, error) {
	return func(cur *mongo.Cursor, err error) ([]T, error) {
		if err != nil {
			return nil, err
		}
		defer cur.Close(ctx)
		out := []T{}
		if err := cur.All(ctx, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func int32In(ids []int32) bson.M {
	return bson.M{"$in": ids}
}

// batches splits values into chunks so `$in` lists stay bounded.
func batches[T any](values []T, size int) [][]T {
	if len(values) == 0 {
		return nil
	}
	out := make([][]T, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		out = append(out, values[start:min(start+size, len(values))])
	}
	return out
}

const batchSize = 500
