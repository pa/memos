package test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/usememos/memos/store"
)

var (
	mongoContainer atomic.Pointer[testcontainers.Container]
	mongoOnce      sync.Once
	mongoBaseURI   atomic.Value // stores string
)

// GetFirestoreDSN returns a DSN for a fresh database on a MongoDB 7
// single-node replica set, which supports the multi-document transactions
// the Firestore driver needs. Set FIRESTORE_TEST_URI (a URI without a
// database path, e.g. mongodb://host:27017/?replicaSet=rs0) to run against an
// existing server instead, such as a real Firestore database.
func GetFirestoreDSN(t *testing.T) string {
	base := os.Getenv("FIRESTORE_TEST_URI")
	if base == "" {
		skipIfContainerProviderUnavailable(t)
		mongoOnce.Do(func() {
			ctx := context.Background()
			req := testcontainers.ContainerRequest{
				Image:        "mongo:7.0",
				Cmd:          []string{"--replSet", "rs0", "--bind_ip_all", "--port", "27017"},
				ExposedPorts: []string{"27017/tcp"},
				WaitingFor:   wait.ForLog("Waiting for connections").WithStartupTimeout(120 * time.Second),
			}
			container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
			if err != nil {
				t.Fatalf("failed to start MongoDB container: %v", err)
			}
			mongoContainer.Store(&container)
			// Advertise localhost so the driver can reach the single member.
			code, _, err := container.Exec(ctx, []string{"mongosh", "--quiet", "--eval",
				`rs.initiate({_id:"rs0",members:[{_id:0,host:"localhost:27017"}]})`})
			if err != nil || code != 0 {
				t.Fatalf("failed to initiate replica set (code %d): %v", code, err)
			}
			for range 60 {
				code, _, _ = container.Exec(ctx, []string{"mongosh", "--quiet", "--eval", `quit(db.hello().isWritablePrimary ? 0 : 1)`})
				if code == 0 {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			host, err := container.Host(ctx)
			if err != nil {
				t.Fatalf("failed to get MongoDB host: %v", err)
			}
			port, err := container.MappedPort(ctx, "27017/tcp")
			if err != nil {
				t.Fatalf("failed to get MongoDB port: %v", err)
			}
			mongoBaseURI.Store(fmt.Sprintf("mongodb://%s:%s/?directConnection=true", host, port.Port()))
		})
		var ok bool
		base, ok = mongoBaseURI.Load().(string)
		if !ok || base == "" {
			t.Fatal("MongoDB container failed to start in a previous test")
		}
	}
	dbName := fmt.Sprintf("memos_test_%d_%d", os.Getpid(), dbCounter.Add(1))
	return insertDatabaseIntoURI(base, dbName)
}

// insertDatabaseIntoURI places dbName in the URI path, before any query.
func insertDatabaseIntoURI(uri, dbName string) string {
	scheme := ""
	rest := uri
	for _, prefix := range []string{"mongodb+srv://", "mongodb://"} {
		if len(rest) >= len(prefix) && rest[:len(prefix)] == prefix {
			scheme, rest = prefix, rest[len(prefix):]
			break
		}
	}
	hostEnd := len(rest)
	for i, c := range rest {
		if c == '/' || c == '?' {
			hostEnd = i
			break
		}
	}
	host, tail := rest[:hostEnd], rest[hostEnd:]
	query := ""
	if i := indexByte(tail, '?'); i >= 0 {
		query = tail[i:]
	}
	return scheme + host + "/" + dbName + query
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

type firestoreRawReader interface {
	CountDocuments(ctx context.Context, collection string, filter map[string]any) (int64, error)
	RawDocument(ctx context.Context, collection string, filter map[string]any) (map[string]any, error)
	InsertRawDocument(ctx context.Context, collection string, doc map[string]any) error
}

func firestoreRaw(t *testing.T, ts *store.Store) firestoreRawReader {
	t.Helper()
	reader, ok := ts.GetDriver().(firestoreRawReader)
	if !ok {
		t.Fatalf("driver %T does not expose raw Firestore reads", ts.GetDriver())
	}
	return reader
}

// countFirestoreDocs counts raw documents, bypassing store visibility rules.
func countFirestoreDocs(ctx context.Context, t *testing.T, ts *store.Store, collection string, filter map[string]any) int64 {
	t.Helper()
	n, err := firestoreRaw(t, ts).CountDocuments(ctx, collection, filter)
	if err != nil {
		t.Fatalf("count %s: %v", collection, err)
	}
	return n
}

func terminateMongoContainer(ctx context.Context) {
	if container := mongoContainer.Load(); container != nil {
		_ = (*container).Terminate(ctx)
	}
}
