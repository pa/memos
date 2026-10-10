package gcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/usememos/memos/provider/storage/s3"
)

// fakeGCS implements the slice of the GCS JSON API the driver uses.
type fakeGCS struct {
	mu      sync.Mutex
	objects map[string][]byte
	types   map[string]string
}

func (f *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	const bucket = "notes"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+bucket+"/o":
		if r.URL.Query().Get("uploadType") != "media" {
			http.Error(w, "bad upload type", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		name := r.URL.Query().Get("name")
		f.objects[name] = body
		f.types[name] = r.Header.Get("Content-Type")
		fmt.Fprintf(w, `{"name":%q}`, name)
	case strings.HasPrefix(r.URL.EscapedPath(), "/storage/v1/b/"+bucket+"/o/"):
		// The object name is one escaped path segment; slashes arrive as %2F.
		name := strings.TrimPrefix(r.URL.Path, "/storage/v1/b/"+bucket+"/o/")
		if strings.Contains(strings.TrimPrefix(r.URL.EscapedPath(), "/storage/v1/b/"+bucket+"/o/"), "/") {
			http.Error(w, "unescaped object name", http.StatusBadRequest)
			return
		}
		data, ok := f.objects[name]
		if r.Method == http.MethodDelete {
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			delete(f.objects, name)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if rng := r.Header.Get("Range"); rng != "" {
			var start, end int
			if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); err != nil || start >= len(data) {
				w.Header().Set("Content-Range", "bytes */"+strconv.Itoa(len(data)))
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			end = min(end, len(data)-1)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
			w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[start : end+1])
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusTeapot)
	}
}

func newTestDriver(t *testing.T) (*Driver, *fakeGCS) {
	t.Helper()
	fake := &fakeGCS{objects: map[string][]byte{}, types: map[string]string{}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return newDriverWithClient(server.Client(), server.URL, "notes"), fake
}

func TestDriverRoundTrip(t *testing.T) {
	ctx := context.Background()
	driver, fake := newTestDriver(t)

	key := "assets/2026/a b+c?.txt"
	content := []byte("hello from gcs")
	got, err := driver.UploadObject(ctx, key, "text/plain", bytes.NewReader(content))
	require.NoError(t, err)
	require.Equal(t, key, got)
	require.Equal(t, "text/plain", fake.types[key])

	data, err := driver.GetObject(ctx, key)
	require.NoError(t, err)
	require.Equal(t, content, data)

	stream, err := driver.GetObjectStream(ctx, key, "bytes=6-9")
	require.NoError(t, err)
	partial, err := io.ReadAll(stream.Body)
	require.NoError(t, err)
	stream.Body.Close()
	require.Equal(t, "from", string(partial))
	require.Equal(t, "bytes 6-9/14", stream.ContentRange)
	require.EqualValues(t, 4, stream.ContentLength)

	_, err = driver.GetObjectStream(ctx, key, "bytes=100-200")
	require.ErrorIs(t, err, s3.ErrRangeNotSatisfiable)
	var rangeErr *s3.RangeNotSatisfiableError
	require.True(t, errors.As(err, &rangeErr))
	require.Equal(t, "bytes */14", rangeErr.ContentRange)

	require.NoError(t, driver.DeleteObject(ctx, key))
	require.NoError(t, driver.DeleteObject(ctx, key), "deleting a missing object succeeds")
	_, err = driver.GetObject(ctx, key)
	require.ErrorContains(t, err, "404")
}

func TestDriverDefaultsContentType(t *testing.T) {
	driver, fake := newTestDriver(t)
	_, err := driver.UploadObject(context.Background(), "blob", "", bytes.NewReader([]byte{1}))
	require.NoError(t, err)
	require.Equal(t, "application/octet-stream", fake.types["blob"])
}

func TestNewDriverRequiresBucket(t *testing.T) {
	_, err := NewDriver(context.Background(), nil)
	require.EqualError(t, err, "GCS bucket is required")
}
