// Package gcs stores attachment objects in Google Cloud Storage through the
// JSON API. Credentials come from Application Default Credentials (the Cloud
// Run service account in production), so no keys live in instance settings.
package gcs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	storepb "github.com/usememos/memos/proto/gen/store"
	"github.com/usememos/memos/provider/storage/s3"
)

const (
	defaultEndpoint = "https://storage.googleapis.com"
	readWriteScope  = "https://www.googleapis.com/auth/devstorage.read_write"
)

// Driver stores attachment objects in one GCS bucket.
type Driver struct {
	client   *http.Client
	endpoint string
	bucket   string
}

// NewDriver creates a GCS driver authenticated with Application Default Credentials.
func NewDriver(ctx context.Context, config *storepb.StorageGCSConfig) (*Driver, error) {
	if config == nil || strings.TrimSpace(config.Bucket) == "" {
		return nil, errors.New("GCS bucket is required")
	}
	// The driver is cached across requests, so token refreshes must not be
	// tied to the context of the request that happened to create it.
	baseCtx := context.WithoutCancel(ctx)
	tokenSource, err := google.DefaultTokenSource(baseCtx, readWriteScope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find Google credentials")
	}
	return newDriverWithClient(oauth2.NewClient(baseCtx, tokenSource), defaultEndpoint, config.Bucket), nil
}

func newDriverWithClient(client *http.Client, endpoint, bucket string) *Driver {
	return &Driver{
		client:   client,
		endpoint: strings.TrimRight(endpoint, "/"),
		bucket:   strings.TrimSpace(bucket),
	}
}

func (d *Driver) objectURL(key string) string {
	return fmt.Sprintf("%s/storage/v1/b/%s/o/%s", d.endpoint, url.PathEscape(d.bucket), url.PathEscape(key))
}

// UploadObject writes an object, replacing any object with the same key.
func (d *Driver) UploadObject(ctx context.Context, key string, fileType string, content io.Reader) (string, error) {
	query := url.Values{"uploadType": {"media"}, "name": {key}}
	uploadURL := fmt.Sprintf("%s/upload/storage/v1/b/%s/o?%s", d.endpoint, url.PathEscape(d.bucket), query.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, content)
	if err != nil {
		return "", errors.Wrap(err, "failed to build upload request")
	}
	if fileType == "" {
		fileType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", fileType)
	resp, err := d.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to upload object")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", responseError("upload object", resp)
	}
	return key, nil
}

// GetObject reads a whole object.
func (d *Driver) GetObject(ctx context.Context, key string) ([]byte, error) {
	stream, err := d.GetObjectStream(ctx, key, "")
	if err != nil {
		return nil, err
	}
	defer stream.Body.Close()
	data, err := io.ReadAll(stream.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read object body")
	}
	return data, nil
}

// GetObjectStream streams an object. A non-empty byteRange is forwarded as an
// HTTP Range header and yields a partial object with ContentRange set.
func (d *Driver) GetObjectStream(ctx context.Context, key string, byteRange string) (*s3.ObjectStream, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.objectURL(key)+"?alt=media", nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build download request")
	}
	if byteRange != "" {
		req.Header.Set("Range", byteRange)
	}
	// Serve stored bytes as-is; transparent decompression would break ranges.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get object")
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
	case http.StatusRequestedRangeNotSatisfiable:
		resp.Body.Close()
		return nil, &s3.RangeNotSatisfiableError{ContentRange: resp.Header.Get("Content-Range")}
	default:
		defer resp.Body.Close()
		return nil, responseError("get object", resp)
	}
	stream := &s3.ObjectStream{Body: resp.Body, ContentLength: resp.ContentLength}
	if resp.StatusCode == http.StatusPartialContent {
		stream.ContentRange = resp.Header.Get("Content-Range")
	}
	return stream, nil
}

// DeleteObject removes an object. Deleting a missing object succeeds, like S3.
func (d *Driver) DeleteObject(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.objectURL(key), nil)
	if err != nil {
		return errors.Wrap(err, "failed to build delete request")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to delete object")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return responseError("delete object", resp)
}

func responseError(action string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return errors.Errorf("failed to %s: GCS returned %s: %s", action, resp.Status, strings.TrimSpace(string(body)))
}
