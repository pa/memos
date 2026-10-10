package memopayload

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	storepb "github.com/usememos/memos/proto/gen/store"
)

// EncryptedContentPrefix marks memo content sealed in the browser. Everything
// after it is a JSON Envelope. The server never holds the key, so it treats
// the ciphertext as opaque and takes searchable metadata from the envelope's
// index, which the client computes before sealing.
const EncryptedContentPrefix = "memos-e2ee:v1:"

// maxEnvelopeTags bounds the blind tag index of one memo.
const maxEnvelopeTags = 64

// blindTagPattern matches a blind tag index value: hex HMAC output. Plain tag
// names never match, so a client bug cannot leak names into the index.
var blindTagPattern = regexp.MustCompile(`^[0-9a-f]{32,64}$`)

// Envelope is the server-visible shape of encrypted memo content.
type Envelope struct {
	// Key identifies the key family, e.g. "pk" (personal) or "sk:<space>:<epoch>".
	Key string `json:"k"`
	// IV and CT are the base64 AES-GCM nonce and ciphertext.
	IV string `json:"iv"`
	CT string `json:"ct"`
	// Tags are blind (keyed hash) tag indexes, never names.
	Tags []string `json:"t,omitempty"`
	// Flags are coarse content properties the client chose to reveal for filtering.
	Flags EnvelopeFlags `json:"p"`
}

// EnvelopeFlags mirror MemoPayload.Property without the title, which would
// leak content.
type EnvelopeFlags struct {
	HasLink            bool `json:"l,omitempty"`
	HasCode            bool `json:"c,omitempty"`
	HasTaskList        bool `json:"t,omitempty"`
	HasIncompleteTasks bool `json:"i,omitempty"`
}

// IsEncryptedContent reports whether content is a sealed envelope.
func IsEncryptedContent(content string) bool {
	return strings.HasPrefix(content, EncryptedContentPrefix)
}

// ParseEnvelope validates and decodes encrypted content.
func ParseEnvelope(content string) (*Envelope, error) {
	if !IsEncryptedContent(content) {
		return nil, errors.New("content is not encrypted")
	}
	envelope := &Envelope{}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(content, EncryptedContentPrefix)), envelope); err != nil {
		return nil, errors.Wrap(err, "invalid encrypted content envelope")
	}
	if envelope.Key == "" || envelope.IV == "" || envelope.CT == "" {
		return nil, errors.New("encrypted content envelope is incomplete")
	}
	if len(envelope.Tags) > maxEnvelopeTags {
		return nil, errors.Errorf("encrypted content has more than %d tags", maxEnvelopeTags)
	}
	for _, tag := range envelope.Tags {
		if !blindTagPattern.MatchString(tag) {
			return nil, errors.New("encrypted content tags must be blind indexes")
		}
	}
	return envelope, nil
}

// applyEnvelope sets the searchable payload from an envelope's index.
func applyEnvelope(payload *storepb.MemoPayload, envelope *Envelope) {
	payload.Tags = uniqueStrings(envelope.Tags)
	payload.Property = &storepb.MemoPayload_Property{
		HasLink:            envelope.Flags.HasLink,
		HasCode:            envelope.Flags.HasCode,
		HasTaskList:        envelope.Flags.HasTaskList,
		HasIncompleteTasks: envelope.Flags.HasIncompleteTasks,
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
