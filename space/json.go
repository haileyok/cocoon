package space

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// Signer signs space tokens.
type Signer = atcrypto.PrivateKey

// LexBytes is the atproto JSON encoding of bytes: {"$bytes": base64}.
type LexBytes []byte

func (b LexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"$bytes": base64.RawStdEncoding.EncodeToString(b)})
}

func (b *LexBytes) UnmarshalJSON(raw []byte) error {
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("expected bytes: %w", err)
	}
	s, ok := m["$bytes"]
	if !ok || len(m) != 1 {
		return fmt.Errorf("expected bytes")
	}
	out, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return fmt.Errorf("expected bytes: %w", err)
	}
	*b = out
	return nil
}

type commitJSON struct {
	Ver   int64    `json:"ver"`
	Repo  string   `json:"repo"`
	Space string   `json:"space"`
	Rev   string   `json:"rev"`
	Data  LexBytes `json:"data"`
}

// MarshalJSON encodes a commit as com.atproto.space.defs#commit.
func (c Commit) MarshalJSON() ([]byte, error) {
	return json.Marshal(commitJSON{Ver: c.Ver, Repo: c.Repo, Space: c.Space, Rev: c.Rev, Data: c.Data})
}

func (c *Commit) UnmarshalJSON(raw []byte) error {
	var j commitJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return err
	}
	*c = Commit{Ver: j.Ver, Repo: j.Repo, Space: j.Space, Rev: j.Rev, Data: j.Data}
	return nil
}
