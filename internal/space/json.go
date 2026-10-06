package space

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// Signer signs space commits and tokens.
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

type signedCommitJSON struct {
	Ver  int64    `json:"ver"`
	Hash LexBytes `json:"hash"`
	Mac  LexBytes `json:"mac"`
	Ikm  LexBytes `json:"ikm"`
	Sig  LexBytes `json:"sig"`
	Rev  string   `json:"rev"`
}

// MarshalJSON encodes a commit as com.atproto.space.defs#signedCommit.
func (c SignedCommit) MarshalJSON() ([]byte, error) {
	return json.Marshal(signedCommitJSON{Ver: c.Ver, Hash: c.Hash, Mac: c.Mac, Ikm: c.Ikm, Sig: c.Sig, Rev: c.Rev})
}

func (c *SignedCommit) UnmarshalJSON(raw []byte) error {
	var j signedCommitJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return err
	}
	*c = SignedCommit{Ver: j.Ver, Hash: j.Hash, Mac: j.Mac, Ikm: j.Ikm, Sig: j.Sig, Rev: j.Rev}
	return nil
}
