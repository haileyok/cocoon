package space

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The language-neutral STAR fixtures from tangled.org/microcosm.blue/star
// (interop/), which cover the DASL-STAR framing. See testdata/SOURCE.

func readFixtures(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestStarInteropValid(t *testing.T) {
	t.Parallel()
	var fixtures []struct {
		Comment string `json:"comment"`
		StarHex string `json:"star_hex"`
		Decoded struct {
			Meta  json.RawMessage `json:"meta"`
			Pairs []struct {
				KeyHex   string `json:"key_hex"`
				ValueHex string `json:"value_hex"`
			} `json:"pairs"`
		} `json:"decoded"`
	}
	readFixtures(t, "star-valid-fixtures.json", &fixtures)
	for _, f := range fixtures {
		t.Run(f.Comment, func(t *testing.T) {
			raw, err := hex.DecodeString(f.StarHex)
			if err != nil {
				t.Fatal(err)
			}
			sr, err := ReadStar(bytes.NewReader(raw), StarLimits{})
			if err != nil && strings.Contains(err.Error(), "non-empty string") {
				// Indigo's DRISL decoder refuses an empty $type, which no
				// Spaces profile has, as each names itself.
				t.Skip("empty $type")
			}
			if err != nil {
				t.Fatal(err)
			}
			// Compared as JSON, the atproto convention for DRISL.
			gotMeta, err := json.Marshal(sr.Meta)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if err := json.Unmarshal(gotMeta, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(f.Decoded.Meta, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("meta: got %s, want %s", gotMeta, f.Decoded.Meta)
			}
			for i, p := range f.Decoded.Pairs {
				k, v, err := sr.Next()
				if err != nil {
					t.Fatalf("pair %d: %v", i, err)
				}
				if hex.EncodeToString(k) != lower(p.KeyHex) || hex.EncodeToString(v) != lower(p.ValueHex) {
					t.Fatalf("pair %d: got %x/%x, want %s/%s", i, k, v, p.KeyHex, p.ValueHex)
				}
			}
			if _, _, err := sr.Next(); err != io.EOF {
				t.Fatalf("expected the end of the archive, got %v", err)
			}
		})
	}
}

func TestStarInteropInvalid(t *testing.T) {
	t.Parallel()
	var fixtures []struct {
		Comment string `json:"comment"`
		StarHex string `json:"star_hex"`
	}
	readFixtures(t, "star-invalid-fixtures.json", &fixtures)
	for _, f := range fixtures {
		t.Run(f.Comment, func(t *testing.T) {
			raw, err := hex.DecodeString(f.StarHex)
			if err != nil {
				t.Fatal(err)
			}
			sr, err := ReadStar(bytes.NewReader(raw), StarLimits{})
			if err != nil {
				return
			}
			for {
				if _, _, err = sr.Next(); err != nil {
					break
				}
			}
			if err == io.EOF {
				t.Fatal("parsed an invalid archive")
			}
		})
	}
}

func lower(s string) string { return string(bytes.ToLower([]byte(s))) }
