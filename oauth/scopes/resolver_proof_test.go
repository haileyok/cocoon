package scopes

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	carutil "github.com/ipld/go-car/util"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
)

// Builds real signed repository proofs; corruptions retain every other layer
// of the proof so failures cannot be mistaken for JSON/CAR decoding failures.
func lexiconProofFixture(t *testing.T, kind, mode string) ([]byte, string) {
	t.Helper()
	return lexiconProofFixtureWithCBOR(t, kind, mode, nil)
}

func lexiconProofFixtureWithCBOR(t *testing.T, kind, mode string, mutate func(string, []byte) []byte) ([]byte, string) {
	t.Helper()
	var key atcrypto.PrivateKey
	var err error
	if mode == "P256" || mode == "legacy P256" {
		key, err = atcrypto.GeneratePrivateKeyP256()
	} else {
		key, err = atcrypto.GeneratePrivateKeyK256()
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := atdata.UnmarshalJSON([]byte(fmt.Sprintf(`{"$type":"com.atproto.lexicon.schema","lexicon":1,"id":"com.example.lexicon","defs":{"main":{"type":%q,"title":"Example","key":"tid","collections":["com.example.record"],"permissions":[{"type":"permission","resource":"repo","collection":["com.example.record"],"action":["create"]},{"type":"permission","resource":"space","spaceType":"com.example.group","collection":["com.example.record"],"action":["create"]}]}}}`, kind)))
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "wrong ID":
		doc["id"] = "com.example.other"
	case "wrong type":
		doc["$type"] = "com.example.other"
	case "wrong version":
		doc["lexicon"] = int64(2)
	case "missing defs":
		delete(doc, "defs")
	case "missing type":
		delete(doc, "$type")
	case "missing permissions":
		delete(doc["defs"].(map[string]any)["main"].(map[string]any), "permissions")
	case "invalid declaration":
		main := doc["defs"].(map[string]any)["main"].(map[string]any)
		if kind == "space" {
			main["title"] = ""
		} else {
			main["permissions"] = []any{map[string]any{"type": "not-permission", "resource": "repo"}}
		}
	}
	record, err := atdata.MarshalCBOR(doc)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		record = mutate("record", record)
	}
	prefix := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
	recordCID, err := prefix.Sum(record)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "wrong codec" {
		recordCID, err = cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(record)
		if err != nil {
			t.Fatal(err)
		}
	}
	path := "com.atproto.lexicon.schema/com.example.lexicon"
	if mode == "wrong path" {
		path = "com.atproto.lexicon.schema/com.example.other"
	}
	node := mst.NodeData{Entries: []mst.EntryData{{KeySuffix: []byte(path), Value: recordCID}}}
	if mode == "bad prefix" {
		node.Entries[0].PrefixLen = 999
	}
	if mode == "negative prefix" {
		node.Entries[0].PrefixLen = -1
	}
	tree, treeCID, err := node.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		tree = mutate("MST", tree)
		c, err := prefix.Sum(tree)
		if err != nil {
			t.Fatal(err)
		}
		treeCID = &c
	}
	child, childCID := tree, *treeCID
	partial := mode == "partial" || mode == "missing path node"
	if partial {
		// A genuine multi-level proof: the requested record is in the left
		// child, while the unrelated right subtree is intentionally absent.
		var parentKey string
		for i := 0; ; i++ {
			parentKey = fmt.Sprintf("com.example.z/other%d", i)
			if mst.HeightForKey([]byte(parentKey)) == mst.HeightForKey([]byte(path))+1 {
				break
			}
		}
		absent, err := prefix.Sum([]byte("absent sibling"))
		if err != nil {
			t.Fatal(err)
		}
		parent := mst.NodeData{Left: &childCID, Entries: []mst.EntryData{{KeySuffix: []byte(parentKey), Value: recordCID, Right: &absent}}}
		tree, treeCID, err = parent.Bytes()
		if err != nil {
			t.Fatal(err)
		}
	}
	commit := repo.Commit{DID: "did:plc:abcdefghijklmnopqrstuvwx", Version: 3, Rev: "3jzfcijpj2z2a", Data: *treeCID}
	if mode == "DID-web" {
		commit.DID = "did:web:public.example.com"
	}
	if mode == "wrong DID" {
		commit.DID = "did:plc:zyxwvutsrqponmlkjihgfedc"
	}
	if mode == "forged signature" {
		key, err = atcrypto.GeneratePrivateKeyK256()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := commit.Sign(key); err != nil {
		t.Fatal(err)
	}
	if mode == "tampered commit" {
		commit.Rev = "3jzfcijpj2z2b"
	}
	if mode == "unsigned commit" {
		commit.Sig = nil
	}
	var commitBytes bytes.Buffer
	if err := commit.MarshalCBOR(&commitBytes); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		commitBytes = *bytes.NewBuffer(mutate("commit", commitBytes.Bytes()))
	}
	commitCID, err := prefix.Sum(commitBytes.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	roots := []cid.Cid{commitCID}
	if mode == "multiple roots" {
		roots = append(roots, recordCID)
	}
	var header bytes.Buffer
	if err := car.WriteHeader(&car.CarHeader{Version: 1, Roots: roots}, &header); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if mutate == nil {
		out.Write(header.Bytes())
	} else {
		// Strip/rebuild the length-delimited header to mutate its CBOR too.
		raw, err := carutil.LdRead(bufio.NewReader(&header))
		if err != nil {
			t.Fatal(err)
		}
		if err := carutil.LdWrite(&out, mutate("header", raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []struct {
		id   cid.Cid
		data []byte
		omit bool
	}{
		{commitCID, commitBytes.Bytes(), mode == "missing commit"},
		{*treeCID, tree, mode == "missing MST"},
		{recordCID, record, mode == "missing record"},
		{childCID, child, !partial || mode == "missing path node"},
	} {
		if b.omit {
			continue
		}
		if mode == "tampered record CID" && b.id == recordCID {
			b.data = bytes.ReplaceAll(b.data, []byte("Example"), []byte("Forged!"))
		}
		if mode == "tampered MST CID" && b.id == *treeCID {
			b.data = bytes.ReplaceAll(b.data, []byte("lexicon"), []byte("forgery"))
		}
		if err := carutil.LdWrite(&out, b.id.Bytes(), b.data); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes(), pub.Multibase()
}

// Pad with an unreferenced, valid block so the exact HTTP size boundary is
// tested independently of proof validity and record-size limits.
func lexiconProofAtSize(t *testing.T, proof []byte, size int) []byte {
	t.Helper()
	// At this size the CAR section length takes three bytes, the CID 36,
	// and the CBOR byte-string header five.
	padding := make([]byte, size-len(proof)-3-36)
	padding[0] = 0x5a
	binary.BigEndian.PutUint32(padding[1:5], uint32(len(padding)-5))
	c, err := cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256).Sum(padding)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.Write(proof)
	if err := carutil.LdWrite(&out, c.Bytes(), padding); err != nil {
		t.Fatal(err)
	}
	if out.Len() != size {
		t.Fatalf("proof size = %d, want %d", out.Len(), size)
	}
	return out.Bytes()
}

func TestVerifyLexiconProof(t *testing.T) {
	for _, kind := range []string{"permission-set", "space"} {
		for mode, wantErr := range map[string]string{
			"valid": "", "P256": "", "legacy P256": "", "legacy K256": "", "partial": "",
			"forged signature": "commit signature", "tampered commit": "commit signature",
			"unsigned commit": "empty commit signature", "wrong DID": "commit DID",
			"wrong path": "record not included", "wrong ID": "document type, version, or ID",
			"wrong type": "document type, version, or ID", "missing type": "document type, version, or ID",
			"wrong version": "document type, version, or ID", "wrong codec": "block CID",
			"tampered record CID": "content integrity", "tampered MST CID": "content integrity",
			"missing defs": "invalid lexicon defs", "invalid declaration": "",
			"missing commit": "missing commit", "missing MST": "could not find",
			"missing record": "record not included", "missing path node": "record not included",
			"multiple roots": "exactly one", "bad prefix": "prefix length", "negative prefix": "prefix length",
			"missing key": "signing key", "missing permissions": "", "truncated": "",
		} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				proof, pub := lexiconProofFixture(t, kind, mode)
				ident := &identity.Identity{DID: syntax.DID("did:plc:abcdefghijklmnopqrstuvwx"), Keys: map[string]identity.VerificationMethod{
					"atproto": {Type: "Multikey", PublicKeyMultibase: pub},
				}}
				if strings.HasPrefix(mode, "legacy") {
					key, err := atcrypto.ParsePublicMultibase(pub)
					if err != nil {
						t.Fatal(err)
					}
					keyType := "EcdsaSecp256k1VerificationKey2019"
					if mode == "legacy P256" {
						keyType = "EcdsaSecp256r1VerificationKey2019"
					}
					ident.Keys["atproto"] = identity.VerificationMethod{
						Type: keyType, PublicKeyMultibase: "z" + base58.Encode(key.UncompressedBytes()),
					}
				}
				if mode == "missing key" {
					ident.Keys = nil
				}
				if mode == "missing permissions" && kind == "permission-set" {
					wantErr = "permissions array"
				}
				if mode == "truncated" {
					proof = proof[:len(proof)-10]
					wantErr = "EOF"
				}
				if mode == "invalid declaration" {
					wantErr = "invalid permission declaration"
					if kind == "space" {
						wantErr = "space type title"
					}
				}
				record, err := verifyLexiconProof(t.Context(), proof, ident, "com.example.lexicon")
				if wantErr == "" {
					if err != nil || !bytes.Contains(record, []byte(`"id":"com.example.lexicon"`)) {
						t.Fatalf("valid proof rejected: %s, %v", record, err)
					}
				} else if err == nil || !strings.Contains(err.Error(), wantErr) || record != nil {
					t.Fatalf("want %q rejection, record=%s error=%v", wantErr, record, err)
				}
			})
		}
	}
}

func TestLexiconProofSigningKeyBounds(t *testing.T) {
	for _, keyType := range []string{"Multikey", "EcdsaSecp256r1VerificationKey2019", "EcdsaSecp256k1VerificationKey2019"} {
		for _, size := range []int{128, 129, 65537} {
			t.Run(fmt.Sprintf("%s/%d", keyType, size), func(t *testing.T) {
				ident := proofIdentity("z" + strings.Repeat("2", size-1))
				method := ident.Keys["atproto"]
				method.Type = keyType
				ident.Keys["atproto"] = method
				_, err := verifyLexiconProof(t.Context(), nil, ident, "com.example.lexicon")
				if err == nil {
					t.Fatal("invalid signing key accepted")
				}
				if got := strings.Contains(err.Error(), "signing key exceeds"); got != (size > 128) {
					t.Fatalf("key length %d: %v", size, err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if _, err := verifyLexiconProof(ctx, nil, ident, "com.example.lexicon"); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled verification: %v", err)
				}
			})
		}
	}
}
