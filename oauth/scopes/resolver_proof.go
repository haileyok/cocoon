package scopes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/lexicon"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-car"
	"github.com/multiformats/go-multihash"
)

// verifyLexiconProof accepts only a signed commit and its MST inclusion proof.
// CAR reads verify each block's hash before it enters the in-memory store; no
// record or tree links are fetched separately, and unsigned JSON is never used.
func verifyLexiconProof(ctx context.Context, proof []byte, ident *identity.Identity, nsid syntax.NSID) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Base58 decoding has quadratic cost. Bound the text before Indigo
	// decodes it; 128 bytes accommodates both compressed Multikeys and
	// legacy uncompressed P-256/K-256 keys (65 bytes before base58).
	if len(ident.Keys["atproto"].PublicKeyMultibase) > 128 {
		return nil, fmt.Errorf("lexicon authority signing key exceeds 128 bytes")
	}
	key, err := ident.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("lexicon authority signing key: %w", err)
	}
	if err := checkProofCAR(proof); err != nil {
		return nil, fmt.Errorf("CAR preflight: %w", err)
	}
	cr, err := car.NewCarReader(bytes.NewReader(proof))
	if err != nil {
		return nil, err
	}
	if len(cr.Header.Roots) != 1 {
		return nil, fmt.Errorf("lexicon proof must have exactly one CAR root")
	}
	bs := repo.NewTinyBlockstore()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		block, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Restrict hashes as well as codecs: weak/identity hashes must not
		// turn content addressing into an attacker-controlled assertion.
		p := block.Cid().Prefix()
		if p.Version != 1 || p.Codec != cid.DagCBOR || p.MhType != multihash.SHA2_256 || p.MhLength != 32 {
			return nil, fmt.Errorf("invalid repository block CID: %s", block.Cid())
		}
		if err := bs.Put(ctx, block); err != nil {
			return nil, err
		}
	}
	block, err := bs.Get(ctx, cr.Header.Roots[0])
	if err != nil {
		return nil, fmt.Errorf("missing commit: %w", err)
	}
	var commit repo.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(block.RawData())); err != nil {
		return nil, err
	}
	if err := commit.VerifyStructure(); err != nil {
		return nil, err
	}
	if commit.DID != ident.DID.String() {
		return nil, fmt.Errorf("commit DID does not match lexicon authority")
	}
	if err := commit.VerifySignature(key); err != nil {
		return nil, fmt.Errorf("commit signature: %w", err)
	}
	if err := checkProofTree(ctx, bs, commit.Data); err != nil {
		return nil, err
	}
	tree, err := mst.LoadTreeFromStore(ctx, bs, commit.Data)
	if err != nil {
		return nil, err
	}
	if err := tree.Verify(); err != nil {
		return nil, err
	}
	r := repo.Repo{MST: *tree, RecordStore: bs}
	record, _, err := r.GetRecordBytes(ctx, "com.atproto.lexicon.schema", syntax.RecordKey(nsid))
	if err != nil {
		return nil, fmt.Errorf("record not included in proof: %w", err)
	}
	return parseLexiconRecord(record, nsid)
}

// Local actor-store reads skip network proof verification, not the size,
// nesting, data-model, or document checks applied to remote lexicons.
func parseLexiconRecord(record []byte, nsid syntax.NSID) (json.RawMessage, error) {
	if len(record) > atdata.MAX_CBOR_RECORD_SIZE {
		return nil, fmt.Errorf("lexicon record exceeds size limit")
	}
	if err := checkProofCBOR(record); err != nil {
		return nil, fmt.Errorf("lexicon CBOR preflight: %w", err)
	}
	doc, err := atdata.UnmarshalCBOR(record)
	if err != nil {
		return nil, err
	}
	if err := checkResolvedLexicon(doc, nsid); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// Indigo's MST loader assumes prefix lengths are safe to slice and recursively
// loads supplied child blocks. Preflight those assumptions without recursion
// before giving it network data. Absent siblings are valid in a partial proof;
// GetRecordBytes will still require every node on the requested record's path.
func checkProofTree(ctx context.Context, bs *repo.TinyBlockstore, root cid.Cid) error {
	type pending struct {
		cid   cid.Cid
		depth int
	}
	queue := []pending{{root, 0}}
	seen := map[cid.Cid]bool{}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		next := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		// MST layers count pairs of leading zero bits in SHA-256: at most
		// 128 layers. Also forbid shared/cyclic nodes, which are not a tree.
		if next.depth > 128 || seen[next.cid] {
			return fmt.Errorf("invalid MST depth or repeated node")
		}
		seen[next.cid] = true
		block, err := bs.Get(ctx, next.cid)
		if err != nil {
			continue
		}
		nd, err := mst.NodeDataFromCBOR(bytes.NewReader(block.RawData()))
		if err != nil {
			return err
		}
		if nd.Left != nil {
			queue = append(queue, pending{*nd.Left, next.depth + 1})
		}
		keyLen := int64(0)
		for _, e := range nd.Entries {
			if e.PrefixLen < 0 || e.PrefixLen > keyLen {
				return fmt.Errorf("invalid MST key prefix length")
			}
			keyLen = e.PrefixLen + int64(len(e.KeySuffix))
			if keyLen > 1024 {
				return fmt.Errorf("invalid MST key length")
			}
			if e.Right != nil {
				queue = append(queue, pending{*e.Right, next.depth + 1})
			}
		}
	}
	return nil
}

// This validates the document envelope and the declarations this resolver
// consumes, not the entire Lexicon language. Indigo does not model Spaces.
// Keep those declarations on our local parser rather than silently dropping
// them or claiming that SchemaFile.CheckSchema validates them.
func checkResolvedLexicon(doc map[string]any, nsid syntax.NSID) error {
	if doc["$type"] != "com.atproto.lexicon.schema" || doc["lexicon"] != int64(1) || doc["id"] != nsid.String() {
		return fmt.Errorf("invalid lexicon document type, version, or ID")
	}
	if description, present := doc["description"]; present {
		if _, ok := description.(string); !ok {
			return fmt.Errorf("invalid lexicon description")
		}
	}
	defs, ok := doc["defs"].(map[string]any)
	if !ok {
		return fmt.Errorf("invalid lexicon defs")
	}
	for name, def := range defs {
		if name == "" || strings.ContainsAny(name, ".#") {
			return fmt.Errorf("invalid lexicon definition name")
		}
		if _, ok := def.(map[string]any); !ok {
			return fmt.Errorf("invalid lexicon definition")
		}
	}
	main, _ := defs["main"].(map[string]any)
	switch main["type"] {
	case "space":
		_, err := ParseSpaceDeclaration(doc)
		return err
	case "permission-set":
		permissions, ok := main["permissions"].([]any)
		if !ok {
			return fmt.Errorf("permission set requires permissions array")
		}
		data, err := json.Marshal(main)
		if err != nil {
			return err
		}
		var ps lexicon.SchemaPermissionSet
		if err := json.Unmarshal(data, &ps); err != nil {
			return err
		}
		// Validate metadata with Indigo, leaving resource interpretation to
		// existing scope parsers (including the local space extension).
		ps.Permissions = nil
		if err := ps.CheckSchema(); err != nil {
			return err
		}
		for _, value := range permissions {
			p, ok := value.(map[string]any)
			if !ok || p["type"] != "permission" {
				return fmt.Errorf("invalid permission declaration")
			}
			if resource, ok := p["resource"].(string); !ok || resource == "" {
				return fmt.Errorf("invalid permission resource")
			}
		}
		return nil
	default:
		return fmt.Errorf("lexicon main must be a permission-set or space")
	}
}
