package space

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	cid "github.com/ipfs/go-cid"
	car "github.com/ipld/go-car"
	carutil "github.com/ipld/go-car/util"
)

func TestSerializeAndVerifyTwoRootCAR(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	records := testRecords(t)
	repo, err := RepoCommitFromRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	ctx := CommitContext{Space: "at://did:plc:test/space/com.example/alpha", Author: "did:plc:author", Rev: "3jzfcijpj2s2a"}
	commit, err := repo.Sign(ctx, key, SignOptions{IKM: bytes.Repeat([]byte{9}, CommitIKMBytes)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := SerializeRepo(commit, records)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRepoCAR(data, VerifyRepoParams{Space: ctx.Space, Author: ctx.Author, DIDKey: pub.DIDKey(), ExpectValues: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Roots) != 2 || len(verified.Index) != len(records) || len(verified.Records) != len(records) {
		t.Fatalf("verified CAR shape = roots %d, index %d, records %d", len(verified.Roots), len(verified.Index), len(verified.Records))
	}
	if !verified.Repo.Matches(commit) {
		t.Fatal("verified index repo does not match commit")
	}

	reader, err := car.NewCarReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.Header.Roots) != 2 || !reader.Header.Roots[0].Equals(verified.Roots[0]) || !reader.Header.Roots[1].Equals(verified.Roots[1]) {
		t.Fatal("CAR roots are not the signed commit and index roots")
	}
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	indexBlock, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	index, err := DecodeRepoIndex(indexBlock.RawData())
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(index))
	for path := range index {
		paths = append(paths, path)
	}
	sortCanonicalPaths(paths)
	for _, path := range paths {
		block, err := reader.Next()
		if err != nil {
			t.Fatalf("read ordered value %s: %v", path, err)
		}
		if !block.Cid().Equals(index[path]) {
			t.Fatalf("value order at %s = %s, want %s", path, block.Cid(), index[path])
		}
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("CAR has unexpected trailing block/error: %v", err)
	}
}

func TestSerializeIndexOnlyCARAndRejectValues(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	records := testRecords(t)
	repo, err := RepoCommitFromRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	ctx := CommitContext{Space: "space", Author: "author", Rev: "rev"}
	commit, err := repo.Sign(ctx, key, SignOptions{IKM: bytes.Repeat([]byte{4}, CommitIKMBytes)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := SerializeRepo(commit, records, SerializeRepoOptions{ExcludeValues: true})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRepoCAR(data, VerifyRepoParams{Space: ctx.Space, Author: ctx.Author, DIDKey: pub.DIDKey(), ExpectValues: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Records) != 0 {
		t.Fatal("index-only CAR returned values")
	}
	if _, err := VerifyRepoCAR(data, VerifyRepoParams{Space: ctx.Space, Author: ctx.Author, DIDKey: pub.DIDKey(), ExpectValues: true}); err == nil {
		t.Fatal("full verifier accepted index-only CAR")
	}
	full, err := SerializeRepo(commit, records)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRepoCAR(full, VerifyRepoParams{Space: ctx.Space, Author: ctx.Author, DIDKey: pub.DIDKey(), ExpectValues: false}); err == nil {
		t.Fatal("index-only verifier accepted value blocks")
	}
}

func TestCARRejectsTamperedCommitIndexValueAndRoots(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	records := testRecords(t)
	repo, err := RepoCommitFromRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	ctx := CommitContext{Space: "space", Author: "author", Rev: "rev"}
	commit, err := repo.Sign(ctx, key, SignOptions{IKM: bytes.Repeat([]byte{2}, CommitIKMBytes)})
	if err != nil {
		t.Fatal(err)
	}
	validParams := VerifyRepoParams{Space: ctx.Space, Author: ctx.Author, DIDKey: pub.DIDKey(), ExpectValues: true}

	badCommit := commit
	badCommit.MAC = append([]byte(nil), commit.MAC...)
	badCommit.MAC[0]++
	badCommitCAR, err := SerializeRepo(badCommit, records)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRepoCAR(badCommitCAR, validParams); err == nil {
		t.Fatal("tampered commit MAC accepted")
	}

	other, err := SerializeRecord("com.example.notes", "different", map[string]interface{}{"text": "changed"})
	if err != nil {
		t.Fatal(err)
	}
	mismatched := append(append([]SerializedRecord(nil), records...), other)
	mismatchedCAR, err := SerializeRepo(commit, mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRepoCAR(mismatchedCAR, validParams); err == nil {
		t.Fatal("index with a different LtHash was accepted")
	}

	tamperedValue := append([]byte(nil), mustSerialize(t, commit, records)...)
	tamperedValue[len(tamperedValue)-1] ^= 1
	if _, err := VerifyRepoCAR(tamperedValue, validParams); err == nil {
		t.Fatal("tampered value bytes accepted")
	}

	buf := new(bytes.Buffer)
	root, err := CIDForCBOR([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	if err := car.WriteHeader(&car.CarHeader{Roots: []cid.Cid{root}, Version: 1}, buf); err != nil {
		t.Fatal(err)
	}
	if err := carutil.LdWrite(buf, []byte{1}, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRepoCAR(buf.Bytes(), validParams); err == nil {
		t.Fatal("CAR with wrong root count accepted")
	}
}

func testRecords(t *testing.T) []SerializedRecord {
	t.Helper()
	values := []struct {
		collection string
		rkey       string
		text       string
	}{
		{"a", "b", "shortest"},
		{"aa", "a", "middle"},
		{"com.example.notes", "one", "longest"},
	}
	records := make([]SerializedRecord, 0, len(values))
	for _, value := range values {
		record, err := SerializeRecord(value.collection, value.rkey, map[string]interface{}{"text": value.text})
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func mustSerialize(t *testing.T, commit SignedCommit, records []SerializedRecord) []byte {
	t.Helper()
	data, err := SerializeRepo(commit, records)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
