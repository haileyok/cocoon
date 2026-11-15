package server

import (
	"errors"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
)

// Space repo MACs (the reference's getSpaceMacRequest, commitMacHeaders and
// recordMacHeaders in api/com/atproto/space/util.ts at bluesky-social/atproto
// d4def6e9). getLatestCommit, getRepo, listRepoOps and getRecord authenticate
// what they return with a MAC: an HTTP message signature (hmac-sha256) over a
// header describing the commit or record, keyed by a per-request shared secret
// that the syncer establishes against the author's #atproto_kem key.

// starContentType is the content type of STAR archives.
const starContentType = "application/vnd.dasl.star"

// accountKemKey is the account's #atproto_kem private key, nil for an account
// that has none yet.
func accountKemKey(repo models.Repo) (*atcrypto.PrivateKeyP256, error) {
	if len(repo.KemKey) == 0 {
		return nil, nil
	}
	return atcrypto.ParsePrivateBytesP256(repo.KemKey)
}

// spaceMacRequest reads the MAC a syncer requested with Accept-Signature, and
// derives the shared secret to answer it with. A request presenting a space
// credential must ask for a MAC; an account reading its own data gets one only
// if it asks, and nil otherwise.
func (s *Server) spaceMacRequest(e echo.Context, p *spaceReadParams, profile string) (*space.CreateMacParams, error) {
	h := e.Response().Header()
	h.Add("Vary", space.HeaderAcceptSignature)

	req, err := space.ParseMacRequest(e.Request().Header.Values(space.HeaderAcceptSignature), profile)
	if err != nil {
		return nil, macRequestError(err)
	}
	if req == nil {
		if p.auth.credential != nil {
			return nil, errInvalid("InvalidSpaceMac", "A MAC must be requested with tag %q", profile)
		}
		return nil, nil
	}
	// So that a browser app can read the MAC from a cross-origin response.
	covered := space.HeaderCommit
	if profile == space.RecordMacProfile {
		covered = space.HeaderRecord
	}
	h.Add("Access-Control-Expose-Headers", covered+", Signature-Input, Signature")

	repo, err := s.getRepoActorByDid(e.Request().Context(), p.repo)
	if err != nil {
		return nil, err
	}
	kem, err := accountKemKey(repo.Repo)
	if err != nil {
		return nil, err
	}
	if kem == nil {
		return nil, fmt.Errorf("account has no KEM key: %s", p.repo)
	}
	secret, err := space.Decapsulate(kem, req.KeyShare)
	if err != nil {
		return nil, macRequestError(err)
	}
	return &space.CreateMacParams{MacRequest: *req, SharedSecret: secret}, nil
}

// macRequestError reports a bad MAC request or key share as InvalidSpaceMac.
func macRequestError(err error) error {
	var me *space.MacError
	if errors.As(err, &me) {
		return errInvalid("InvalidSpaceMac", "%s", me.Message)
	}
	var ke *space.KemError
	if errors.As(err, &ke) {
		return errInvalid("InvalidSpaceMac", "%s", ke.Message)
	}
	return err
}

// setCommitMac sets the MAC response headers for a commit, when a MAC was
// requested.
func setCommitMac(e echo.Context, mac *space.CreateMacParams, c space.Commit) {
	if mac == nil {
		return
	}
	setHeaders(e, space.CreateCommitMacHeaders(c, *mac))
}

// setRecordMac sets the MAC response headers for a record, when a MAC was
// requested.
func setRecordMac(e echo.Context, mac *space.CreateMacParams, uri string, c cid.Cid) {
	if mac == nil {
		return
	}
	setHeaders(e, space.CreateRecordMacHeaders(uri, c, *mac))
}

func setHeaders(e echo.Context, headers map[string]string) {
	for k, v := range headers {
		e.Response().Header().Set(k, v)
	}
}

// newKemKey generates an account's dedicated #atproto_kem keypair.
func newKemKey() (*atcrypto.PrivateKeyP256, string, error) {
	k, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		return nil, "", err
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, "", err
	}
	return k, pub.DIDKey(), nil
}

// accountKemDIDKey is the did:key of the account's #atproto_kem key, empty
// when it has none.
func accountKemDIDKey(repo models.Repo) (string, error) {
	k, err := accountKemKey(repo)
	if err != nil || k == nil {
		return "", err
	}
	pub, err := k.PublicKey()
	if err != nil {
		return "", err
	}
	return pub.DIDKey(), nil
}
