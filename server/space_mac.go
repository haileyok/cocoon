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

// Space repo MACs (the reference's getSpaceMacSecret, commitMacHeaders and
// recordMacHeaders in api/com/atproto/space/util.ts at bluesky-social/atproto
// ac0c9f15). getLatestCommit, getRepo, listRepoOps and getRecord authenticate
// what they return with a MAC keyed by a per-request shared secret, which the
// syncer establishes against the author's #atproto_kem key.

// accountKemKey is the account's #atproto_kem private key, nil for an account
// that has none yet.
func accountKemKey(repo models.Repo) (*atcrypto.PrivateKeyP256, error) {
	if len(repo.KemKey) == 0 {
		return nil, nil
	}
	return atcrypto.ParsePrivateBytesP256(repo.KemKey)
}

// spaceMacSecret returns the shared secret to MAC a read's response with.
// A request presenting a space credential must ask for a MAC; an account
// reading its own data gets one only if it asks, and nil otherwise.
func (s *Server) spaceMacSecret(e echo.Context, p *spaceReadParams, typ string) ([]byte, error) {
	h := e.Response().Header()
	h.Add("Vary", space.HeaderWantMac)

	values := e.Request().Header.Values(space.HeaderWantMac)
	if len(values) == 0 && p.auth.credential == nil {
		return nil, nil
	}
	// So that a browser app can read the MAC from a cross-origin response.
	h.Add("Access-Control-Expose-Headers", space.HeaderMac)

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
	secret, err := func() ([]byte, error) {
		keyShare, err := space.ParseWantMacHeader(values, typ)
		if err != nil {
			return nil, err
		}
		return space.Decapsulate(kem, keyShare)
	}()
	if err != nil {
		var me *space.MacError
		if errors.As(err, &me) {
			return nil, errInvalid("BadSpaceMac", "%s", me.Message)
		}
		return nil, err
	}
	return secret, nil
}

// setCommitMac sets the Atproto-Space-Mac response header for a commit, when
// a MAC was requested.
func setCommitMac(e echo.Context, secret []byte, c space.Commit) {
	if secret == nil {
		return
	}
	e.Response().Header().Set(space.HeaderMac, space.FormatMacHeader(space.CommitMacType, space.ComputeCommitMac(secret, c)))
}

// setRecordMac sets the Atproto-Space-Mac response header for a record, when
// a MAC was requested.
func setRecordMac(e echo.Context, secret []byte, uri string, c cid.Cid) {
	if secret == nil {
		return
	}
	e.Response().Header().Set(space.HeaderMac, space.FormatMacHeader(space.RecordMacType, space.ComputeRecordMac(secret, uri, c)))
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
