package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/internal/space"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// verifyClientAttestation establishes which app asks for a credential,
// following the reference's ClientAttestationVerifier: resolve the client_id
// to its client metadata, take the JWKS it publishes (inline or by uri),
// check the signature against the key the attestation names, then consume
// its jti. It returns the verified client_id.
func (s *Server) verifyClientAttestation(ctx context.Context, attestation, expectedAud string) (string, error) {
	invalid := func(format string, args ...any) error {
		return errInvalid("InvalidClientAttestation", format, args...)
	}
	parsed, err := space.ParseSpaceToken(space.TokenClientAttestation, attestation)
	if err != nil {
		return "", invalid("Invalid client attestation: %v", err)
	}
	clientID := parsed.Payload.Iss

	var meta struct {
		Jwks    json.RawMessage `json:"jwks"`
		JwksURI string          `json:"jwks_uri"`
	}
	if err := s.fetchJSON(ctx, clientID, &meta); err != nil {
		return "", invalid("Could not resolve client metadata for %q", clientID)
	}
	var rawKeys []byte
	switch {
	case len(meta.Jwks) > 0 && string(meta.Jwks) != "null":
		rawKeys = meta.Jwks
	case meta.JwksURI != "":
		var keys json.RawMessage
		if err := s.fetchJSON(ctx, meta.JwksURI, &keys); err != nil {
			return "", invalid("Could not resolve client JWKS from %q", meta.JwksURI)
		}
		rawKeys = keys
	default:
		return "", invalid("Client %q publishes no keys to verify an attestation against", clientID)
	}
	set, err := jwk.Parse(rawKeys)
	if err != nil {
		return "", invalid("Could not resolve client JWKS for %q", clientID)
	}

	if err := verifyAttestationJWT(attestation, set, parsed); err != nil {
		return "", invalid("Invalid client attestation for %q", clientID)
	}
	now := time.Now().Unix()
	if parsed.Payload.Aud != expectedAud {
		return "", invalid("Invalid client attestation for %q", clientID)
	}
	if now > parsed.Payload.Exp {
		return "", invalid("Invalid client attestation for %q", clientID)
	}
	unique, err := s.useSpaceTokenOnce(ctx, "attestation", clientID, parsed.Payload.Jti, parsed.Payload.Exp)
	if err != nil {
		return "", err
	}
	if !unique {
		return "", invalid("Client attestation for %q has already been used", clientID)
	}
	return clientID, nil
}

// verifyAttestationJWT checks the signature against the JWKS key the header
// names (or any key of a matching algorithm when it names none).
func verifyAttestationJWT(token string, set jwk.Set, parsed *space.ParsedToken) error {
	alg := jwa.SignatureAlgorithm(parsed.Header.Alg)
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		if parsed.Header.Kid != "" && key.KeyID() != parsed.Header.Kid {
			continue
		}
		if ka := key.Algorithm(); ka != nil && ka.String() != "" && ka.String() != string(alg) {
			continue
		}
		if _, err := jws.Verify([]byte(token), jws.WithKey(alg, key)); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no key verifies the attestation")
}

func (s *Server) fetchJSON(ctx context.Context, u string, dst any) error {
	cli := s.spaceFetchHTTP
	if cli == nil {
		cli = helpers.NewSafeFetchClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status %d fetching %q", resp.StatusCode, u)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst)
}
