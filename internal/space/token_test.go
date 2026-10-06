package space

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

// Ported from packages/space/tests/credential.test.ts.

const (
	tSpace     = "at://did:example:space/space/app.bsky.group/test"
	tUser      = "did:example:alice"
	tAuthority = "did:example:space"
	tSpaceHost = tAuthority + "#atproto_space_host"
	tClientID  = "https://app.example.com/client-metadata.json"
)

func newP256(t *testing.T) *atcrypto.PrivateKeyP256 {
	t.Helper()
	k, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyFn(did string) SigningKeyFunc {
	return func(string, string, bool) (string, error) { return did, nil }
}

func tokenCode(t *testing.T, err error) string {
	t.Helper()
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("not a TokenError: %v", err)
	}
	return te.Code
}

func retype(jwt, typ string) string {
	parts := strings.Split(jwt, ".")
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var m map[string]any
	_ = json.Unmarshal(h, &m)
	m["typ"] = typ
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b) + "." + parts[1] + "." + parts[2]
}

// withClaims merges claims into the payload (a nil value deletes the claim)
// and re-signs.
func withClaims(t *testing.T, jwt string, claims map[string]any, key atcrypto.PrivateKey) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(p, &m)
	for k, v := range claims {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(b)
	sig, err := key.HashAndSign([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

var hexJti = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestDelegationToken(t *testing.T) {
	userKey, authorityKey := newK256(t), newK256(t)
	create := func() string {
		jwt, err := CreateSpaceToken(TokenDelegation, CreateTokenOpts{Iss: tUser, Sub: tSpace, Aud: tSpaceHost}, userKey)
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}

	tok, err := VerifySpaceToken(TokenDelegation, create(), VerifyTokenOpts{GetSigningKey: keyFn(didKeyOf(t, userKey)), Aud: tSpaceHost, Sub: tSpace})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header.Typ != "atproto-space-delegation+jwt" || tok.Header.Kid != "#atproto" || tok.Header.Alg != "ES256K" {
		t.Fatalf("header %+v", tok.Header)
	}
	if tok.Payload.Iss != tUser || tok.Payload.Sub != tSpace || tok.Payload.Aud != tSpaceHost || tok.Payload.Exp-tok.Payload.Iat != 60 || !hexJti.MatchString(tok.Payload.Jti) {
		t.Fatalf("payload %+v", tok.Payload)
	}

	if _, err := CreateSpaceToken(TokenDelegation, CreateTokenOpts{Iss: tUser, Sub: tSpace}, userKey); err == nil || !strings.Contains(err.Error(), `requires an "aud"`) {
		t.Fatalf("aud not required: %v", err)
	}
	_, err = VerifySpaceToken(TokenDelegation, create(), VerifyTokenOpts{GetSigningKey: keyFn(didKeyOf(t, userKey)), Aud: "did:example:other#atproto_space_host"})
	if tokenCode(t, err) != "BadJwtAudience" {
		t.Fatal(err)
	}
	_, err = VerifySpaceToken(TokenDelegation, create(), VerifyTokenOpts{GetSigningKey: keyFn(didKeyOf(t, userKey)), Aud: tSpaceHost, Sub: "at://did:example:space/space/app.bsky.group/other"})
	if tokenCode(t, err) != "BadJwtSub" {
		t.Fatal(err)
	}
	_, err = VerifySpaceToken(TokenDelegation, create(), VerifyTokenOpts{GetSigningKey: keyFn(didKeyOf(t, authorityKey)), Aud: tSpaceHost})
	if tokenCode(t, err) != "BadJwtSignature" {
		t.Fatal(err)
	}
	_, err = VerifySpaceToken(TokenCredential, create(), VerifyTokenOpts{GetSigningKey: keyFn(didKeyOf(t, userKey))})
	if tokenCode(t, err) != "BadJwtType" {
		t.Fatal(err)
	}
}

func TestSpaceCredential(t *testing.T) {
	authorityKey := newK256(t)
	authDid := didKeyOf(t, authorityKey)
	keyID := didKeyOf(t, newP256(t))
	create := func(exp *int64, kid string) (string, error) {
		return CreateSpaceToken(TokenCredential, CreateTokenOpts{Iss: tAuthority, Sub: tSpace, KeyID: keyID, ExpiresInSec: exp, Kid: kid}, authorityKey)
	}
	mustCreate := func(exp *int64, kid string) string {
		jwt, err := create(exp, kid)
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	i64 := func(v int64) *int64 { return &v }

	t.Run("round-trips, defaults to 10 minutes, and carries no aud", func(t *testing.T) {
		tok, err := VerifySpaceToken(TokenCredential, mustCreate(nil, ""), VerifyTokenOpts{GetSigningKey: keyFn(authDid), Sub: tSpace})
		if err != nil {
			t.Fatal(err)
		}
		if tok.Header.Typ != "atproto-space-credential+jwt" || tok.Header.Kid != "#atproto" || tok.Payload.Iss != tAuthority || tok.Payload.Aud != "" || tok.Payload.Exp-tok.Payload.Iat != 600 || !hexJti.MatchString(tok.Payload.Jti) {
			t.Fatalf("%+v", tok)
		}
		if tok.Payload.Cnf == nil || tok.Payload.Cnf.Kid != keyID {
			t.Fatal("not bound to the requested key")
		}
	})
	t.Run("allows a lifetime of 60 minutes", func(t *testing.T) {
		tok, err := VerifySpaceToken(TokenCredential, mustCreate(i64(3600), ""), VerifyTokenOpts{GetSigningKey: keyFn(authDid)})
		if err != nil || tok.Payload.Exp-tok.Payload.Iat != 3600 {
			t.Fatal(err)
		}
	})
	for _, exp := range []int64{0, -1, 3601} {
		if _, err := create(i64(exp), ""); err == nil || !strings.Contains(err.Error(), "invalid space credential lifetime") {
			t.Fatalf("lifetime %d: %v", exp, err)
		}
	}
	for name, claims := range map[string]map[string]any{
		"missing iat":    {"iat": nil},
		"invalid iat":    {"iat": "now"},
		"missing jti":    {"jti": nil},
		"empty jti":      {"jti": ""},
		"non-string jti": {"jti": 123},
	} {
		jwt := withClaims(t, mustCreate(nil, ""), claims, authorityKey)
		_, err := VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: keyFn(authDid)})
		if tokenCode(t, err) != "BadJwt" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	t.Run("rejects a signed credential lasting more than 60 minutes", func(t *testing.T) {
		tok := mustCreate(nil, "")
		parsed, err := ParseSpaceToken(TokenCredential, tok)
		if err != nil {
			t.Fatal(err)
		}
		jwt := withClaims(t, tok, map[string]any{"exp": parsed.Payload.Iat + 3601}, authorityKey)
		_, err = VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: keyFn(authDid)})
		if tokenCode(t, err) != "BadJwt" {
			t.Fatal(err)
		}
	})
	t.Run("rejects future issuance beyond clock skew", func(t *testing.T) {
		iat := time.Now().Unix() + 60
		jwt := withClaims(t, mustCreate(nil, ""), map[string]any{"iat": iat, "exp": iat + 600}, authorityKey)
		_, err := VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: keyFn(authDid)})
		if tokenCode(t, err) != "BadJwt" {
			t.Fatal(err)
		}
	})
	t.Run("requires a keyId at mint time", func(t *testing.T) {
		_, err := CreateSpaceToken(TokenCredential, CreateTokenOpts{Iss: tAuthority, Sub: tSpace}, authorityKey)
		if err == nil || !strings.Contains(err.Error(), `requires a "keyId"`) {
			t.Fatal(err)
		}
	})
	t.Run("is rejected when it carries no binding", func(t *testing.T) {
		unbound, err := CreateSpaceToken(TokenDelegation, CreateTokenOpts{Iss: tAuthority, Sub: tSpace, Aud: tSpaceHost}, authorityKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseSpaceToken(TokenCredential, retype(unbound, TokenSpecs[TokenCredential].Typ))
		if err == nil || !strings.Contains(err.Error(), `missing token "cnf.kid"`) {
			t.Fatal(err)
		}
	})
	t.Run("passes iss and kid to the key resolver, honouring a kid override", func(t *testing.T) {
		for kid, want := range map[string]string{"": "#atproto", "#atproto_space": "#atproto_space"} {
			var gotIss, gotKid string
			var gotForce bool
			_, err := VerifySpaceToken(TokenCredential, mustCreate(nil, kid), VerifyTokenOpts{GetSigningKey: func(iss, kid string, force bool) (string, error) {
				gotIss, gotKid, gotForce = iss, kid, force
				return authDid, nil
			}})
			if err != nil || gotIss != tAuthority || gotKid != want || gotForce {
				t.Fatalf("%v %s %s %v", err, gotIss, gotKid, gotForce)
			}
		}
	})
	t.Run("retries with a freshly resolved key when the signing key has rotated", func(t *testing.T) {
		rotated := newK256(t)
		jwt, _ := CreateSpaceToken(TokenCredential, CreateTokenOpts{Iss: tAuthority, Sub: tSpace, KeyID: keyID}, rotated)
		var calls []bool
		tok, err := VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: func(iss, kid string, force bool) (string, error) {
			calls = append(calls, force)
			if len(calls) == 1 {
				return authDid, nil
			}
			return didKeyOf(t, rotated), nil
		}})
		if err != nil || tok.Payload.Iss != tAuthority || len(calls) != 2 || calls[0] || !calls[1] {
			t.Fatalf("%v %v", err, calls)
		}
	})
	t.Run("does not retry when the resolved key is unchanged", func(t *testing.T) {
		jwt, _ := CreateSpaceToken(TokenCredential, CreateTokenOpts{Iss: tAuthority, Sub: tSpace, KeyID: keyID}, newK256(t))
		n := 0
		_, err := VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: func(string, string, bool) (string, error) {
			n++
			return authDid, nil
		}})
		if tokenCode(t, err) != "BadJwtSignature" || n != 2 {
			t.Fatalf("%v %d", err, n)
		}
	})
	t.Run("rejects an expired credential and tolerates small clock skew", func(t *testing.T) {
		jwt := mustCreate(i64(1), "")
		_, err := VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: keyFn(authDid), Now: time.Now().Add(60 * time.Second)})
		if tokenCode(t, err) != "JwtExpired" {
			t.Fatal(err)
		}
		if _, err := VerifySpaceToken(TokenCredential, jwt, VerifyTokenOpts{GetSigningKey: keyFn(authDid), Now: time.Now().Add(3 * time.Second)}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestClientAttestationToken(t *testing.T) {
	clientKey := newK256(t)
	jwt, err := CreateSpaceToken(TokenClientAttestation, CreateTokenOpts{Iss: tClientID, Sub: tClientID, Aud: tSpaceHost, Kid: "key-1"}, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ParseSpaceToken(TokenClientAttestation, jwt)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header.Typ != "atproto-client-attestation+jwt" || tok.Header.Kid != "key-1" || tok.Payload.Iss != tClientID || tok.Payload.Sub != tClientID || tok.Payload.Aud != tSpaceHost {
		t.Fatalf("%+v", tok)
	}
	bad, _ := CreateSpaceToken(TokenClientAttestation, CreateTokenOpts{Iss: tClientID, Sub: "https://other.example/x", Aud: tSpaceHost}, clientKey)
	if _, err := ParseSpaceToken(TokenClientAttestation, bad); err == nil || !strings.Contains(err.Error(), "must both be the client_id") {
		t.Fatal(err)
	}
	v, err := VerifySpaceToken(TokenClientAttestation, jwt, VerifyTokenOpts{GetSigningKey: keyFn(didKeyOf(t, clientKey)), Aud: tSpaceHost})
	if err != nil || v.Payload.Iss != tClientID {
		t.Fatal(err)
	}
}

func TestMalformedTokens(t *testing.T) {
	for _, jwt := range []string{"nope", "aaa.bbb", "!!!.e30.c2ln"} {
		_, err := ParseSpaceToken(TokenCredential, jwt)
		var te *TokenError
		if !errors.As(err, &te) {
			t.Fatalf("%q: %v", jwt, err)
		}
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256K","typ":"atproto-space-credential+jwt"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"did:example:space"}`))
	if _, err := ParseSpaceToken(TokenCredential, h+"."+p+".c2ln"); err == nil || !strings.Contains(err.Error(), `missing token "sub"`) {
		t.Fatal(err)
	}
}

func TestTokenVectors(t *testing.T) {
	v := loadVectors(t)
	now := time.Unix(v.Now, 0)
	for i, tv := range v.Tokens {
		var opts struct {
			Iss, Sub, Aud, KeyID string
			Kid                  string
		}
		var raw map[string]any
		_ = json.Unmarshal(tv.Opts, &raw)
		opts.Iss, _ = raw["iss"].(string)
		opts.Sub, _ = raw["sub"].(string)
		opts.Aud, _ = raw["aud"].(string)
		opts.KeyID, _ = raw["keyId"].(string)
		opts.Kid, _ = raw["kid"].(string)
		typ := TokenType(tv.Type)
		tok, err := VerifySpaceToken(typ, tv.JWT, VerifyTokenOpts{GetSigningKey: keyFn(tv.SigningKey), Aud: opts.Aud, Sub: opts.Sub, Now: now})
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if tok.Payload.Iss != opts.Iss || tok.Payload.Sub != opts.Sub || tok.Payload.Aud != opts.Aud {
			t.Errorf("vector %d payload %+v", i, tok.Payload)
		}
		if opts.KeyID != "" && (tok.Payload.Cnf == nil || tok.Payload.Cnf.Kid != opts.KeyID) {
			t.Errorf("vector %d cnf", i)
		}
		if opts.Kid != "" && tok.Header.Kid != opts.Kid {
			t.Errorf("vector %d kid %q", i, tok.Header.Kid)
		}
	}
}

func TestTokenResolverErrorsPropagate(t *testing.T) {
	key := newK256(t)
	jwt, _ := CreateSpaceToken(TokenDelegation, CreateTokenOpts{Iss: tUser, Sub: tSpace, Aud: tSpaceHost}, key)
	sentinel := errors.New("no such key")
	_, err := VerifySpaceToken(TokenDelegation, jwt, VerifyTokenOpts{GetSigningKey: func(string, string, bool) (string, error) { return "", sentinel }})
	if !errors.Is(err, sentinel) {
		t.Fatalf("resolver error lost: %v", err)
	}
}
