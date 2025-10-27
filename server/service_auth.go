package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/identity"
	atproto_identity "github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/golang-jwt/jwt/v4"
)

type ES256KSigningMethod struct {
	alg string
}

func (m *ES256KSigningMethod) Alg() string {
	return m.alg
}

func (m *ES256KSigningMethod) Verify(signingString string, signature string, key interface{}) error {
	signatureBytes, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	return key.(atcrypto.PublicKey).HashAndVerifyLenient([]byte(signingString), signatureBytes)
}

func (m *ES256KSigningMethod) Sign(signingString string, key interface{}) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

func init() {
	ES256K := ES256KSigningMethod{alg: "ES256K"}
	jwt.RegisterSigningMethod(ES256K.Alg(), func() jwt.SigningMethod {
		return &ES256K
	})
}

func (s *Server) validateServiceAuth(ctx context.Context, rawToken string, nsid string) (string, error) {
	token := strings.TrimSpace(rawToken)

	parsedToken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		did := syntax.DID(token.Claims.(jwt.MapClaims)["iss"].(string))
		didDoc, err := s.passport.FetchDoc(ctx, did.String());
		if err != nil {
			return nil, fmt.Errorf("unable to resolve did %s: %s", did, err)
		}

		verificationMethods := make([]atproto_identity.DocVerificationMethod, len(didDoc.VerificationMethods))
		for i, verificationMethod := range didDoc.VerificationMethods {
			verificationMethods[i] = atproto_identity.DocVerificationMethod{
				ID: verificationMethod.Id,
				Type: verificationMethod.Type,
				PublicKeyMultibase: verificationMethod.PublicKeyMultibase,
				Controller: verificationMethod.Controller,
			}
		}
		services := make([]atproto_identity.DocService, len(didDoc.Service))
		for i, service := range didDoc.Service {
			services[i] = atproto_identity.DocService{
				ID: service.Id,
				Type: service.Type,
				ServiceEndpoint: service.ServiceEndpoint,
			}
		}
		parsedIdentity := atproto_identity.ParseIdentity(&identity.DIDDocument{
			DID: did,
			AlsoKnownAs: didDoc.AlsoKnownAs,
			VerificationMethod: verificationMethods,
			Service: services,
		})

		key, err := parsedIdentity.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("signing key not found for did %s: %s", did, err)
		}
		return key, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid token: %s", err)
	}

	claims := parsedToken.Claims.(jwt.MapClaims)
	if claims["lxm"] != nsid {
		return "", fmt.Errorf("bad jwt lexicon method (\"lxm\"). must match: %s", nsid)
	}
	return claims["iss"].(string), nil
}