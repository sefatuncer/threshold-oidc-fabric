// Package jwks generates RFC 7517-compliant JWKS and OIDC Discovery
// JSON from a DKG public key, enabling standard OIDC Relying Parties
// to validate threshold-signed JWTs without modification.
package jwks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
)

// JWK represents a JSON Web Key (RFC 7517) for EC keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKSet represents a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// OIDCDiscovery represents the OpenID Connect Discovery document.
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SupportedAlgs         []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypes         []string `json:"response_types_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
}

// GenerateJWKS creates a RFC 7517-compliant JWKS JSON from a DKG public key.
func GenerateJWKS(publicKey *dkg.Commitment, kid string) ([]byte, error) {
	if publicKey == nil || publicKey.X == nil || publicKey.Y == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// P-256 coordinates are 32 bytes each
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	// Pad to 32 bytes
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	jwkSet := JWKSet{
		Keys: []JWK{{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xPadded),
			Y:   base64.RawURLEncoding.EncodeToString(yPadded),
			Kid: kid,
			Use: "sig",
			Alg: "ES256",
		}},
	}

	return json.MarshalIndent(jwkSet, "", "  ")
}

// GenerateDiscovery creates an OIDC Discovery document.
func GenerateDiscovery(issuer string) ([]byte, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer cannot be empty")
	}

	discovery := OIDCDiscovery{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSURI:               issuer + "/.well-known/jwks.json",
		SupportedAlgs:         []string{"ES256"},
		ResponseTypes:         []string{"code"},
		SubjectTypes:          []string{"public"},
	}

	return json.MarshalIndent(discovery, "", "  ")
}
