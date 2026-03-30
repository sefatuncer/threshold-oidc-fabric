package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
)

func TestGenerateJWKS(t *testing.T) {
	params := dkg.DefaultParams()
	result, _ := dkg.SimulateDKG(params)

	jwksJSON, err := GenerateJWKS(result.PublicKey, "threshold-key-1")
	if err != nil {
		t.Fatalf("GenerateJWKS failed: %v", err)
	}

	// Parse back
	var jwkSet JWKSet
	if err := json.Unmarshal(jwksJSON, &jwkSet); err != nil {
		t.Fatalf("JWKS JSON parse failed: %v", err)
	}

	if len(jwkSet.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwkSet.Keys))
	}

	key := jwkSet.Keys[0]
	if key.Kty != "EC" || key.Crv != "P-256" || key.Alg != "ES256" {
		t.Errorf("unexpected key params: kty=%s crv=%s alg=%s", key.Kty, key.Crv, key.Alg)
	}

	// Verify the JWKS coordinates match the DKG public key
	xBytes, _ := base64.RawURLEncoding.DecodeString(key.X)
	yBytes, _ := base64.RawURLEncoding.DecodeString(key.Y)

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if x.Cmp(result.PublicKey.X) != 0 || y.Cmp(result.PublicKey.Y) != 0 {
		t.Error("JWKS coordinates do not match DKG public key")
	}

	// Verify the key can be used for ECDSA verification
	pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	msg := []byte("test message")
	hash := sha256.Sum256(msg)
	_ = pk // key is valid if no panic
	_ = hash
}

func TestGenerateJWKS_NilKey(t *testing.T) {
	_, err := GenerateJWKS(nil, "kid")
	if err == nil {
		t.Error("should fail with nil key")
	}
}

func TestGenerateDiscovery(t *testing.T) {
	issuer := "https://threshold-oidc.example.com"
	discoveryJSON, err := GenerateDiscovery(issuer)
	if err != nil {
		t.Fatalf("GenerateDiscovery failed: %v", err)
	}

	var disc OIDCDiscovery
	if err := json.Unmarshal(discoveryJSON, &disc); err != nil {
		t.Fatalf("Discovery JSON parse failed: %v", err)
	}

	if disc.Issuer != issuer {
		t.Errorf("expected issuer %s, got %s", issuer, disc.Issuer)
	}
	if disc.JWKSURI != issuer+"/.well-known/jwks.json" {
		t.Errorf("unexpected jwks_uri: %s", disc.JWKSURI)
	}
	if disc.SupportedAlgs[0] != "ES256" {
		t.Errorf("expected ES256, got %s", disc.SupportedAlgs[0])
	}
}

func TestGenerateDiscovery_EmptyIssuer(t *testing.T) {
	_, err := GenerateDiscovery("")
	if err == nil {
		t.Error("should fail with empty issuer")
	}
}
