// Package signing implements threshold ECDSA signing simulation for
// generating ES256-signed JWTs. This PoC demonstrates that t-of-n
// partial signatures can be combined into a valid ECDSA signature
// verifiable by standard JWT libraries.
//
// NOTE: This uses Shamir's Secret Sharing for key reconstruction
// simulation. A production system would use CGGMP21's MPC-based
// signing (no key reconstruction).
package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
)

// JWTHeader represents the JWT header for ES256.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWTPayload represents OIDC ID Token claims.
type JWTPayload struct {
	Iss            string `json:"iss"`
	Sub            string `json:"sub"`
	Aud            string `json:"aud"`
	Exp            int64  `json:"exp"`
	Iat            int64  `json:"iat"`
	Nonce          string `json:"nonce"`
	AuthTime       int64  `json:"auth_time"`
	Amr            []string `json:"amr"`
	ThresholdPeers int    `json:"threshold_peers"`
}

// SigningResult contains the output of threshold signing.
type SigningResult struct {
	JWT       string        // Complete JWT string
	R, S      *big.Int      // ECDSA signature components
	Duration  time.Duration // Signing duration
	PeersUsed int           // Number of peers that participated
}

// ThresholdSign produces an ES256-signed JWT using threshold signing simulation.
//
// IMPORTANT LIMITATION: This PoC reconstructs the secret key via Lagrange
// interpolation, which defeats the purpose of threshold signing in production.
// A real implementation MUST use CGGMP21 MPC-based signing where the key is
// NEVER reconstructed. This simulation demonstrates:
//   - Correctness: any t-of-n share subset produces a valid ES256 signature
//   - JWT compatibility: output is a standard JWT verifiable by any OIDC library
//   - Feldman VSS: share verification against commitments works
//
// Benchmark results from this simulation measure only the cryptographic
// computation cost, NOT the end-to-end latency of a distributed MPC protocol
// (which would add network RTT, typically 100-500ms for real deployments).
func ThresholdSign(dkgResult *dkg.DKGResult, signerIndices []int, payload *JWTPayload) (*SigningResult, error) {
	start := time.Now()
	curve := dkgResult.Params.Curve
	order := curve.Params().N
	t := dkgResult.Params.T

	if len(signerIndices) < t {
		return nil, fmt.Errorf("need at least %d signers, got %d", t, len(signerIndices))
	}

	// Use only t signers (first t from the provided indices)
	activeSigners := signerIndices[:t]

	// Check for duplicate signer indices (would cause ModInverse panic)
	seen := make(map[int]bool)
	for _, idx := range activeSigners {
		if seen[idx] {
			return nil, fmt.Errorf("duplicate signer index: %d", idx)
		}
		seen[idx] = true
	}

	// Collect shares for active signers
	shares := make([]*dkg.Share, t)
	for i, idx := range activeSigners {
		if idx < 1 || idx > dkgResult.Params.N {
			return nil, fmt.Errorf("invalid signer index: %d", idx)
		}
		shares[i] = dkgResult.Shares[idx-1]
	}

	// Lagrange interpolation to reconstruct secret key
	// sk = sum(share_i * lambda_i) where lambda_i = product(j/(j-i)) for j != i
	sk := new(big.Int)
	for i, share := range shares {
		lambda := lagrangeCoefficient(activeSigners, i, order)
		term := new(big.Int).Mul(share.Value, lambda)
		term.Mod(term, order)
		sk.Add(sk, term)
		sk.Mod(sk, order)
	}

	// Reconstruct the private key
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     dkgResult.PublicKey.X,
			Y:     dkgResult.PublicKey.Y,
		},
		D: sk,
	}

	// Build JWT
	header := JWTHeader{Alg: "ES256", Typ: "JWT", Kid: "threshold-key-1"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("header marshal failed: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("payload marshal failed: %w", err)
	}

	headerB64 := base64URLEncode(headerJSON)
	payloadB64 := base64URLEncode(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	// Sign with ECDSA (ES256 = ECDSA + P-256 + SHA-256)
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}

	// Encode signature as JWS (R || S, each 32 bytes for P-256)
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	sigB64 := base64URLEncode(sigBytes)

	jwt := signingInput + "." + sigB64

	return &SigningResult{
		JWT:       jwt,
		R:         r,
		S:         s,
		Duration:  time.Since(start),
		PeersUsed: t,
	}, nil
}

// VerifyJWT verifies a JWT signature using the DKG public key.
func VerifyJWT(jwt string, publicKey *dkg.Commitment, curve elliptic.Curve) (bool, error) {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return false, fmt.Errorf("signature decode failed: %w", err)
	}

	if len(sigBytes) != 64 {
		return false, fmt.Errorf("invalid signature length: expected 64, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     publicKey.X,
		Y:     publicKey.Y,
	}

	hash := sha256.Sum256([]byte(signingInput))
	return ecdsa.Verify(pk, hash[:], r, s), nil
}

// ValidatePayload checks OIDC mandatory claims.
func ValidatePayload(p *JWTPayload) error {
	if p.Iss == "" {
		return fmt.Errorf("iss (issuer) is required")
	}
	if p.Sub == "" {
		return fmt.Errorf("sub (subject) is required")
	}
	if p.Aud == "" {
		return fmt.Errorf("aud (audience) is required")
	}
	if p.Exp == 0 {
		return fmt.Errorf("exp (expiration) is required")
	}
	if p.Exp <= time.Now().Unix() {
		return fmt.Errorf("exp is in the past")
	}
	return nil
}

// VerifyJWTWithClaims verifies signature AND checks temporal claims.
func VerifyJWTWithClaims(jwtStr string, expectedNonce string, publicKey *dkg.Commitment, curve elliptic.Curve) (bool, error) {
	// 1. Verify signature
	valid, err := VerifyJWT(jwtStr, publicKey, curve)
	if err != nil || !valid {
		return false, err
	}

	// 2. Decode payload and check claims
	parts := strings.SplitN(jwtStr, ".", 3)
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return false, fmt.Errorf("payload decode failed: %w", err)
	}

	var payload JWTPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false, fmt.Errorf("payload unmarshal failed: %w", err)
	}

	// Check expiration
	if payload.Exp <= time.Now().Unix() {
		return false, fmt.Errorf("token expired")
	}

	// Check nonce if provided
	if expectedNonce != "" && payload.Nonce != expectedNonce {
		return false, fmt.Errorf("nonce mismatch: expected %s, got %s", expectedNonce, payload.Nonce)
	}

	return true, nil
}

// lagrangeCoefficient computes the Lagrange basis polynomial at x=0
// for the i-th signer in the activeSigners list.
func lagrangeCoefficient(signerIndices []int, i int, order *big.Int) *big.Int {
	xi := big.NewInt(int64(signerIndices[i]))
	num := big.NewInt(1)
	den := big.NewInt(1)

	for j, idx := range signerIndices {
		if j == i {
			continue
		}
		xj := big.NewInt(int64(idx))

		// numerator *= -xj = (order - xj)
		negXj := new(big.Int).Sub(order, xj)
		num.Mul(num, negXj)
		num.Mod(num, order)

		// denominator *= (xi - xj)
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, order)
		den.Mul(den, diff)
		den.Mod(den, order)
	}

	// lambda = num * den^{-1} mod order
	denInv := new(big.Int).ModInverse(den, order)
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, order)
	return lambda
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
