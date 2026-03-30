package signing

import (
	"crypto/elliptic"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
)

func TestThresholdSign(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	payload := &JWTPayload{
		Iss:            "https://threshold-oidc.example.com",
		Sub:            "user-12345",
		Aud:            "rp-client-1",
		Exp:            time.Now().Add(1 * time.Hour).Unix(),
		Iat:            time.Now().Unix(),
		Nonce:          "test-nonce-abc",
		AuthTime:       time.Now().Unix(),
		Amr:            []string{"pwd", "otp"},
		ThresholdPeers: params.T,
	}

	// Sign with peers 1, 2, 3 (t=3)
	result, err := ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if result.JWT == "" {
		t.Error("JWT should not be empty")
	}

	t.Logf("JWT length: %d", len(result.JWT))
	t.Logf("Signing duration: %v", result.Duration)

	// Verify the JWT
	valid, err := VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if !valid {
		t.Error("JWT signature should be valid")
	}
}

func TestThresholdSign_DifferentSignerSets(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	payload := &JWTPayload{
		Iss:            "https://threshold-oidc.example.com",
		Sub:            "user-99",
		Aud:            "rp-2",
		Exp:            time.Now().Add(1 * time.Hour).Unix(),
		Iat:            time.Now().Unix(),
		Nonce:          "nonce-xyz",
		AuthTime:       time.Now().Unix(),
		Amr:            []string{"pwd"},
		ThresholdPeers: params.T,
	}

	// Different t-sized subsets should all produce valid signatures
	signerSets := [][]int{
		{1, 2, 3},
		{1, 3, 5},
		{2, 4, 5},
		{1, 2, 4},
		{3, 4, 5},
	}

	for _, signers := range signerSets {
		result, err := ThresholdSign(dkgResult, signers, payload)
		if err != nil {
			t.Errorf("signing with %v failed: %v", signers, err)
			continue
		}

		valid, err := VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
		if err != nil {
			t.Errorf("verification with signers %v error: %v", signers, err)
			continue
		}
		if !valid {
			t.Errorf("JWT from signers %v should be valid", signers)
		}
	}
}

func TestThresholdSign_InsufficientSigners(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	payload := &JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "user-1",
		Aud: "rp-1",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}

	// Only 2 signers (t=3 required) should fail
	_, err = ThresholdSign(dkgResult, []int{1, 2}, payload)
	if err == nil {
		t.Error("signing with fewer than t signers should fail")
	}
}

func TestThresholdSign_TEqualsN(t *testing.T) {
	// t=n means ALL peers must sign (zero fault tolerance)
	params := dkg.Params{T: 3, N: 3, Curve: elliptic.P256()}
	dkgResult, _ := dkg.SimulateDKG(params)
	payload := &JWTPayload{
		Iss: "https://test.com", Sub: "u1", Aud: "rp1",
		Exp: time.Now().Add(1 * time.Hour).Unix(), Iat: time.Now().Unix(),
	}
	result, err := ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
	if err != nil {
		t.Fatalf("t=n signing failed: %v", err)
	}
	valid, _ := VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
	if !valid {
		t.Error("t=n JWT should be valid")
	}
}

func TestThresholdSign_DuplicateSignerIndex(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, _ := dkg.SimulateDKG(params)
	payload := &JWTPayload{
		Iss: "https://test.com", Sub: "u1", Aud: "rp1",
		Exp: time.Now().Add(1 * time.Hour).Unix(), Iat: time.Now().Unix(),
	}
	_, err := ThresholdSign(dkgResult, []int{1, 1, 3}, payload)
	if err == nil {
		t.Error("duplicate signer index should be rejected")
	}
}

func TestValidatePayload(t *testing.T) {
	// Valid payload
	valid := &JWTPayload{
		Iss: "https://test.com", Sub: "u1", Aud: "rp1",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
	}
	if err := ValidatePayload(valid); err != nil {
		t.Errorf("valid payload rejected: %v", err)
	}

	// Missing iss
	noIss := &JWTPayload{Sub: "u1", Aud: "rp1", Exp: time.Now().Add(1 * time.Hour).Unix()}
	if err := ValidatePayload(noIss); err == nil {
		t.Error("missing iss should fail")
	}

	// Expired
	expired := &JWTPayload{
		Iss: "https://test.com", Sub: "u1", Aud: "rp1",
		Exp: time.Now().Add(-1 * time.Hour).Unix(),
	}
	if err := ValidatePayload(expired); err == nil {
		t.Error("expired payload should fail")
	}
}

func TestVerifyJWTWithClaims(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, _ := dkg.SimulateDKG(params)
	nonce := "test-nonce-xyz"
	payload := &JWTPayload{
		Iss: "https://test.com", Sub: "u1", Aud: "rp1",
		Exp: time.Now().Add(1 * time.Hour).Unix(), Iat: time.Now().Unix(),
		Nonce: nonce,
	}
	result, _ := ThresholdSign(dkgResult, []int{1, 2, 3}, payload)

	// Correct nonce
	valid, err := VerifyJWTWithClaims(result.JWT, nonce, dkgResult.PublicKey, params.Curve)
	if err != nil || !valid {
		t.Errorf("valid JWT with correct nonce should pass: %v", err)
	}

	// Wrong nonce
	_, err = VerifyJWTWithClaims(result.JWT, "wrong-nonce", dkgResult.PublicKey, params.Curve)
	if err == nil {
		t.Error("wrong nonce should fail")
	}
}

func TestConcurrentSigning(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, _ := dkg.SimulateDKG(params)

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := &JWTPayload{
				Iss: "https://test.com", Sub: fmt.Sprintf("user-%d", idx), Aud: "rp1",
				Exp: time.Now().Add(1 * time.Hour).Unix(), Iat: time.Now().Unix(),
			}
			result, err := ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d sign failed: %v", idx, err)
				return
			}
			valid, err := VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
			if err != nil || !valid {
				errors <- fmt.Errorf("goroutine %d verify failed", idx)
			}
		}(i)
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func BenchmarkThresholdSign(b *testing.B) {
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		b.Fatalf("DKG failed: %v", err)
	}

	payload := &JWTPayload{
		Iss:            "https://threshold-oidc.example.com",
		Sub:            "user-bench",
		Aud:            "rp-bench",
		Exp:            time.Now().Add(1 * time.Hour).Unix(),
		Iat:            time.Now().Unix(),
		Nonce:          "bench-nonce",
		ThresholdPeers: params.T,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
	}
}

func BenchmarkDKG(b *testing.B) {
	params := dkg.DefaultParams()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dkg.SimulateDKG(params)
	}
}
