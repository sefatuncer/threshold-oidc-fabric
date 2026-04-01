// Package integration provides end-to-end tests that exercise the full
// Threshold-OIDC + Accountability Protocol pipeline:
//   Scenario 1: Normal flow (DKG → Sign → Verify)
//   Scenario 2: Misbehavior flow (DKG → Sign → Detect → Evidence → Sanction)
//   Scenario 3: Availability (t-1 peers down, system still works)
package integration

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/chaincode"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/signing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1: Normal Flow — Happy Path
// DKG → Authentication (simulated) → Threshold Signing → JWT Verify
// ─────────────────────────────────────────────────────────────────────────────

func TestScenario1_NormalFlow(t *testing.T) {
	t.Log("=== Scenario 1: Normal Flow (Happy Path) ===")

	// Phase 1: DKG — generate (3,5) threshold key
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("Phase 1 (DKG) failed: %v", err)
	}
	t.Logf("Phase 1: DKG complete. pk=(%s..., %s...)",
		dkgResult.PublicKey.X.Text(16)[:16],
		dkgResult.PublicKey.Y.Text(16)[:16])

	// Verify all shares against Feldman commitments
	for _, share := range dkgResult.Shares {
		if !dkg.VerifyShare(share, dkgResult.Commitments, params.Curve) {
			t.Fatalf("Phase 1: Share %d failed Feldman verification", share.Index)
		}
	}
	t.Logf("Phase 1: All %d shares verified against Feldman commitments", params.N)

	// Phase 2: Authentication (simulated — not implemented in PoC)
	t.Log("Phase 2: Authentication simulated (t=3 peers approve)")

	// Phase 3: Threshold Signing — peers 1, 3, 5 sign
	payload := &signing.JWTPayload{
		Iss:            "https://threshold-oidc.example.com",
		Sub:            "user-alice-12345",
		Aud:            "relying-party-app",
		Exp:            time.Now().Add(1 * time.Hour).Unix(),
		Iat:            time.Now().Unix(),
		Nonce:          "e2e-nonce-abc123",
		AuthTime:       time.Now().Unix(),
		Amr:            []string{"pwd", "otp"},
		ThresholdPeers: params.T,
	}

	sigResult, err := signing.ThresholdSign(dkgResult, []int{1, 3, 5}, payload)
	if err != nil {
		t.Fatalf("Phase 3 (Signing) failed: %v", err)
	}
	t.Logf("Phase 3: JWT signed by peers [1,3,5] in %v", sigResult.Duration)
	t.Logf("Phase 3: JWT length=%d bytes", len(sigResult.JWT))

	// Phase 4: Token Delivery + RP Verification
	valid, err := signing.VerifyJWT(sigResult.JWT, dkgResult.PublicKey, params.Curve)
	if err != nil {
		t.Fatalf("Phase 4 (Verify) error: %v", err)
	}
	if !valid {
		t.Fatal("Phase 4: JWT verification FAILED — token is invalid")
	}
	t.Log("Phase 4: JWT verified successfully with threshold public key")
	t.Log("=== Scenario 1: PASS — Normal flow works end-to-end ===")
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2: Misbehavior Flow
// DKG → Signing with invalid σ_i → Detect → Evidence → Record → Sanction
// ─────────────────────────────────────────────────────────────────────────────

func TestScenario2_MisbehaviorFlow(t *testing.T) {
	t.Log("=== Scenario 2: Misbehavior Detection + Accountability ===")

	// Phase 1: DKG
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	// Simulate P3 sending an invalid partial signature (M1 misbehavior)
	// Detection: P3's share is tampered, fails Feldman verification
	tamperedShare := &dkg.Share{
		Index: 3,
		Value: new(big.Int).Add(dkgResult.Shares[2].Value, big.NewInt(42)),
	}

	// Step 1: Detection via Feldman VSS
	isValid := dkg.VerifyShare(tamperedShare, dkgResult.Commitments, params.Curve)
	if isValid {
		t.Fatal("Tampered share should NOT pass Feldman verification")
	}
	t.Log("Step 1: Misbehavior DETECTED — P3's share fails Feldman VSS verification")

	// Verify honest share still passes (no false positive)
	honestValid := dkg.VerifyShare(dkgResult.Shares[2], dkgResult.Commitments, params.Curve)
	if !honestValid {
		t.Fatal("Honest P3 share should pass verification — false positive detected!")
	}
	t.Log("Step 1: Honest P3 share verified OK — zero false positives confirmed")

	// Step 2: Evidence generation with real cryptographic data
	// The chaincode will independently re-verify the share against commitments.
	evidence := chaincode.EvidencePackage{
		EvidenceID:  "ev-e2e-001",
		Type:        chaincode.M1InvalidSignature,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		AccusedPeer: "P_3",
		SessionID:   "sess-e2e-001",
		Evidence: chaincode.CryptoEvidence{
			ShareValueHex:       hex.EncodeToString(tamperedShare.Value.Bytes()),
			CommitmentPointsHex: commitmentPointsHex(dkgResult.Commitments),
			Message:             "jwt-signing-input-e2e",
			PeerIndex:           3,
		},
		Witnesses: []chaincode.Witness{
			{PeerID: "P_1", Attestation: "Verified σ_3 failed against commitments", Signature: "sig_P1"},
			{PeerID: "P_2", Attestation: "Verified σ_3 failed against commitments", Signature: "sig_P2"},
			{PeerID: "P_4", Attestation: "Verified σ_3 failed against commitments", Signature: "sig_P4"},
		},
	}
	t.Logf("Step 2: Evidence package created with %d witnesses", len(evidence.Witnesses))

	// Step 3: Blockchain record (using in-memory store)
	store := chaincode.NewMemoryStore()
	contract := chaincode.NewAccountabilityContract(store)

	evidenceJSON, _ := json.Marshal(evidence)
	err = contract.RecordMisbehavior(string(evidenceJSON))
	if err != nil {
		t.Fatalf("Step 3: RecordMisbehavior failed: %v", err)
	}
	t.Log("Step 3: Evidence recorded on ledger (in-memory simulation)")

	// Check peer status after 1 strike
	status, _ := contract.GetPeerStatus("P_3")
	if status.Status != chaincode.StatusWarning {
		t.Errorf("After 1 M1 strike: expected WARNING, got %s", status.Status)
	}
	t.Logf("Step 3: P_3 status = %s (1 strike)", status.Status)

	// Record 2 more strikes to trigger DISABLED
	for i := 2; i <= 3; i++ {
		evidence.EvidenceID = fmt.Sprintf("ev-e2e-%03d", i)
		evidenceJSON, _ = json.Marshal(evidence)
		contract.RecordMisbehavior(string(evidenceJSON))
	}

	status, _ = contract.GetPeerStatus("P_3")
	if status.Status != chaincode.StatusDisabled {
		t.Errorf("After 3 M1 strikes: expected DISABLED, got %s", status.Status)
	}
	t.Logf("Step 4: P_3 DISABLED after 3 strikes. Reason: %s", status.DisabledReason)

	// Verify signing still works with remaining peers (P1, P2, P4 — without P3)
	payload := &signing.JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "user-bob",
		Aud: "rp-1",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}
	sigResult, err := signing.ThresholdSign(dkgResult, []int{1, 2, 4}, payload)
	if err != nil {
		t.Fatalf("Signing without P3 failed: %v", err)
	}
	valid, _ := signing.VerifyJWT(sigResult.JWT, dkgResult.PublicKey, params.Curve)
	if !valid {
		t.Fatal("JWT from remaining peers should be valid")
	}
	t.Log("Step 5: System continues operating without P3 — JWT valid")
	t.Log("=== Scenario 2: PASS — Full accountability pipeline works ===")
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3: Availability — t-1 peers offline, system still works
// ─────────────────────────────────────────────────────────────────────────────

func TestScenario3_Availability(t *testing.T) {
	t.Log("=== Scenario 3: Availability Under Failure ===")

	params := dkg.DefaultParams() // (3,5)
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	payload := &signing.JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "user-charlie",
		Aud: "rp-availability",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}

	// t-1 = 2 peers offline → 3 peers remain → should work (t=3)
	t.Log("Simulating 2 peers offline (P4, P5). Remaining: P1, P2, P3")

	result, err := signing.ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
	if err != nil {
		t.Fatalf("Signing with 3 peers (2 offline) failed: %v", err)
	}
	valid, _ := signing.VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
	if !valid {
		t.Fatal("JWT should be valid with exactly t peers")
	}
	t.Log("OK: System works with exactly t=3 peers (2 offline)")

	// t peers offline → only 2 remain → should FAIL
	t.Log("Simulating 3 peers offline. Remaining: P1, P2 (< t=3)")
	_, err = signing.ThresholdSign(dkgResult, []int{1, 2}, payload)
	if err == nil {
		t.Fatal("Signing should fail with fewer than t peers")
	}
	t.Logf("OK: System correctly refuses to sign with %d < t=%d peers: %v", 2, params.T, err)

	t.Log("=== Scenario 3: PASS — Availability guarantees hold ===")
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark: Different (t,n) configurations
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkDKG_Configurations(b *testing.B) {
	configs := []struct {
		name string
		t, n int
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"4-of-7", 4, 7},
		{"5-of-9", 5, 9},
		{"7-of-13", 7, 13},
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			params := dkg.Params{T: cfg.t, N: cfg.n, Curve: elliptic.P256()}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dkg.SimulateDKG(params)
			}
		})
	}
}

func BenchmarkSigning_Configurations(b *testing.B) {
	configs := []struct {
		name    string
		t, n    int
		signers []int
	}{
		{"2-of-3", 2, 3, []int{1, 2}},
		{"3-of-5", 3, 5, []int{1, 2, 3}},
		{"4-of-7", 4, 7, []int{1, 2, 3, 4}},
		{"5-of-9", 5, 9, []int{1, 2, 3, 4, 5}},
		{"7-of-13", 7, 13, []int{1, 2, 3, 4, 5, 6, 7}},
	}

	payload := &signing.JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "bench-user",
		Aud: "bench-rp",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}

	for _, cfg := range configs {
		b.Run(cfg.name, func(b *testing.B) {
			params := dkg.Params{T: cfg.t, N: cfg.n, Curve: elliptic.P256()}
			dkgResult, _ := dkg.SimulateDKG(params)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				signing.ThresholdSign(dkgResult, cfg.signers, payload)
			}
		})
	}
}

func BenchmarkAccountability_RecordMisbehavior(b *testing.B) {
	// Use real DKG result for cryptographic re-verification benchmark
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		b.Fatalf("DKG failed: %v", err)
	}

	// Tamper share to create valid M1 evidence
	tamperedValue := new(big.Int).Add(dkgResult.Shares[2].Value, big.NewInt(42))
	tamperedValue.Mod(tamperedValue, params.Curve.Params().N)

	evidence := chaincode.EvidencePackage{
		EvidenceID:  "ev-bench",
		Type:        chaincode.M1InvalidSignature,
		Timestamp:   "2026-03-30T12:00:00Z",
		AccusedPeer: "P_3",
		SessionID:   "sess-bench",
		Evidence: chaincode.CryptoEvidence{
			ShareValueHex:       hex.EncodeToString(tamperedValue.Bytes()),
			CommitmentPointsHex: commitmentPointsHex(dkgResult.Commitments),
			Message:             "jwt-signing-input",
			PeerIndex:           3,
		},
		Witnesses: []chaincode.Witness{
			{PeerID: "P_1", Signature: "sig1"},
			{PeerID: "P_2", Signature: "sig2"},
		},
	}
	evidenceJSON, _ := json.Marshal(evidence)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store := chaincode.NewMemoryStore()
		contract := chaincode.NewAccountabilityContract(store)
		contract.RecordMisbehavior(string(evidenceJSON))
	}
}

// commitmentPointsHex converts DKG commitments to hex-encoded pairs for CryptoEvidence.
func commitmentPointsHex(comms []dkg.Commitment) [][2]string {
	result := make([][2]string, len(comms))
	for i, c := range comms {
		result[i] = [2]string{
			hex.EncodeToString(c.X.Bytes()),
			hex.EncodeToString(c.Y.Bytes()),
		}
	}
	return result
}
