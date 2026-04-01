package coordinator

import (
	"crypto/elliptic"
	"testing"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/signing"
)

// setupCoordinator creates a Coordinator with only public DKG info.
// The DKGResult (with shares) stays on the "peer side" — the Coordinator
// receives PublicInfo only and a signing callback.
func setupCoordinator(t *testing.T) (*Coordinator, *dkg.DKGResult) {
	t.Helper()
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	// Coordinator receives ONLY public info — no shares
	publicInfo := dkgResult.PublicInfo()

	// PeerSigningFunc simulates distributed signing (peer-side, has shares)
	peerSign := func(payload *signing.JWTPayload, signerIndices []int) (*signing.SigningResult, error) {
		return signing.ThresholdSign(dkgResult, signerIndices, payload)
	}

	coord := New(publicInfo, "https://threshold-oidc.example.com", peerSign)
	return coord, dkgResult
}

func TestCoordinator_HasNoKeyMaterial(t *testing.T) {
	coord, _ := setupCoordinator(t)
	if coord.HasKeyMaterial() {
		t.Error("Coordinator must NEVER hold key material")
	}
	// Verify PublicInfo contains NO shares (compile-time enforced by type)
	// PublicDKGInfo has PublicKey, Commitments, Params — no Shares field.
	if coord.PublicInfo.PublicKey == nil {
		t.Error("PublicInfo should have a public key")
	}
}

func TestCoordinator_PublicInfoHasNoShares(t *testing.T) {
	// This test verifies the type-level guarantee: PublicDKGInfo cannot
	// hold secret shares because the field does not exist in the struct.
	params := dkg.DefaultParams()
	dkgResult, _ := dkg.SimulateDKG(params)
	publicInfo := dkgResult.PublicInfo()

	// Verify public info has the right data
	if publicInfo.PublicKey == nil {
		t.Error("publicInfo should have public key")
	}
	if len(publicInfo.Commitments) != params.T {
		t.Errorf("expected %d commitments, got %d", params.T, len(publicInfo.Commitments))
	}
	if publicInfo.Params.T != params.T || publicInfo.Params.N != params.N {
		t.Error("params mismatch")
	}
	// Note: There is no publicInfo.Shares field — enforced by Go type system
}

func TestCoordinator_FullFlow(t *testing.T) {
	coord, dkgResult := setupCoordinator(t)

	// 1. Create session
	sessionID := coord.CreateSession("rp-1", "https://rp.example.com/callback", "nonce-123", "state-abc")
	if sessionID == "" {
		t.Fatal("session ID should not be empty")
	}

	// 2. Record peer approvals (need t=3) — all authenticate same user
	userID := "alice@example.com"
	for i := 0; i < 2; i++ {
		reached, err := coord.RecordPeerApproval(sessionID, userID)
		if err != nil {
			t.Fatalf("approval %d failed: %v", i+1, err)
		}
		if reached {
			t.Errorf("threshold should not be reached after %d approvals", i+1)
		}
	}

	// 3. Third approval reaches threshold
	reached, err := coord.RecordPeerApproval(sessionID, userID)
	if err != nil {
		t.Fatalf("approval 3 failed: %v", err)
	}
	if !reached {
		t.Error("threshold should be reached after 3 approvals")
	}

	// 4. Produce token (signing happens peer-side via callback)
	result, err := coord.ProduceToken(sessionID, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("ProduceToken failed: %v", err)
	}
	if result.JWT == "" {
		t.Error("JWT should not be empty")
	}

	// 5. Verify JWT with DKG public key
	if !verifyJWTHelper(result.JWT, dkgResult.PublicKey, dkgResult.Params.Curve) {
		t.Error("JWT should be valid")
	}
}

func verifyJWTHelper(jwt string, pk *dkg.Commitment, curve elliptic.Curve) bool {
	valid, _ := signing.VerifyJWT(jwt, pk, curve)
	return valid
}

func TestCoordinator_CannotForgeToken(t *testing.T) {
	coord, _ := setupCoordinator(t)

	// Try to produce token WITHOUT authentication
	sessionID := coord.CreateSession("rp-1", "https://rp.example.com/cb", "n", "s")
	_, err := coord.ProduceToken(sessionID, []int{1, 2, 3})
	if err == nil {
		t.Error("should not produce token for unauthenticated session")
	}
}

func TestCoordinator_NilSignFuncFails(t *testing.T) {
	params := dkg.DefaultParams()
	dkgResult, _ := dkg.SimulateDKG(params)

	// Create coordinator WITHOUT signing function
	coord := New(dkgResult.PublicInfo(), "https://test.example.com", nil)

	sessionID := coord.CreateSession("rp", "https://rp.example.com/cb", "n", "s")
	for i := 0; i < 3; i++ {
		coord.RecordPeerApproval(sessionID, "user")
	}

	_, err := coord.ProduceToken(sessionID, []int{1, 2, 3})
	if err == nil {
		t.Error("should fail when no peer signing function configured")
	}
}

func TestCoordinator_BindingMismatchRejectsApproval(t *testing.T) {
	coord, _ := setupCoordinator(t)
	sessionID := coord.CreateSession("rp-1", "https://rp.example.com/cb", "n", "s")

	// First peer authenticates alice
	_, err := coord.RecordPeerApproval(sessionID, "alice")
	if err != nil {
		t.Fatalf("first approval failed: %v", err)
	}

	// Second peer authenticates bob — binding hash mismatch
	_, err = coord.RecordPeerApproval(sessionID, "bob")
	if err == nil {
		t.Error("should reject approval with different user (binding mismatch)")
	}
}

func TestCoordinator_InvalidSession(t *testing.T) {
	coord, _ := setupCoordinator(t)
	_, err := coord.RecordPeerApproval("nonexistent", "user")
	if err == nil {
		t.Error("should fail for nonexistent session")
	}
}
