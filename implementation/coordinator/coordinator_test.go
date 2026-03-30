package coordinator

import (
	"crypto/elliptic"
	"testing"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/signing"
)

func setupCoordinator(t *testing.T) *Coordinator {
	params := dkg.DefaultParams()
	dkgResult, err := dkg.SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	return New(dkgResult, "https://threshold-oidc.example.com")
}

func TestCoordinator_HasNoKeyMaterial(t *testing.T) {
	coord := setupCoordinator(t)
	if coord.HasKeyMaterial() {
		t.Error("Coordinator must NEVER hold key material")
	}
}

func TestCoordinator_FullFlow(t *testing.T) {
	coord := setupCoordinator(t)

	// 1. Create session
	sessionID := coord.CreateSession("rp-1", "https://rp.example.com/callback", "nonce-123", "state-abc")
	if sessionID == "" {
		t.Fatal("session ID should not be empty")
	}

	// 2. Record peer approvals (need t=3)
	for i := 0; i < 2; i++ {
		reached, err := coord.RecordPeerApproval(sessionID)
		if err != nil {
			t.Fatalf("approval %d failed: %v", i+1, err)
		}
		if reached {
			t.Errorf("threshold should not be reached after %d approvals", i+1)
		}
	}

	// 3. Third approval reaches threshold
	reached, err := coord.RecordPeerApproval(sessionID)
	if err != nil {
		t.Fatalf("approval 3 failed: %v", err)
	}
	if !reached {
		t.Error("threshold should be reached after 3 approvals")
	}

	// 4. Produce token
	result, err := coord.ProduceToken(sessionID, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("ProduceToken failed: %v", err)
	}
	if result.JWT == "" {
		t.Error("JWT should not be empty")
	}

	// 5. Verify JWT with DKG public key
	if !verifyJWTHelper(result.JWT, coord.DKGResult.PublicKey, coord.DKGResult.Params.Curve) {
		t.Error("JWT should be valid")
	}
}

func verifyJWTHelper(jwt string, pk *dkg.Commitment, curve elliptic.Curve) bool {
	valid, _ := signing.VerifyJWT(jwt, pk, curve)
	return valid
}

func TestCoordinator_CannotForgeToken(t *testing.T) {
	coord := setupCoordinator(t)

	// Try to produce token WITHOUT authentication
	sessionID := coord.CreateSession("rp-1", "https://rp.example.com/cb", "n", "s")
	_, err := coord.ProduceToken(sessionID, []int{1, 2, 3})
	if err == nil {
		t.Error("should not produce token for unauthenticated session")
	}
}

func TestCoordinator_InvalidSession(t *testing.T) {
	coord := setupCoordinator(t)
	_, err := coord.RecordPeerApproval("nonexistent")
	if err == nil {
		t.Error("should fail for nonexistent session")
	}
}
