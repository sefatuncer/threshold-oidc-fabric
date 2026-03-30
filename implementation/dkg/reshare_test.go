package dkg

import (
	"testing"
)

func TestReshare_AfterDisable(t *testing.T) {
	// Original DKG: (3,5)
	params := DefaultParams()
	original, err := SimulateDKG(params)
	if err != nil {
		t.Fatalf("original DKG failed: %v", err)
	}

	// Disable peer 3 → reshare among 4 remaining peers
	reshared, err := Reshare(original, 3)
	if err != nil {
		t.Fatalf("reshare failed: %v", err)
	}

	// New DKG should have n-1=4 peers, same threshold t=3
	if reshared.Params.N != 4 {
		t.Errorf("expected 4 peers after reshare, got %d", reshared.Params.N)
	}
	if reshared.Params.T != 3 {
		t.Errorf("threshold should remain 3, got %d", reshared.Params.T)
	}

	// New public key should be different from old
	if reshared.PublicKey.X.Cmp(original.PublicKey.X) == 0 &&
		reshared.PublicKey.Y.Cmp(original.PublicKey.Y) == 0 {
		t.Error("new public key should differ from old after reshare")
	}

	// All new shares should verify
	for _, share := range reshared.Shares {
		if !VerifyShare(share, reshared.Commitments, reshared.Params.Curve) {
			t.Errorf("reshared share %d failed verification", share.Index)
		}
	}
}

func TestReshare_InsufficientPeers(t *testing.T) {
	// (3,3) → disable 1 → only 2 remain < t=3
	params := Params{T: 3, N: 3, Curve: DefaultParams().Curve}
	result, _ := SimulateDKG(params)

	_, err := Reshare(result, 1)
	if err == nil {
		t.Error("reshare should fail when remaining peers < threshold")
	}
}
