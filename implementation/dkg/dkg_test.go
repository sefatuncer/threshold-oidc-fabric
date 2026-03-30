package dkg

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestSimulateDKG(t *testing.T) {
	params := DefaultParams() // (3, 5) on P-256
	result, err := SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	// Check we got the right number of shares
	if len(result.Shares) != params.N {
		t.Errorf("expected %d shares, got %d", params.N, len(result.Shares))
	}

	// Check we got the right number of commitments
	if len(result.Commitments) != params.T {
		t.Errorf("expected %d commitments, got %d", params.T, len(result.Commitments))
	}

	// Public key should be on the curve
	if !params.Curve.IsOnCurve(result.PublicKey.X, result.PublicKey.Y) {
		t.Error("public key is not on the curve")
	}

	// All shares should be non-zero
	for i, share := range result.Shares {
		if share.Value.Sign() == 0 {
			t.Errorf("share %d has zero value", i)
		}
	}
}

func TestVerifyShare(t *testing.T) {
	params := DefaultParams()
	result, err := SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	// All honest shares should verify
	for _, share := range result.Shares {
		if !VerifyShare(share, result.Commitments, params.Curve) {
			t.Errorf("honest share %d failed verification", share.Index)
		}
	}
}

func TestVerifyShare_InvalidShare(t *testing.T) {
	params := DefaultParams()
	result, err := SimulateDKG(params)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	// Tamper with a share (simulate M1 misbehavior)
	tamperedShare := &Share{
		Index: result.Shares[0].Index,
		Value: new(big.Int).Add(result.Shares[0].Value, big.NewInt(1)),
	}

	// Tampered share should NOT verify
	if VerifyShare(tamperedShare, result.Commitments, params.Curve) {
		t.Error("tampered share should not pass verification")
	}
}

func TestDKGDifferentParams(t *testing.T) {
	testCases := []struct {
		name string
		t, n int
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"4-of-7", 4, 7},
		{"5-of-9", 5, 9},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := Params{T: tc.t, N: tc.n, Curve: elliptic.P256()}
			result, err := SimulateDKG(params)
			if err != nil {
				t.Fatalf("DKG failed: %v", err)
			}

			// Verify all shares
			for _, share := range result.Shares {
				if !VerifyShare(share, result.Commitments, params.Curve) {
					t.Errorf("share %d failed verification", share.Index)
				}
			}
		})
	}
}

func TestSimulateDKG_InvalidParams(t *testing.T) {
	testCases := []struct {
		name string
		t, n int
	}{
		{"t-greater-than-n", 5, 3},
		{"t-less-than-2", 1, 3},
		{"t-equals-1", 1, 5},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := Params{T: tc.t, N: tc.n, Curve: elliptic.P256()}
			_, err := SimulateDKG(params)
			if err == nil {
				t.Errorf("DKG should fail for t=%d, n=%d", tc.t, tc.n)
			}
		})
	}
}
