package dkg

import (
	"fmt"
)

// Reshare simulates key refresh after a peer is disabled.
// In production, CGGMP21 proactive resharing would be used.
// This PoC generates a new DKG among the remaining peers,
// producing a new public key and new shares.
func Reshare(oldResult *DKGResult, disabledPeerIndex int) (*DKGResult, error) {
	if disabledPeerIndex < 1 || disabledPeerIndex > oldResult.Params.N {
		return nil, fmt.Errorf("invalid peer index: %d", disabledPeerIndex)
	}

	newN := oldResult.Params.N - 1
	newT := oldResult.Params.T
	if newN < newT {
		return nil, fmt.Errorf("cannot reshare: remaining peers %d < threshold %d", newN, newT)
	}

	newParams := Params{
		T:     newT,
		N:     newN,
		Curve: oldResult.Params.Curve,
	}

	return SimulateDKG(newParams)
}
