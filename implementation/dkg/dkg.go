// Package dkg implements a simplified Distributed Key Generation (DKG)
// simulation for threshold ECDSA on P-256. This is a PoC-level implementation
// demonstrating the Feldman VSS-based DKG protocol described in the paper.
//
// NOTE: This is a PoC-level simulation, NOT a production MPC implementation.
// A production system would integrate tss-lib (BNB Chain, v2.0.2) or a similar
// audited library implementing the full CGGMP21 MPC protocol. The current PoC
// uses Go's standard crypto library to simulate DKG locally — it does NOT
// perform distributed multi-party computation across network nodes.
package dkg

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

// Params holds the DKG configuration.
type Params struct {
	T     int            // Threshold (minimum signers)
	N     int            // Total number of peers
	Curve elliptic.Curve // Elliptic curve (P-256)
}

// Share represents a peer's secret key share.
type Share struct {
	Index int      // Peer index (1-based)
	Value *big.Int // Secret share value
}

// Commitment represents a Feldman VSS commitment (point on curve).
type Commitment struct {
	X, Y *big.Int
}

// DKGResult contains the full output of the DKG protocol, including
// secret shares. This must ONLY be stored by the peers themselves,
// never by the Coordinator or any non-signing component.
type DKGResult struct {
	PublicKey    *Commitment  // Joint public key (pk = sk * G)
	Shares      []*Share     // Each peer's secret share (PRIVATE — peer-only)
	Commitments []Commitment // Feldman VSS commitments (public)
	Params      Params
}

// PublicDKGInfo contains only the public outputs of the DKG protocol.
// This is what the Coordinator and Relying Parties receive — it contains
// NO secret key shares. The Coordinator uses this to verify parameters
// and build JWT payloads, but CANNOT sign tokens.
type PublicDKGInfo struct {
	PublicKey    *Commitment  // Joint public key (pk = sk * G)
	Commitments []Commitment // Feldman VSS commitments (public)
	Params      Params
}

// PublicInfo extracts only the public information from a DKGResult.
// The returned struct contains no secret key material.
func (r *DKGResult) PublicInfo() *PublicDKGInfo {
	return &PublicDKGInfo{
		PublicKey:    r.PublicKey,
		Commitments: r.Commitments,
		Params:      r.Params,
	}
}

// DefaultParams returns (t=3, n=5) on P-256.
func DefaultParams() Params {
	return Params{
		T:     3,
		N:     5,
		Curve: elliptic.P256(),
	}
}

// SimulateDKG runs a simplified DKG protocol.
// In a real system, this would be distributed across peers.
// Here we simulate it centrally for PoC/benchmarking purposes.
func SimulateDKG(params Params) (*DKGResult, error) {
	curve := params.Curve
	order := curve.Params().N

	if params.T > params.N {
		return nil, fmt.Errorf("threshold %d exceeds total peers %d", params.T, params.N)
	}
	if params.T < 2 {
		return nil, fmt.Errorf("threshold must be at least 2, got %d", params.T)
	}

	// Each peer i generates a random polynomial f_i(x) of degree t-1
	// For simulation, we generate all polynomials and compute shares directly

	// Aggregate polynomial coefficients: a_0, a_1, ..., a_{t-1}
	// where a_0 = secret key (sum of all peers' a_{i,0})
	coefficients := make([]*big.Int, params.T)
	for j := 0; j < params.T; j++ {
		coeff, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, fmt.Errorf("random generation failed: %w", err)
		}
		coefficients[j] = coeff
	}

	// Compute Feldman VSS commitments: C_j = a_j * G
	commitments := make([]Commitment, params.T)
	for j := 0; j < params.T; j++ {
		cx, cy := curve.ScalarBaseMult(coefficients[j].Bytes())
		commitments[j] = Commitment{X: cx, Y: cy}
	}

	// The joint public key is C_0 = a_0 * G
	publicKey := &commitments[0]

	// Compute shares: share_i = f(i) = sum(a_j * i^j) mod order
	shares := make([]*Share, params.N)
	for i := 1; i <= params.N; i++ {
		shareVal := new(big.Int).Set(coefficients[0])
		iPow := big.NewInt(int64(i))
		for j := 1; j < params.T; j++ {
			term := new(big.Int).Mul(coefficients[j], iPow)
			term.Mod(term, order)
			shareVal.Add(shareVal, term)
			shareVal.Mod(shareVal, order)
			iPow.Mul(iPow, big.NewInt(int64(i)))
			iPow.Mod(iPow, order)
		}
		shares[i-1] = &Share{Index: i, Value: shareVal}
	}

	return &DKGResult{
		PublicKey:    publicKey,
		Shares:      shares,
		Commitments: commitments,
		Params:      params,
	}, nil
}

// VerifyShare checks a share against Feldman VSS commitments.
// Returns true if the share is consistent with the commitments.
func VerifyShare(share *Share, commitments []Commitment, curve elliptic.Curve) bool {
	// Compute g^{share} (left side)
	lx, ly := curve.ScalarBaseMult(share.Value.Bytes())

	// Compute Product(C_j^{i^j}) for j=0..t-1 (right side)
	i := big.NewInt(int64(share.Index))
	rx, ry := commitments[0].X, commitments[0].Y // C_0^{i^0} = C_0

	iPow := new(big.Int).Set(i) // i^1
	for j := 1; j < len(commitments); j++ {
		// C_j^{i^j}
		cx, cy := curve.ScalarMult(commitments[j].X, commitments[j].Y, iPow.Bytes())
		rx, ry = curve.Add(rx, ry, cx, cy)
		iPow.Mul(iPow, i)
		iPow.Mod(iPow, curve.Params().N)
	}

	return lx.Cmp(rx) == 0 && ly.Cmp(ry) == 0
}
