// Package benchmark provides comprehensive performance measurement for the
// Threshold-OIDC PoC. Results are intended for Section 7 of the paper.
//
// Measures:
//   - DKG latency across (t,n) configurations
//   - Token signing latency (threshold vs baseline single-key)
//   - Accountability overhead (normal flow vs misbehavior flow)
//   - Feldman VSS verification cost
//   - JWT verification cost
package benchmark

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/chaincode"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/signing"
)

const (
	iterations     = 500
	warmUpCount    = 50 // warm-up iterations discarded before measurement
	confidenceZ95  = 1.96
)

// stats computes min, max, mean, stddev, p50, p99, and 95% CI from durations.
type stats struct {
	Min, Max, Mean, StdDev, P50, P99 time.Duration
	CI95Lower, CI95Upper             time.Duration // 95% confidence interval
	Count                            int
}

func computeStats(durations []time.Duration) stats {
	if len(durations) == 0 {
		return stats{}
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	var sum float64
	for _, d := range durations {
		sum += float64(d)
	}
	mean := sum / float64(len(durations))

	var variance float64
	for _, d := range durations {
		diff := float64(d) - mean
		variance += diff * diff
	}
	variance /= float64(len(durations) - 1) // Bessel's correction (sample variance)
	stddev := math.Sqrt(variance)

	// 95% confidence interval: mean ± z * (stddev / sqrt(n))
	sem := stddev / math.Sqrt(float64(len(durations))) // standard error of mean
	ci95Margin := confidenceZ95 * sem

	return stats{
		Min:       durations[0],
		Max:       durations[len(durations)-1],
		Mean:      time.Duration(mean),
		StdDev:    time.Duration(stddev),
		P50:       durations[len(durations)/2],
		P99:       durations[int(float64(len(durations))*0.99)],
		CI95Lower: time.Duration(mean - ci95Margin),
		CI95Upper: time.Duration(mean + ci95Margin),
		Count:     len(durations),
	}
}

func (s stats) String() string {
	return fmt.Sprintf("n=%d mean=%v [95%%CI: %v-%v] min=%v p50=%v p99=%v stddev=%v",
		s.Count, s.Mean, s.CI95Lower, s.CI95Upper, s.Min, s.P50, s.P99, s.StdDev)
}

// runWarmUp executes warm-up iterations that are discarded before measurement.
// This ensures JIT compilation, CPU cache warming, and Go runtime stabilization.
func runWarmUp(f func()) {
	for i := 0; i < warmUpCount; i++ {
		f()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: DKG Latency Across Configurations
// ─────────────────────────────────────────────────────────────────────────────

func TestBenchmark_DKG_Latency(t *testing.T) {
	configs := []struct{ t, n int }{
		{2, 3}, {3, 5}, {4, 7}, {5, 9}, {7, 13},
	}

	t.Log("=== DKG Latency (crypto computation only) ===")
	t.Logf("%-10s %s", "Config", "Statistics")

	for _, cfg := range configs {
		params := dkg.Params{T: cfg.t, N: cfg.n, Curve: elliptic.P256()}

		// Warm-up: discard first iterations to stabilize CPU cache and runtime
		runWarmUp(func() { dkg.SimulateDKG(params) })

		durations := make([]time.Duration, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			dkg.SimulateDKG(params)
			durations[i] = time.Since(start)
		}

		s := computeStats(durations)
		t.Logf("(%d,%d)     %s", cfg.t, cfg.n, s)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Token Signing Latency — Threshold vs Baseline (Single-Key)
// ─────────────────────────────────────────────────────────────────────────────

func TestBenchmark_Signing_ThresholdVsBaseline(t *testing.T) {
	t.Log("=== Signing Latency: Threshold vs Baseline ===")

	payload := &signing.JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "bench-user", Aud: "bench-rp",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(), Nonce: "bench-nonce",
		ThresholdPeers: 3,
	}

	// Baseline: standard single-key ECDSA signing
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Warm-up baseline
	runWarmUp(func() {
		msg := []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0")
		hash := sha256.Sum256(msg)
		ecdsa.Sign(rand.Reader, privateKey, hash[:])
	})

	baselineDurations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		msg := []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0")
		hash := sha256.Sum256(msg)
		ecdsa.Sign(rand.Reader, privateKey, hash[:])
		baselineDurations[i] = time.Since(start)
	}
	baselineStats := computeStats(baselineDurations)
	t.Logf("Baseline (single-key ES256): %s", baselineStats)

	// Threshold signing for different (t,n) configurations
	configs := []struct {
		t, n    int
		signers []int
	}{
		{2, 3, []int{1, 2}},
		{3, 5, []int{1, 2, 3}},
		{4, 7, []int{1, 2, 3, 4}},
		{5, 9, []int{1, 2, 3, 4, 5}},
		{7, 13, []int{1, 2, 3, 4, 5, 6, 7}},
	}

	for _, cfg := range configs {
		params := dkg.Params{T: cfg.t, N: cfg.n, Curve: elliptic.P256()}
		dkgResult, _ := dkg.SimulateDKG(params)

		// Warm-up threshold signing
		runWarmUp(func() { signing.ThresholdSign(dkgResult, cfg.signers, payload) })

		durations := make([]time.Duration, iterations)
		for i := 0; i < iterations; i++ {
			start := time.Now()
			signing.ThresholdSign(dkgResult, cfg.signers, payload)
			durations[i] = time.Since(start)
		}
		s := computeStats(durations)
		overhead := float64(s.Mean) / float64(baselineStats.Mean)
		t.Logf("Threshold (%d,%d): %s  [overhead: %.1fx vs baseline]", cfg.t, cfg.n, s, overhead)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Accountability Overhead — Normal vs Misbehavior Flow
// ─────────────────────────────────────────────────────────────────────────────

func TestBenchmark_Accountability_Overhead(t *testing.T) {
	t.Log("=== Accountability Overhead ===")

	params := dkg.DefaultParams()
	dkgResult, _ := dkg.SimulateDKG(params)
	payload := &signing.JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "bench-user", Aud: "bench-rp",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}

	// Warm-up: stabilize CPU cache and Go runtime
	runWarmUp(func() {
		result, _ := signing.ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
		signing.VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
	})

	// Normal flow: DKG already done, sign + verify only
	normalDurations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		result, _ := signing.ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
		signing.VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
		normalDurations[i] = time.Since(start)
	}
	normalStats := computeStats(normalDurations)
	t.Logf("Normal flow (sign+verify):      %s", normalStats)

	// Feldman VSS verification cost (per share)
	vssDurations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		for _, share := range dkgResult.Shares {
			dkg.VerifyShare(share, dkgResult.Commitments, params.Curve)
		}
		vssDurations[i] = time.Since(start)
	}
	vssStats := computeStats(vssDurations)
	t.Logf("Feldman VSS verify (all %d):     %s", params.N, vssStats)

	// Misbehavior flow: sign + verify + detect + evidence + record
	misbehaviorDurations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()

		// Sign
		result, _ := signing.ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
		signing.VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)

		// Detect (Feldman VSS on all shares)
		for _, share := range dkgResult.Shares {
			dkg.VerifyShare(share, dkgResult.Commitments, params.Curve)
		}

		// Record misbehavior with real Feldman VSS re-verification
		store := chaincode.NewMemoryStore()
		contract := chaincode.NewAccountabilityContract(store)
		tamperedVal := new(big.Int).Add(dkgResult.Shares[2].Value, big.NewInt(42))
		tamperedVal.Mod(tamperedVal, params.Curve.Params().N)
		commHex := make([][2]string, len(dkgResult.Commitments))
		for ci, c := range dkgResult.Commitments {
			commHex[ci] = [2]string{hex.EncodeToString(c.X.Bytes()), hex.EncodeToString(c.Y.Bytes())}
		}
		evidence := chaincode.EvidencePackage{
			EvidenceID: fmt.Sprintf("ev-%d", i), Type: chaincode.M1InvalidSignature,
			AccusedPeer: "P_3",
			Evidence: chaincode.CryptoEvidence{
				ShareValueHex:       hex.EncodeToString(tamperedVal.Bytes()),
				CommitmentPointsHex: commHex,
				Message:             "jwt-signing-input",
				PeerIndex:           3,
			},
			Witnesses: []chaincode.Witness{
				{PeerID: "P_1", Signature: "s1"},
				{PeerID: "P_2", Signature: "s2"},
			},
		}
		evidenceJSON, _ := json.Marshal(evidence)
		contract.RecordMisbehavior(string(evidenceJSON))

		misbehaviorDurations[i] = time.Since(start)
	}
	misbehaviorStats := computeStats(misbehaviorDurations)
	overhead := float64(misbehaviorStats.Mean-normalStats.Mean) / float64(normalStats.Mean) * 100
	t.Logf("Misbehavior flow (full pipeline): %s", misbehaviorStats)
	t.Logf("Accountability overhead: +%.1f%% over normal flow", overhead)

	// JWT verification only (RP-side cost)
	result, _ := signing.ThresholdSign(dkgResult, []int{1, 2, 3}, payload)
	verifyDurations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		signing.VerifyJWT(result.JWT, dkgResult.PublicKey, params.Curve)
		verifyDurations[i] = time.Since(start)
	}
	verifyStats := computeStats(verifyDurations)
	t.Logf("JWT verify only (RP-side):       %s", verifyStats)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Throughput — Tokens Per Second
// ─────────────────────────────────────────────────────────────────────────────

func TestBenchmark_Throughput(t *testing.T) {
	t.Log("=== Token Throughput (sequential) ===")

	configs := []struct {
		t, n    int
		signers []int
	}{
		{2, 3, []int{1, 2}},
		{3, 5, []int{1, 2, 3}},
		{5, 9, []int{1, 2, 3, 4, 5}},
	}

	payload := &signing.JWTPayload{
		Iss: "https://threshold-oidc.example.com",
		Sub: "throughput-user", Aud: "throughput-rp",
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}

	for _, cfg := range configs {
		params := dkg.Params{T: cfg.t, N: cfg.n, Curve: elliptic.P256()}
		dkgResult, _ := dkg.SimulateDKG(params)

		// Warm-up
		runWarmUp(func() { signing.ThresholdSign(dkgResult, cfg.signers, payload) })

		count := 1000
		start := time.Now()
		for i := 0; i < count; i++ {
			signing.ThresholdSign(dkgResult, cfg.signers, payload)
		}
		elapsed := time.Since(start)
		tps := float64(count) / elapsed.Seconds()
		t.Logf("(%d,%d): %d tokens in %v = %.0f tokens/sec (simulation, sequential)",
			cfg.t, cfg.n, count, elapsed, tps)
	}
}
