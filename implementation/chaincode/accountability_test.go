package chaincode

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
)

func newTestContract() *AccountabilityContract {
	return NewAccountabilityContract(NewMemoryStore())
}

// makeEvidenceWithRealCrypto creates an M1 evidence package using a real DKG
// result. If tamperShare is true, the share value is corrupted to simulate
// genuine misbehavior. If false, the share is valid (false accusation test).
func makeEvidenceWithRealCrypto(id, peer string, dkgResult *dkg.DKGResult, shareIndex int, tamperShare bool) string {
	share := dkgResult.Shares[shareIndex-1]

	shareValue := new(big.Int).Set(share.Value)
	if tamperShare {
		// Corrupt the share to simulate misbehavior
		shareValue.Add(shareValue, big.NewInt(42))
		shareValue.Mod(shareValue, dkgResult.Params.Curve.Params().N)
	}

	// Encode commitments as hex pairs
	commitmentHex := make([][2]string, len(dkgResult.Commitments))
	for i, c := range dkgResult.Commitments {
		commitmentHex[i] = [2]string{
			hex.EncodeToString(c.X.Bytes()),
			hex.EncodeToString(c.Y.Bytes()),
		}
	}

	ep := EvidencePackage{
		EvidenceID:  id,
		Type:        M1InvalidSignature,
		Timestamp:   "2026-03-30T12:00:00Z",
		AccusedPeer: peer,
		SessionID:   "sess-1",
		Evidence: CryptoEvidence{
			ShareValueHex:       hex.EncodeToString(shareValue.Bytes()),
			CommitmentPointsHex: commitmentHex,
			Message:             "jwt-signing-input",
			PeerIndex:           shareIndex,
		},
		Witnesses: []Witness{
			{PeerID: "P_1", Attestation: "verified misbehavior", Signature: "sig_1"},
			{PeerID: "P_2", Attestation: "verified misbehavior", Signature: "sig_2"},
		},
	}
	data, _ := json.Marshal(ep)
	return string(data)
}

// makeNonCryptoEvidence creates evidence for M2/M3/M4 types that don't
// require Feldman VSS re-verification.
func makeNonCryptoEvidence(id, peer string, mType MisbehaviorType, witnesses int) string {
	ws := make([]Witness, witnesses)
	for i := 0; i < witnesses; i++ {
		ws[i] = Witness{
			PeerID:      fmt.Sprintf("P_%d", i+1),
			Attestation: "verified misbehavior",
			Signature:   fmt.Sprintf("sig_%d", i+1),
		}
	}
	ep := EvidencePackage{
		EvidenceID:  id,
		Type:        mType,
		Timestamp:   "2026-03-30T12:00:00Z",
		AccusedPeer: peer,
		SessionID:   "sess-1",
		Evidence:    CryptoEvidence{PeerIndex: 3, Message: "jwt-signing-input"},
		Witnesses:   ws,
	}
	data, _ := json.Marshal(ep)
	return string(data)
}

// helper to get a DKG result for crypto-based tests
func testDKG(t *testing.T) *dkg.DKGResult {
	t.Helper()
	result, err := dkg.SimulateDKG(dkg.DefaultParams())
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	return result
}

func TestRecordMisbehavior_M1_RealCryptoVerification(t *testing.T) {
	contract := newTestContract()
	dkgResult := testDKG(t)

	// Tampered share → chaincode should accept (misbehavior confirmed)
	evidence := makeEvidenceWithRealCrypto("ev-1", "P_3", dkgResult, 3, true)
	err := contract.RecordMisbehavior(evidence)
	if err != nil {
		t.Fatalf("RecordMisbehavior should succeed for tampered share: %v", err)
	}

	status, err := contract.GetPeerStatus("P_3")
	if err != nil {
		t.Fatalf("GetPeerStatus failed: %v", err)
	}
	if status.Status != StatusWarning {
		t.Errorf("expected WARNING after 1 strike, got %s", status.Status)
	}
	if status.StrikeCounts[string(M1InvalidSignature)] != 1 {
		t.Errorf("expected 1 strike, got %d", status.StrikeCounts[string(M1InvalidSignature)])
	}
}

func TestRecordMisbehavior_M1_FalseAccusationRejected(t *testing.T) {
	contract := newTestContract()
	dkgResult := testDKG(t)

	// Valid share → chaincode should REJECT (false accusation)
	evidence := makeEvidenceWithRealCrypto("ev-fake", "P_3", dkgResult, 3, false)
	err := contract.RecordMisbehavior(evidence)
	if err == nil {
		t.Fatal("should reject evidence where Feldman VSS shows share is valid (false accusation)")
	}
	// Verify the error message mentions false accusation
	if err.Error() != "evidence rejected: Feldman VSS re-verification shows share is valid (false accusation)" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecordMisbehavior_M1_MissingCryptoData(t *testing.T) {
	contract := newTestContract()

	// M1 evidence without shareValueHex should fail
	ep := EvidencePackage{
		EvidenceID:  "ev-nodata",
		Type:        M1InvalidSignature,
		AccusedPeer: "P_3",
		Evidence:    CryptoEvidence{PeerIndex: 3},
		Witnesses: []Witness{
			{PeerID: "P_1", Attestation: "x", Signature: "s1"},
			{PeerID: "P_2", Attestation: "x", Signature: "s2"},
		},
	}
	data, _ := json.Marshal(ep)
	err := contract.RecordMisbehavior(string(data))
	if err == nil {
		t.Error("should fail when M1 evidence lacks cryptographic data")
	}
}

func TestRecordMisbehavior_InsufficientWitnesses(t *testing.T) {
	contract := newTestContract()
	evidence := makeNonCryptoEvidence("ev-1", "P_3", M2Timeout, 1)

	err := contract.RecordMisbehavior(evidence)
	if err == nil {
		t.Error("should fail with insufficient witnesses")
	}
}

func TestStrikeSystem_M1_DisableAt3(t *testing.T) {
	contract := newTestContract()
	dkgResult := testDKG(t)

	// 3 M1 strikes with real crypto verification should disable the peer
	for i := 1; i <= 3; i++ {
		evidence := makeEvidenceWithRealCrypto(fmt.Sprintf("ev-%d", i), "P_3", dkgResult, 3, true)
		err := contract.RecordMisbehavior(evidence)
		if err != nil {
			t.Fatalf("strike %d failed: %v", i, err)
		}
	}

	status, _ := contract.GetPeerStatus("P_3")
	if status.Status != StatusDisabled {
		t.Errorf("expected DISABLED after 3 M1 strikes, got %s", status.Status)
	}
	if status.DisabledReason != "M1_INVALID_SIGNATURE_THRESHOLD_EXCEEDED" {
		t.Errorf("unexpected disabled reason: %s", status.DisabledReason)
	}
}

func TestStrikeSystem_M3_ImmediateDisable(t *testing.T) {
	contract := newTestContract()
	evidence := makeNonCryptoEvidence("ev-1", "P_2", M3Inconsistent, 2)

	err := contract.RecordMisbehavior(evidence)
	if err != nil {
		t.Fatalf("RecordMisbehavior failed: %v", err)
	}

	status, _ := contract.GetPeerStatus("P_2")
	if status.Status != StatusDisabled {
		t.Errorf("M3 should immediately disable, got %s", status.Status)
	}
}

func TestStrikeSystem_M4_ImmediateDisable(t *testing.T) {
	contract := newTestContract()
	evidence := makeNonCryptoEvidence("ev-1", "P_4", M4Equivocation, 2)

	err := contract.RecordMisbehavior(evidence)
	if err != nil {
		t.Fatalf("RecordMisbehavior failed: %v", err)
	}

	status, _ := contract.GetPeerStatus("P_4")
	if status.Status != StatusDisabled {
		t.Errorf("M4 should immediately disable, got %s", status.Status)
	}
}

func TestQueryMisbehaviorHistory(t *testing.T) {
	contract := newTestContract()
	dkgResult := testDKG(t)

	// Record M1 with real crypto + M2 without
	contract.RecordMisbehavior(makeEvidenceWithRealCrypto("ev-1", "P_3", dkgResult, 3, true))
	contract.RecordMisbehavior(makeNonCryptoEvidence("ev-2", "P_3", M2Timeout, 2))

	history, err := contract.QueryMisbehaviorHistory("P_3")
	if err != nil {
		t.Fatalf("QueryMisbehaviorHistory failed: %v", err)
	}

	if len(history) != 2 {
		t.Errorf("expected 2 records, got %d", len(history))
	}
}

func TestStrikeSystem_M2_GradualEscalation(t *testing.T) {
	contract := newTestContract()

	// M2 (Timeout): 10 strikes to disable — no crypto verification needed
	for i := 1; i <= 10; i++ {
		evidence := makeNonCryptoEvidence(fmt.Sprintf("ev-timeout-%d", i), "P_5", M2Timeout, 2)
		err := contract.RecordMisbehavior(evidence)
		if err != nil {
			t.Fatalf("M2 strike %d failed: %v", i, err)
		}

		status, _ := contract.GetPeerStatus("P_5")

		switch {
		case i < 6:
			if status.Status != StatusWarning {
				t.Errorf("strike %d: expected WARNING, got %s", i, status.Status)
			}
		case i < 10:
			if status.Status != StatusProbation {
				t.Errorf("strike %d: expected PROBATION, got %s", i, status.Status)
			}
		case i == 10:
			if status.Status != StatusDisabled {
				t.Errorf("strike %d: expected DISABLED, got %s", i, status.Status)
			}
		}
	}
}

func TestDuplicateEvidenceID_Rejected(t *testing.T) {
	contract := newTestContract()
	dkgResult := testDKG(t)

	// First submission should succeed
	err := contract.RecordMisbehavior(makeEvidenceWithRealCrypto("ev-dup", "P_3", dkgResult, 3, true))
	if err != nil {
		t.Fatalf("first submission should succeed: %v", err)
	}

	// Same evidence ID again should be rejected (replay prevention)
	err = contract.RecordMisbehavior(makeEvidenceWithRealCrypto("ev-dup", "P_3", dkgResult, 3, true))
	if err == nil {
		t.Error("duplicate evidence ID should be rejected")
	}

	// Strike count should be 1 (not 2)
	status, _ := contract.GetPeerStatus("P_3")
	if status.StrikeCounts[string(M1InvalidSignature)] != 1 {
		t.Errorf("expected 1 strike (dedup), got %d", status.StrikeCounts[string(M1InvalidSignature)])
	}
}

func TestGetAllPeerStatuses(t *testing.T) {
	contract := newTestContract()
	dkgResult := testDKG(t)

	contract.RecordMisbehavior(makeEvidenceWithRealCrypto("ev-1", "P_1", dkgResult, 1, true))
	contract.RecordMisbehavior(makeNonCryptoEvidence("ev-2", "P_3", M2Timeout, 2))

	statuses, err := contract.GetAllPeerStatuses([]string{"P_1", "P_2", "P_3"})
	if err != nil {
		t.Fatalf("GetAllPeerStatuses failed: %v", err)
	}
	if len(statuses) != 3 {
		t.Errorf("expected 3 statuses, got %d", len(statuses))
	}
	for _, s := range statuses {
		if s.PeerID == "P_2" && s.Status != StatusActive {
			t.Errorf("P_2 should be ACTIVE, got %s", s.Status)
		}
	}
}

func TestCleanPeerStatus(t *testing.T) {
	contract := newTestContract()

	status, err := contract.GetPeerStatus("P_1")
	if err != nil {
		t.Fatalf("GetPeerStatus failed: %v", err)
	}
	if status.Status != StatusActive {
		t.Errorf("clean peer should be ACTIVE, got %s", status.Status)
	}
}

func TestVerifyShareFromEvidence_AllSharesValid(t *testing.T) {
	// Verify that dkg.VerifyShare correctly validates all DKG shares
	// This confirms the re-verification path works end-to-end
	dkgResult := testDKG(t)
	curve := elliptic.P256()

	for _, share := range dkgResult.Shares {
		valid := dkg.VerifyShare(share, dkgResult.Commitments, curve)
		if !valid {
			t.Errorf("share %d should be valid", share.Index)
		}
	}
}

func TestVerifyShareFromEvidence_TamperedShareInvalid(t *testing.T) {
	// Verify that a tampered share fails Feldman VSS verification
	dkgResult := testDKG(t)
	curve := elliptic.P256()

	tampered := &dkg.Share{
		Index: 3,
		Value: new(big.Int).Add(dkgResult.Shares[2].Value, big.NewInt(1)),
	}
	valid := dkg.VerifyShare(tampered, dkgResult.Commitments, curve)
	if valid {
		t.Error("tampered share should fail verification")
	}
}
