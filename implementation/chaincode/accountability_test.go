package chaincode

import (
	"encoding/json"
	"fmt"
	"testing"
)

func newTestContract() *AccountabilityContract {
	return NewAccountabilityContract(NewMemoryStore())
}

func makeEvidence(id, peer string, mType MisbehaviorType, witnesses int) string {
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
		Evidence: CryptoEvidence{
			InvalidPartialSig:   "invalid-sig-data",
			ExpectedCommitments: []string{"C0", "C1", "C2"},
			Message:             "jwt-signing-input",
			PeerIndex:           3,
			VerificationResult:  false,
		},
		Witnesses: ws,
	}
	data, _ := json.Marshal(ep)
	return string(data)
}

func TestRecordMisbehavior_Success(t *testing.T) {
	contract := newTestContract()
	evidence := makeEvidence("ev-1", "P_3", M1InvalidSignature, 2)

	err := contract.RecordMisbehavior(evidence)
	if err != nil {
		t.Fatalf("RecordMisbehavior failed: %v", err)
	}

	// Check peer status
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

func TestRecordMisbehavior_InsufficientWitnesses(t *testing.T) {
	contract := newTestContract()
	evidence := makeEvidence("ev-1", "P_3", M1InvalidSignature, 1) // only 1 witness

	err := contract.RecordMisbehavior(evidence)
	if err == nil {
		t.Error("should fail with insufficient witnesses")
	}
}

func TestRecordMisbehavior_ValidSignatureRejected(t *testing.T) {
	contract := newTestContract()

	// Create evidence where verification result is true (sig is actually valid)
	ep := EvidencePackage{
		EvidenceID:  "ev-fake",
		Type:        M1InvalidSignature,
		AccusedPeer: "P_3",
		Evidence: CryptoEvidence{
			VerificationResult: true, // signature is valid — false accusation!
		},
		Witnesses: []Witness{{PeerID: "P_1"}, {PeerID: "P_2"}},
	}
	data, _ := json.Marshal(ep)

	err := contract.RecordMisbehavior(string(data))
	if err == nil {
		t.Error("should reject evidence where partial signature is actually valid")
	}
}

func TestStrikeSystem_M1_DisableAt3(t *testing.T) {
	contract := newTestContract()

	// 3 M1 strikes should disable the peer
	for i := 1; i <= 3; i++ {
		evidence := makeEvidence(fmt.Sprintf("ev-%d", i), "P_3", M1InvalidSignature, 2)
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
	evidence := makeEvidence("ev-1", "P_2", M3Inconsistent, 2)

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
	evidence := makeEvidence("ev-1", "P_4", M4Equivocation, 2)

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

	// Record 2 misbehaviors
	contract.RecordMisbehavior(makeEvidence("ev-1", "P_3", M1InvalidSignature, 2))
	contract.RecordMisbehavior(makeEvidence("ev-2", "P_3", M2Timeout, 2))

	history, err := contract.QueryMisbehaviorHistory("P_3")
	if err != nil {
		t.Fatalf("QueryMisbehaviorHistory failed: %v", err)
	}

	if len(history) != 2 {
		t.Errorf("expected 2 records, got %d", len(history))
	}
}

func TestCleanPeerStatus(t *testing.T) {
	contract := newTestContract()

	// A peer with no misbehavior should be ACTIVE
	status, err := contract.GetPeerStatus("P_1")
	if err != nil {
		t.Fatalf("GetPeerStatus failed: %v", err)
	}
	if status.Status != StatusActive {
		t.Errorf("clean peer should be ACTIVE, got %s", status.Status)
	}
}
