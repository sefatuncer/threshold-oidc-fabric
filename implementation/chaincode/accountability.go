// Package chaincode implements the Accountability Protocol smart contract
// for Hyperledger Fabric. It records misbehavior evidence, tracks strike
// counts, and enforces automated sanctions.
//
// Chaincode functions:
//   - RecordMisbehavior: Validate and store evidence on the ledger
//   - QueryMisbehaviorHistory: Retrieve a peer's misbehavior records
//   - GetPeerStatus: Check if a peer is active or disabled
//   - GetAllPeerStatuses: List all peers and their current status
package chaincode

import (
	"encoding/json"
	"fmt"
	"time"
)

// MisbehaviorType categorizes peer misbehavior.
type MisbehaviorType string

const (
	M1InvalidSignature MisbehaviorType = "M1_INVALID_SIGNATURE"
	M2Timeout          MisbehaviorType = "M2_TIMEOUT"
	M3Inconsistent     MisbehaviorType = "M3_INCONSISTENT_SHARE"
	M4Equivocation     MisbehaviorType = "M4_EQUIVOCATION"
)

// Sanction thresholds by misbehavior type.
var sanctionThresholds = map[MisbehaviorType]int{
	M1InvalidSignature: 3,
	M2Timeout:          10,
	M3Inconsistent:     1,
	M4Equivocation:     1,
}

// PeerStatusType represents the operational status of a peer.
type PeerStatusType string

const (
	StatusActive    PeerStatusType = "ACTIVE"
	StatusWarning   PeerStatusType = "WARNING"
	StatusProbation PeerStatusType = "PROBATION"
	StatusDisabled  PeerStatusType = "DISABLED"
)

// EvidencePackage contains cryptographic proof of misbehavior.
type EvidencePackage struct {
	EvidenceID  string          `json:"evidenceId"`
	Type        MisbehaviorType `json:"type"`
	Timestamp   string          `json:"timestamp"`
	AccusedPeer string          `json:"accusedPeer"`
	SessionID   string          `json:"sessionId"`
	Evidence    CryptoEvidence  `json:"cryptographicEvidence"`
	Witnesses   []Witness       `json:"witnesses"`
}

// CryptoEvidence holds the cryptographic proof data.
type CryptoEvidence struct {
	InvalidPartialSig   string   `json:"invalidPartialSignature"`
	ExpectedCommitments []string `json:"expectedCommitments"`
	Message             string   `json:"message"`
	PeerIndex           int      `json:"peerIndex"`
	VerificationResult  bool     `json:"verificationResult"`
}

// Witness represents a peer attestation.
type Witness struct {
	PeerID      string `json:"peerId"`
	Attestation string `json:"attestation"`
	Signature   string `json:"signature"`
}

// PeerStatus tracks a peer's accountability state.
type PeerStatus struct {
	PeerID         string            `json:"peerId"`
	Status         PeerStatusType    `json:"status"`
	StrikeCounts   map[string]int    `json:"strikeCounts"`
	DisabledAt     string            `json:"disabledAt,omitempty"`
	DisabledReason string            `json:"disabledReason,omitempty"`
	History        []string          `json:"history"`
}

// LedgerStore is an interface for ledger operations.
// In HLF, this maps to stub.PutState / stub.GetState.
// For standalone testing, we use an in-memory implementation.
type LedgerStore interface {
	PutState(key string, value []byte) error
	GetState(key string) ([]byte, error)
}

// AccountabilityContract implements the accountability chaincode logic.
type AccountabilityContract struct {
	Store            LedgerStore
	MinWitnesses     int // Minimum witness count (default: t-1 = 2)
}

// NewAccountabilityContract creates a new contract with defaults.
func NewAccountabilityContract(store LedgerStore) *AccountabilityContract {
	return &AccountabilityContract{
		Store:        store,
		MinWitnesses: 2,
	}
}

// RecordMisbehavior validates evidence and records it on the ledger.
func (c *AccountabilityContract) RecordMisbehavior(evidenceJSON string) error {
	var evidence EvidencePackage
	if err := json.Unmarshal([]byte(evidenceJSON), &evidence); err != nil {
		return fmt.Errorf("invalid evidence JSON: %w", err)
	}

	// 1. Validate evidence format
	if evidence.EvidenceID == "" || evidence.AccusedPeer == "" {
		return fmt.Errorf("evidence must have evidenceId and accusedPeer")
	}
	if evidence.Type == "" {
		return fmt.Errorf("evidence must have a type")
	}

	// 2. For M1, verify that the partial signature is actually invalid
	if evidence.Type == M1InvalidSignature {
		if evidence.Evidence.VerificationResult {
			return fmt.Errorf("evidence invalid: partial signature is actually valid")
		}
	}

	// 3. Check minimum witness count
	if len(evidence.Witnesses) < c.MinWitnesses {
		return fmt.Errorf("insufficient witnesses: need %d, got %d",
			c.MinWitnesses, len(evidence.Witnesses))
	}

	// 4. Store evidence on ledger
	evidenceKey := fmt.Sprintf("MISBEHAVIOR_%s_%s", evidence.AccusedPeer, evidence.EvidenceID)
	evidenceBytes, _ := json.Marshal(evidence)
	if err := c.Store.PutState(evidenceKey, evidenceBytes); err != nil {
		return fmt.Errorf("failed to store evidence: %w", err)
	}

	// 5. Update peer status
	peerStatus, err := c.getOrCreatePeerStatus(evidence.AccusedPeer)
	if err != nil {
		return fmt.Errorf("failed to get peer status: %w", err)
	}

	// Increment strike count
	typeStr := string(evidence.Type)
	peerStatus.StrikeCounts[typeStr]++
	peerStatus.History = append(peerStatus.History, evidence.EvidenceID)

	// 6. Check sanction threshold
	threshold, exists := sanctionThresholds[evidence.Type]
	if !exists {
		threshold = 3 // default
	}

	currentStrikes := peerStatus.StrikeCounts[typeStr]
	if currentStrikes >= threshold {
		peerStatus.Status = StatusDisabled
		peerStatus.DisabledAt = time.Now().UTC().Format(time.RFC3339)
		peerStatus.DisabledReason = fmt.Sprintf("%s_THRESHOLD_EXCEEDED", evidence.Type)
	} else if currentStrikes >= threshold/2+1 {
		peerStatus.Status = StatusProbation
	} else if currentStrikes >= 1 {
		peerStatus.Status = StatusWarning
	}

	// Save updated status
	return c.savePeerStatus(peerStatus)
}

// QueryMisbehaviorHistory returns a peer's misbehavior records.
func (c *AccountabilityContract) QueryMisbehaviorHistory(peerID string) ([]EvidencePackage, error) {
	status, err := c.getOrCreatePeerStatus(peerID)
	if err != nil {
		return nil, err
	}

	var records []EvidencePackage
	for _, evidenceID := range status.History {
		key := fmt.Sprintf("MISBEHAVIOR_%s_%s", peerID, evidenceID)
		data, err := c.Store.GetState(key)
		if err != nil || data == nil {
			continue
		}
		var ep EvidencePackage
		if err := json.Unmarshal(data, &ep); err == nil {
			records = append(records, ep)
		}
	}
	return records, nil
}

// GetPeerStatus returns the current status of a peer.
func (c *AccountabilityContract) GetPeerStatus(peerID string) (*PeerStatus, error) {
	return c.getOrCreatePeerStatus(peerID)
}

func (c *AccountabilityContract) getOrCreatePeerStatus(peerID string) (*PeerStatus, error) {
	key := fmt.Sprintf("PEER_STATUS_%s", peerID)
	data, err := c.Store.GetState(key)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return &PeerStatus{
			PeerID:       peerID,
			Status:       StatusActive,
			StrikeCounts: make(map[string]int),
			History:      []string{},
		}, nil
	}

	var status PeerStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (c *AccountabilityContract) savePeerStatus(status *PeerStatus) error {
	key := fmt.Sprintf("PEER_STATUS_%s", status.PeerID)
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return c.Store.PutState(key, data)
}

// MemoryStore is an in-memory LedgerStore for standalone testing.
type MemoryStore struct {
	data map[string][]byte
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string][]byte)}
}

func (m *MemoryStore) PutState(key string, value []byte) error {
	m.data[key] = value
	return nil
}

func (m *MemoryStore) GetState(key string) ([]byte, error) {
	return m.data[key], nil
}
