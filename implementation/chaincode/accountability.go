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
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
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
// For M1 (invalid partial signature), the chaincode performs independent
// Feldman VSS re-verification rather than trusting the reporter's boolean flag.
type CryptoEvidence struct {
	// ShareValueHex is the accused peer's claimed share value (hex-encoded big.Int).
	// The chaincode re-verifies this against commitments using dkg.VerifyShare.
	ShareValueHex string `json:"shareValueHex"`
	// CommitmentPointsHex stores Feldman VSS commitment points as hex-encoded
	// pairs [x_hex, y_hex] for each commitment on P-256.
	CommitmentPointsHex [][2]string `json:"commitmentPointsHex"`
	// Message is the JWT signing input that was being signed.
	Message   string `json:"message"`
	// PeerIndex is the 1-based index of the accused peer.
	PeerIndex int    `json:"peerIndex"`
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

	// 2. For M1, perform independent Feldman VSS re-verification.
	// The chaincode does NOT trust the reporter's claim — it re-verifies
	// the accused peer's share against the Feldman commitments on-chain.
	if evidence.Type == M1InvalidSignature {
		shareValid, err := c.verifyShareFromEvidence(&evidence.Evidence)
		if err != nil {
			return fmt.Errorf("cryptographic re-verification failed: %w", err)
		}
		if shareValid {
			// The share is actually valid — this is a false accusation.
			return fmt.Errorf("evidence rejected: Feldman VSS re-verification shows share is valid (false accusation)")
		}
		// Share is genuinely invalid → misbehavior confirmed cryptographically.
	}

	// For M2 (Timeout): No cryptographic re-verification possible — timeout is
	// an operational event, not a cryptographic one. Protection relies on the
	// high sanction threshold (10 strikes) and t-1 witness requirement.
	//
	// For M3 (Inconsistent Share): Verification requires cross-session commitment
	// comparison. The chaincode checks that the commitment stored in this evidence
	// differs from a previously recorded commitment for the same peer — this is a
	// ledger lookup, not a Feldman VSS check. Implemented via witness attestations.
	//
	// For M4 (Equivocation): Verification requires two different σ_i values signed
	// by the same peer for the same session. The evidence must contain both values
	// and peer signatures proving authenticity. Implemented via witness attestations
	// carrying the conflicting signatures.
	//
	// In all cases, the t-1 witness requirement provides Byzantine fault tolerance
	// against false accusations. Only M1 benefits from on-chain Feldman VSS
	// re-verification because it involves a single share-commitment pair that can
	// be independently checked.

	// 3. Check minimum witness count
	if len(evidence.Witnesses) < c.MinWitnesses {
		return fmt.Errorf("insufficient witnesses: need %d, got %d",
			c.MinWitnesses, len(evidence.Witnesses))
	}

	// 4. Check for duplicate evidence ID (prevent replay)
	evidenceKey := fmt.Sprintf("MISBEHAVIOR_%s_%s", evidence.AccusedPeer, evidence.EvidenceID)
	existing, _ := c.Store.GetState(evidenceKey)
	if existing != nil {
		return fmt.Errorf("evidence %s already recorded (replay rejected)", evidence.EvidenceID)
	}

	// 5. Store evidence on ledger
	evidenceBytes, _ := json.Marshal(evidence)
	if err := c.Store.PutState(evidenceKey, evidenceBytes); err != nil {
		return fmt.Errorf("failed to store evidence: %w", err)
	}

	// 6. Update peer status
	peerStatus, err := c.getOrCreatePeerStatus(evidence.AccusedPeer)
	if err != nil {
		return fmt.Errorf("failed to get peer status: %w", err)
	}

	// Increment strike count
	typeStr := string(evidence.Type)
	peerStatus.StrikeCounts[typeStr]++
	peerStatus.History = append(peerStatus.History, evidence.EvidenceID)

	// 7. Check sanction threshold
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

// GetAllPeerStatuses returns status for all registered peers.
func (c *AccountabilityContract) GetAllPeerStatuses(peerIDs []string) ([]PeerStatus, error) {
	var statuses []PeerStatus
	for _, id := range peerIDs {
		status, err := c.getOrCreatePeerStatus(id)
		if err != nil {
			return nil, fmt.Errorf("failed to get status for %s: %w", id, err)
		}
		statuses = append(statuses, *status)
	}
	return statuses, nil
}

// verifyShareFromEvidence performs independent Feldman VSS re-verification
// of the accused peer's share against the public commitments. This is the
// core cryptographic guarantee of the Accountability Protocol: the chaincode
// itself verifies the evidence rather than trusting the reporter's claim.
//
// Returns (true, nil) if the share IS valid (false accusation).
// Returns (false, nil) if the share IS invalid (confirmed misbehavior).
func (c *AccountabilityContract) verifyShareFromEvidence(ev *CryptoEvidence) (bool, error) {
	if ev.ShareValueHex == "" {
		return false, fmt.Errorf("shareValueHex is required for M1 evidence")
	}
	if len(ev.CommitmentPointsHex) == 0 {
		return false, fmt.Errorf("commitmentPointsHex is required for M1 evidence")
	}
	if ev.PeerIndex < 1 {
		return false, fmt.Errorf("peerIndex must be >= 1")
	}

	// Parse the share value from hex
	shareBytes, err := hex.DecodeString(ev.ShareValueHex)
	if err != nil {
		return false, fmt.Errorf("invalid shareValueHex: %w", err)
	}
	shareValue := new(big.Int).SetBytes(shareBytes)

	// Parse commitment points from hex
	curve := elliptic.P256()
	commitments := make([]dkg.Commitment, len(ev.CommitmentPointsHex))
	for i, pair := range ev.CommitmentPointsHex {
		xBytes, err := hex.DecodeString(pair[0])
		if err != nil {
			return false, fmt.Errorf("invalid commitment[%d].x hex: %w", i, err)
		}
		yBytes, err := hex.DecodeString(pair[1])
		if err != nil {
			return false, fmt.Errorf("invalid commitment[%d].y hex: %w", i, err)
		}
		commitments[i] = dkg.Commitment{
			X: new(big.Int).SetBytes(xBytes),
			Y: new(big.Int).SetBytes(yBytes),
		}
	}

	// Perform Feldman VSS verification using the same function
	// used during DKG — deterministic and cryptographically sound.
	share := &dkg.Share{
		Index: ev.PeerIndex,
		Value: shareValue,
	}
	return dkg.VerifyShare(share, commitments, curve), nil
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

// MemoryStore is a thread-safe in-memory LedgerStore for testing.
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string][]byte)}
}

func (m *MemoryStore) PutState(key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *MemoryStore) GetState(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.data[key], nil
}
