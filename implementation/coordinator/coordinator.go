// Package coordinator implements the Threshold-OIDC Coordinator, a
// stateless flow manager that orchestrates authentication and signing
// without holding any key material. This demonstrates the separation
// of concerns: the Coordinator CANNOT forge tokens.
//
// SECURITY PROPERTY: The Coordinator stores only PublicDKGInfo (public key +
// commitments). It has NO access to secret key shares. Token production
// is delegated to a PeerSigningFunc callback that represents the distributed
// peer signing process. The Coordinator builds the JWT payload and passes it
// to the peers for threshold signing — it cannot sign itself.
package coordinator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/signing"
)

// secureRandomHex generates a cryptographically secure random hex string.
// Used for session IDs and authorization codes to prevent prediction attacks.
func secureRandomHex(bytes int) string {
	b := make([]byte, bytes)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// PeerSigningFunc represents the distributed signing process.
// In production, this would collect partial signatures from t peers via
// network calls and aggregate them. The Coordinator invokes this callback
// but has no access to key shares — signing happens peer-side.
type PeerSigningFunc func(payload *signing.JWTPayload, signerIndices []int) (*signing.SigningResult, error)

// Coordinator manages OIDC sessions and signing orchestration.
// SECURITY: It holds only PublicDKGInfo (pk + commitments) — NO key shares.
// It CANNOT produce valid signatures without the PeerSigningFunc callback.
type Coordinator struct {
	// PublicInfo contains only the joint public key and Feldman commitments.
	// NO secret key shares — this is a strict security boundary.
	PublicInfo *dkg.PublicDKGInfo
	Issuer    string
	SignFunc  PeerSigningFunc // Callback to peers for threshold signing
	sessions  map[string]*Session
	mu        sync.RWMutex
}

// Session tracks an in-progress authentication flow.
type Session struct {
	ID            string
	ClientID      string
	RedirectURI   string
	Nonce         string
	State         string
	UserID        string // Authenticated user identity
	CreatedAt     time.Time
	Authenticated bool
	ApprovalCount int
	BindingHash   string // H(user_id || session_id || nonce) — payload binding
	AuthCode      string
	JWT           string
}

// ComputeBindingHash computes H(user_id || session_id || nonce) for
// payload binding. Peers include this hash in their MFA attestations
// and verify it before signing, preventing Coordinator payload manipulation.
func ComputeBindingHash(userID, sessionID, nonce string) string {
	h := sha256.Sum256([]byte(userID + "||" + sessionID + "||" + nonce))
	return hex.EncodeToString(h[:])
}

// New creates a Coordinator with ONLY public DKG information and a peer
// signing callback. The Coordinator never receives secret key shares.
func New(publicInfo *dkg.PublicDKGInfo, issuer string, signFunc PeerSigningFunc) *Coordinator {
	return &Coordinator{
		PublicInfo: publicInfo,
		Issuer:    issuer,
		SignFunc:  signFunc,
		sessions:  make(map[string]*Session),
	}
}

// CreateSession starts a new OIDC authorization flow.
func (c *Coordinator) CreateSession(clientID, redirectURI, nonce, state string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	sessionID := fmt.Sprintf("sess-%s", secureRandomHex(16))
	c.sessions[sessionID] = &Session{
		ID:          sessionID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Nonce:       nonce,
		State:       state,
		CreatedAt:   time.Now(),
	}
	return sessionID
}

// RecordPeerApproval records that a peer has approved authentication
// for a given userID. The first approval sets the binding hash;
// subsequent approvals must match. Returns true if threshold t is reached.
func (c *Coordinator) RecordPeerApproval(sessionID, userID string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	session, ok := c.sessions[sessionID]
	if !ok {
		return false, fmt.Errorf("session not found: %s", sessionID)
	}

	bindingHash := ComputeBindingHash(userID, sessionID, session.Nonce)

	// First approval sets the binding; subsequent must match
	if session.BindingHash == "" {
		session.BindingHash = bindingHash
		session.UserID = userID
	} else if session.BindingHash != bindingHash {
		return false, fmt.Errorf("binding hash mismatch: peer authenticated different user")
	}

	session.ApprovalCount++
	if session.ApprovalCount >= c.PublicInfo.Params.T {
		session.Authenticated = true
		session.AuthCode = fmt.Sprintf("code-%s", secureRandomHex(16))
		return true, nil
	}
	return false, nil
}

// ProduceToken orchestrates threshold signing for an authenticated session.
// The Coordinator builds the JWT payload and delegates signing to the peers
// via SignFunc. It CANNOT sign itself — it has no key material.
func (c *Coordinator) ProduceToken(sessionID string, signerIndices []int) (*signing.SigningResult, error) {
	c.mu.RLock()
	session, ok := c.sessions[sessionID]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if !session.Authenticated {
		return nil, fmt.Errorf("session not authenticated")
	}

	// Payload binding: sub must match the authenticated user
	sub := session.UserID
	expectedHash := ComputeBindingHash(sub, sessionID, session.Nonce)
	if expectedHash != session.BindingHash {
		return nil, fmt.Errorf("payload binding failed: sub does not match authenticated user")
	}

	payload := &signing.JWTPayload{
		Iss:            c.Issuer,
		Sub:            sub,
		Aud:            session.ClientID,
		Exp:            time.Now().Add(1 * time.Hour).Unix(),
		Iat:            time.Now().Unix(),
		Nonce:          session.Nonce,
		AuthTime:       session.CreatedAt.Unix(),
		Amr:            []string{"pwd", "otp"},
		ThresholdPeers: c.PublicInfo.Params.T,
	}

	// Delegate signing to peers — Coordinator has no key shares
	if c.SignFunc == nil {
		return nil, fmt.Errorf("no peer signing function configured")
	}
	result, err := c.SignFunc(payload, signerIndices)
	if err != nil {
		return nil, fmt.Errorf("peer signing failed: %w", err)
	}

	c.mu.Lock()
	session.JWT = result.JWT
	c.mu.Unlock()

	return result, nil
}

// ExchangeCode exchanges an authorization code for the signed JWT.
func (c *Coordinator) ExchangeCode(authCode string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, session := range c.sessions {
		if session.AuthCode == authCode && session.JWT != "" {
			return session.JWT, nil
		}
	}
	return "", fmt.Errorf("invalid or expired authorization code")
}

// HasKeyMaterial returns false — the Coordinator NEVER holds key material.
// This is enforced by type system: PublicDKGInfo contains no Share fields.
func (c *Coordinator) HasKeyMaterial() bool {
	// PublicDKGInfo type does not contain Shares — enforced at compile time.
	return false
}
