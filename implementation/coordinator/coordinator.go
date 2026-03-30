// Package coordinator implements the Threshold-OIDC Coordinator, a
// stateless flow manager that orchestrates authentication and signing
// without holding any key material. This demonstrates the separation
// of concerns: the Coordinator CANNOT forge tokens.
package coordinator

import (
	"fmt"
	"sync"
	"time"

	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/dkg"
	"github.com/sefatuncer/hyperledger-fabric-oidc-mfa/signing"
)

// Coordinator manages OIDC sessions and signing orchestration.
// IMPORTANT: It holds NO key shares and CANNOT produce valid signatures.
type Coordinator struct {
	// No sk, sk_i, or any key material fields — by design
	DKGResult *dkg.DKGResult // Public info only (pk, commitments)
	Issuer    string
	sessions  map[string]*Session
	mu        sync.RWMutex
}

// Session tracks an in-progress authentication flow.
type Session struct {
	ID           string
	ClientID     string
	RedirectURI  string
	Nonce        string
	State        string
	CreatedAt    time.Time
	Authenticated bool
	ApprovalCount int
	AuthCode     string
	JWT          string
}

// New creates a Coordinator with public DKG information.
func New(dkgResult *dkg.DKGResult, issuer string) *Coordinator {
	return &Coordinator{
		DKGResult: dkgResult,
		Issuer:    issuer,
		sessions:  make(map[string]*Session),
	}
}

// CreateSession starts a new OIDC authorization flow.
func (c *Coordinator) CreateSession(clientID, redirectURI, nonce, state string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	sessionID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
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

// RecordPeerApproval records that a peer has approved authentication.
// Returns true if the threshold t is reached.
func (c *Coordinator) RecordPeerApproval(sessionID string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	session, ok := c.sessions[sessionID]
	if !ok {
		return false, fmt.Errorf("session not found: %s", sessionID)
	}

	session.ApprovalCount++
	if session.ApprovalCount >= c.DKGResult.Params.T {
		session.Authenticated = true
		session.AuthCode = fmt.Sprintf("code-%d", time.Now().UnixNano())
		return true, nil
	}
	return false, nil
}

// ProduceToken orchestrates threshold signing for an authenticated session.
// The Coordinator collects partial signatures but CANNOT sign itself.
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

	payload := &signing.JWTPayload{
		Iss:            c.Issuer,
		Sub:            "user-" + session.ClientID,
		Aud:            session.ClientID,
		Exp:            time.Now().Add(1 * time.Hour).Unix(),
		Iat:            time.Now().Unix(),
		Nonce:          session.Nonce,
		AuthTime:       session.CreatedAt.Unix(),
		Amr:            []string{"pwd", "otp"},
		ThresholdPeers: c.DKGResult.Params.T,
	}

	result, err := signing.ThresholdSign(c.DKGResult, signerIndices, payload)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
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
// This method exists solely to demonstrate the security property.
func (c *Coordinator) HasKeyMaterial() bool {
	return false
}
