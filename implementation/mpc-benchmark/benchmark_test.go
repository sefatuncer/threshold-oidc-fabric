package main

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	mpsecdsa "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

// --- Network simulation (mirrors internal/test) ---

type Network struct {
	parties party.IDSlice
	chans   map[party.ID]chan *protocol.Message
	done    chan struct{}
	mtx     sync.Mutex
}

func NewNetwork(parties party.IDSlice) *Network {
	n := &Network{
		parties: parties,
		chans:   make(map[party.ID]chan *protocol.Message, len(parties)),
	}
	for _, id := range parties {
		n.chans[id] = make(chan *protocol.Message, len(parties)*len(parties))
	}
	n.done = make(chan struct{})
	return n
}

func (n *Network) Send(msg *protocol.Message) {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	for id, c := range n.chans {
		if msg.IsFor(id) && c != nil {
			n.chans[id] <- msg
		}
	}
}

func (n *Network) Next(id party.ID) <-chan *protocol.Message {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	return n.chans[id]
}

func (n *Network) Done(id party.ID) chan struct{} {
	n.mtx.Lock()
	defer n.mtx.Unlock()
	if ch, ok := n.chans[id]; ok {
		close(ch)
		delete(n.chans, id)
	}
	if len(n.chans) == 0 {
		close(n.done)
	}
	return n.done
}

func handlerLoop(id party.ID, h protocol.Handler, net *Network) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				<-net.Done(id)
				return
			}
			go net.Send(msg)
		case msg := <-net.Next(id):
			h.Accept(msg)
		}
	}
}

// --- Helpers ---

func partyIDs(n int) party.IDSlice {
	ids := make(party.IDSlice, n)
	for i := 0; i < n; i++ {
		ids[i] = party.ID(fmt.Sprintf("p%d", i))
	}
	return ids
}

func runKeygen(t *testing.T, group curve.Curve, ids party.IDSlice, threshold int) map[party.ID]*cmp.Config {
	n := len(ids)
	net := NewNetwork(ids)
	configs := make(map[party.ID]*cmp.Config, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(n)

	for _, id := range ids {
		go func(id party.ID) {
			defer wg.Done()
			pl := pool.NewPool(0)
			defer pl.TearDown()
			h, err := protocol.NewMultiHandler(cmp.Keygen(group, id, ids, threshold, pl), nil)
			if err != nil {
				t.Errorf("keygen handler: %v", err)
				return
			}
			handlerLoop(id, h, net)
			r, err := h.Result()
			if err != nil {
				t.Errorf("keygen result: %v", err)
				return
			}
			cfg := r.(*cmp.Config)
			mu.Lock()
			configs[id] = cfg
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return configs
}

func runSigning(t *testing.T, configs map[party.ID]*cmp.Config, signers party.IDSlice, msg []byte) *mpsecdsa.Signature {
	net := NewNetwork(signers)
	var result *mpsecdsa.Signature
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(len(signers))

	for _, id := range signers {
		go func(id party.ID) {
			defer wg.Done()
			pl := pool.NewPool(0)
			defer pl.TearDown()
			h, err := protocol.NewMultiHandler(cmp.Sign(configs[id], signers, msg, pl), nil)
			if err != nil {
				t.Errorf("sign handler: %v", err)
				return
			}
			handlerLoop(id, h, net)
			r, err := h.Result()
			if err != nil {
				t.Errorf("sign result: %v", err)
				return
			}
			sig := r.(*mpsecdsa.Signature)
			mu.Lock()
			if result == nil {
				result = sig
			}
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return result
}

func TestMPCBenchmark(t *testing.T) {
	fmt.Println("\n========================================")
	fmt.Println("  Real MPC Benchmark (CMP/CGGMP)")
	fmt.Println("  taurusgroup/multi-party-sig")
	fmt.Println("========================================")

	group := curve.Secp256k1{}
	threshold := 1 // t where t+1 signers needed
	n := 3
	ids := partyIDs(n)

	// === KEYGEN ===
	fmt.Println("\n--- Keygen (threshold=2, parties=3) ---")
	kgStart := time.Now()
	configs := runKeygen(t, group, ids, threshold)
	kgDur := time.Since(kgStart)
	fmt.Printf("DKG: %v\n", kgDur)

	if len(configs) != n {
		t.Fatalf("keygen incomplete: got %d configs", len(configs))
	}

	// === SIGNING ===
	fmt.Println("\n--- Signing (2-of-3) ---")
	msg := sha256.Sum256([]byte(`{"alg":"ES256","typ":"JWT"}.{"sub":"user123","iss":"threshold-oidc"}`))
	signers := ids[:threshold+1]
	iterations := 5
	var totalSign time.Duration

	for iter := 0; iter < iterations; iter++ {
		signStart := time.Now()
		sig := runSigning(t, configs, signers, msg[:])
		signDur := time.Since(signStart)
		totalSign += signDur

		if sig == nil {
			t.Fatal("nil signature")
		}
		if !sig.Verify(configs[ids[0]].PublicPoint(), msg[:]) {
			t.Fatal("signature verification failed")
		}
		fmt.Printf("  Signing iter %d: %v\n", iter+1, signDur)
	}

	avgSign := totalSign / time.Duration(iterations)
	fmt.Printf("\n  Average MPC Signing (2,3): %v\n", avgSign)

	// === BASELINE ===
	fmt.Println("\n--- Baseline (single-key P-256) ---")
	privKey, _ := stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	baseIter := 1000
	baseStart := time.Now()
	for i := 0; i < baseIter; i++ {
		stdecdsa.Sign(rand.Reader, privKey, msg[:])
	}
	avgBase := time.Since(baseStart) / time.Duration(baseIter)
	fmt.Printf("  Average baseline: %v\n", avgBase)
	fmt.Printf("  MPC overhead: %.0fx\n", float64(avgSign)/float64(avgBase))

	fmt.Println("\n========================================")
	fmt.Printf("SUMMARY: DKG=%v, MPC_Sign=%v, Baseline=%v, Overhead=%.0fx\n",
		kgDur, avgSign, avgBase, float64(avgSign)/float64(avgBase))
	fmt.Println("========================================")
}
