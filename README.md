# Threshold-Based OpenID Connect

**Decentralized Multi-Factor Authentication with Accountable Peer Detection on Hyperledger Fabric**

## Overview

This project implements a Threshold-Based OpenID Connect (OIDC) protocol that eliminates the Single Point of Failure (SPOF) in traditional Identity Providers by distributing IdP functionality across Hyperledger Fabric peers using threshold cryptography (t-of-n ECDSA).

### Key Features

- **Threshold Token Generation:** OIDC ID tokens are produced via distributed threshold ECDSA signing — no single peer holds the complete signing key
- **Accountability Protocol:** Misbehaving peers are detected via Feldman VSS verification, with immutable evidence recorded on the blockchain
- **OIDC Compatibility:** Generated tokens are standard JWTs — Relying Parties require zero modification
- **Automated Sanctions:** Peers exceeding a misbehavior threshold are automatically disabled via chaincode

## Architecture

```
┌─────────┐     ┌──────────────────────────────────────┐     ┌────────┐
│  User   │────>│  HLF Peer Network (t-of-n signing)   │────>│   RP   │
│  (MFA)  │     │  ┌──────┐ ┌──────┐ ┌──────┐         │     │(OIDC)  │
│         │<────│  │Peer 1│ │Peer 2│ │Peer n│  ...     │<────│        │
└─────────┘     │  └──┬───┘ └──┬───┘ └──┬───┘         │     └────────┘
                │     │partial  │partial │partial      │
                │     │sigs     │sigs    │sigs         │
                │     └────┬────┴────┬───┘             │
                │          │aggregate│                  │
                │          └────┬────┘                  │
                │          Standard JWT                 │
                │                                       │
                │  Accountability Chaincode:             │
                │  - Misbehavior detection (Feldman VSS) │
                │  - Evidence recording (immutable)      │
                │  - Automated peer sanctions            │
                └──────────────────────────────────────┘
```

## Project Structure

```
├── implementation/
│   ├── dkg/                # DKG simulation (Feldman VSS, P-256)
│   ├── signing/            # Threshold ECDSA signing + ES256 JWT
│   ├── chaincode/          # Accountability Protocol chaincode (Go)
│   ├── integration/        # End-to-end scenario tests
│   └── benchmark/          # Performance benchmark suite
├── evaluation/             # Benchmark results and analysis
└── docs/                   # Technical documentation (not tracked in git)
```

## Protocol Flow

1. **Setup (DKG):** Peers generate a shared ECDSA key pair via Distributed Key Generation. Public key is published at the OIDC `jwks_uri` endpoint.
2. **User Authentication:** User proves identity via MFA. At least *t* peers must approve.
3. **Token Generation:** Each approving peer produces a partial ECDSA signature. *t* partial signatures are aggregated into a standard JWT.
4. **Token Delivery:** Standard OIDC redirect — RP receives a valid JWT without any protocol changes.

## Accountability Protocol

A novel 3-phase mechanism not found in existing threshold SSO schemes (VeriSSO, PASTA, PESTO):

1. **Detection:** Feldman VSS verification identifies invalid partial signatures and timeouts
2. **Evidence Generation:** Cryptographic proof package (invalid signature + commitments + timestamps + peer attestations)
3. **Blockchain Record:** Chaincode validates and records evidence immutably; automatic sanctions after repeated violations

## Tech Stack

- **Blockchain:** Hyperledger Fabric
- **Threshold Crypto:** threshold ECDSA (tss-lib), Feldman VSS, DKG
- **Token Format:** JWT (ES256 / P-256)
- **Chaincode:** Go
- **Protocol:** OpenID Connect 1.0

## Related Work

| Scheme | Year | Threshold | OIDC Compatible | Blockchain | Misbehavior Detection | Accountability |
|--------|------|:---------:|:---------------:|:----------:|:---------------------:|:--------------:|
| PASTA | 2018 | Yes | No | No | No | No |
| PESTO | 2020 | Yes | No | No | Partial | No |
| TSAPP | 2023 | Yes | No | No | No | No |
| VeriSSO | 2025 | Yes | Yes | No | No | No |
| **Ours** | **2026** | **Yes** | **Yes** | **Yes (HLF)** | **Yes** | **Yes** |

## Running Tests

```bash
# All tests
go test ./... -v

# Race detector
go test -race ./...

# Benchmarks
go test ./benchmark/ -bench=. -benchmem

# Specific package
go test ./signing/ -v -run TestVerifyJWTWithClaims
```

## Reproducing Benchmark Results

```bash
cd implementation
go test ./benchmark/ -bench=. -benchmem -count=3
```

Results will show DKG/Signing/Accountability latency across
(2,3), (3,5), (4,7), (5,9), (7,13) configurations.

**Environment:** Go 1.22+, Linux, any x86_64 processor.

## License

MIT
