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
│   ├── chaincode/          # HLF chaincode (Go) — accountability & token logic
│   └── client-sdk/         # Client SDK for OIDC flow
├── protocol/               # Protocol design artifacts
├── analysis/               # Security analysis scripts, ProVerif models
├── evaluation/             # Performance benchmarks
└── docs/                   # Technical documentation
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

## License

TBD
