# Benchmark Summary — Threshold-OIDC PoC

**Date:** 2026-04-01
**Platform:** Linux 5.15.0, Intel Broadwell, Go 1.22.12
**Iterations:** 500 per measurement (1000 for throughput), 50 warm-up iterations discarded
**Statistical reporting:** Mean, StdDev, P50, P99, 95% Confidence Interval (CI)

> **CRITICAL CAVEAT — SIMULATION ONLY:**
> All measurements below are **local cryptographic computation cost only**.
> The PoC uses Lagrange interpolation (key reconstruction), NOT real MPC-based
> threshold signing (CGGMP21). Real-world MPC deployment would add:
> - Network RTT per MPC round: 50-200ms (CGGMP21 requires 4+ rounds)
> - HLF ledger write latency: 100-1000ms (endorsement + ordering + commit)
> - MPC computation overhead: 10-100x over key reconstruction simulation
>
> **These numbers should NOT be directly compared with systems measured in
> real distributed environments (e.g., PESTO's 124ms includes network RTT).**

## 1. DKG Latency (One-Time Cost, Simulation)

| Config | Mean | 95% CI | Min | P50 | P99 | StdDev |
|--------|------|--------|-----|-----|-----|--------|
| (2,3)  | 47us | ±2us   | 39us | 44us | 75us | 8us |
| (3,5)  | 74us | ±1us   | 66us | 72us | 113us | 8us |
| (4,7)  | 107us | ±5us  | 92us | 99us | 177us | 56us |
| (5,9)  | 139us | ±3us  | 122us | 130us | 233us | 40us |
| (7,13) | 211us | ±3us  | 187us | 200us | 352us | 40us |

Scaling: approximately O(t·n). Warm-up: 50 iterations discarded.

## 2. Signing Latency — Threshold Simulation vs Baseline

| Config | Mean (sim) | 95% CI | Overhead vs Baseline | **Estimated E2E** |
|--------|------------|--------|---------------------|-------------------|
| Baseline (single-key ES256) | 38us | ±1us | 1.0x | <1ms |
| Threshold (2,3) sim | 52us | ±2us | 1.4x | **200-600ms** |
| Threshold (3,5) sim | 54us | ±2us | 1.4x | **250-700ms** |
| Threshold (4,7) sim | 64us | ±3us | 1.7x | **300-900ms** |
| Threshold (5,9) sim | 76us | ±3us | 2.0x | **400-1200ms** |
| Threshold (7,13) sim | 108us | ±4us | 2.8x | **500-1500ms** |

**Estimated E2E Model:** `T_e2e = T_mpc + (rounds × RTT) + T_hlf`

| Parameter | Value | Source |
|-----------|-------|--------|
| T_mpc (MPC computation) | 50-200ms | Fireblocks MPC-CMP whitepaper (CGGMP-based, P-256) |
| rounds | 4-5 | CGGMP21 protocol specification [cggmp21] |
| RTT (per round) | 10-50ms (LAN), 50-200ms (WAN) | PESTO evaluation [pesto2020]: servers across countries |
| T_hlf | 100-500ms | HLF v3.0 endorsement+ordering latency (only for DKG/accountability, not signing) |

**Calibration references:**
- PESTO reports 124ms for 2-round protocol across countries (RTT~60ms per round)
- Fireblocks MPC-CMP achieves ~200ms for threshold ECDSA on P-256 in production
- VeriSSO reports ~30ms for committee-based signing (lighter than full MPC)
- Our estimates are conservative: (3,5) with LAN RTT ≈ 50+4×20+0 = 130ms, with WAN RTT ≈ 200+4×100+0 = 600ms

The "sim" column measures only local cryptographic cost (Lagrange reconstruction), NOT real MPC.

## 3. Accountability Overhead

| Flow | Mean (sim) | 95% CI | vs Normal |
|------|------------|--------|-----------|
| Normal flow (sign+verify) | 181us | ±5us | 1.0x |
| Feldman VSS verify (5 shares) | 1,144us | ±15us | — |
| Misbehavior flow (full pipeline) | 1,205us | ±18us | 6.7x |
| JWT verify only (RP-side) | 113us | ±3us | — |

Key finding: accountability overhead is significant (~6.7x) but only incurred
during misbehavior events, not during normal operation. Normal flow has ZERO
accountability overhead. The chaincode now performs **real Feldman VSS
re-verification** (not a boolean flag check) as part of the misbehavior flow.

## 4. Throughput (Sequential, Simulation)

| Config | Tokens/sec (sim) | Estimated Real-World |
|--------|-----------------|---------------------|
| (2,3)  | 16,322          | ~2-5 tokens/sec     |
| (3,5)  | 13,385          | ~1-4 tokens/sec     |
| (5,9)  | 11,294          | ~0.7-2.5 tokens/sec |

**Note:** Simulation throughput measures sequential crypto-only cost.
Real-world throughput depends on network topology, MPC round latency,
HLF consensus, and parallelization strategy. Estimated real-world
values assume sequential signing with 4-round MPC + network RTT.

## 5. Competitor Comparison

| System | Measurement Type | Token/Sign Latency | Notes |
|--------|-----------------|-------------------|-------|
| Standard OIDC | Production | <1ms | Single IdP, no threshold |
| **Ours (3,5) simulation** | **Crypto-only sim** | **54us** | **Lagrange reconstruction, NOT MPC** |
| **Ours (3,5) estimated** | **Parametric model** | **250-700ms** | **Includes estimated MPC rounds + network** |
| PESTO (2020) | Real distributed | 124ms | 2-round protocol, servers in different countries |
| VeriSSO (2025) | Real system | ~30ms | Single SSO flow, committee-based |
| PASTA (2018) | Not reported | — | CCS paper, focus on security proofs |

**Fair comparison caveat:** Our simulation measures only local crypto cost.
PESTO and VeriSSO measurements include real network latency. Our estimated
E2E latency (250-700ms) is in the same order of magnitude as PESTO (124ms),
suggesting competitive performance. However, our system adds accountability
overhead that PESTO lacks entirely — this is the key advantage, not speed.

## 6. Methodology Notes

- **Warm-up:** 50 iterations discarded before each measurement series
- **Confidence intervals:** 95% CI computed as mean ± 1.96 × (stddev / sqrt(n))
- **Simulation limitation:** Lagrange key reconstruction ≠ real MPC threshold signing
- **GC consideration:** Go GC may affect microsecond-level measurements; results
  represent typical performance including GC pauses
- **Reproducibility:** Source code available at github.com/sefatuncer/threshold-oidc-fabric
