# Related Work: 5-Paper Structured Analysis

> Date: 2026-03-29
> Purpose: Our work = Threshold-OIDC + Accountability Protocol on Hyperledger Fabric (HLF)

---

## Paper 1: Belfaik et al. (2023) — OIDC + Blockchain, IdP Still Centralized

**Full Citation:**
Belfaik, H., Bouras, A., & Benlahmar, E. H. (2023). A Novel Secure and Privacy-Preserving Model for OpenID Connect Based on Blockchain. *IEEE Access*, 11, 67929–67945. DOI: 10.1109/ACCESS.2023.3292143

**Technical Approach:**
Proposes securing OIDC protocol parameters (client_id, client_secret, authorization code, access/id tokens, state, redirect_uri) by storing them on Ethereum blockchain using ERC-721 (NFT) standard. The model uses NFTs to represent and protect critical OIDC artifacts, preventing impersonation and unauthorized access. The IdP itself remains a centralized entity — blockchain is used as an auxiliary secure storage/verification layer, not to replace the IdP.

| Feature | Value |
|---------|-------|
| **Threshold Crypto** | NO — No key splitting or threshold signing |
| **OIDC Compatible** | YES — Directly extends OIDC protocol flows |
| **Blockchain** | YES — Ethereum (ERC-721 NFTs) |
| **Misbehavior Detection** | NO — No mechanism to detect/prove IdP misbehavior |

**Key Difference from Our Work:**
Belfaik et al. use blockchain as a secure storage layer for OIDC parameters but leave the IdP as a centralized single point of failure (SPOF). There is no threshold token issuance and no accountability mechanism. Our work eliminates SPOF via threshold-OIDC (distributed IdP nodes sign tokens collaboratively) and adds an on-chain Accountability Protocol on HLF for detecting and sanctioning server misbehavior.

---

## Paper 2: SSH-DAuth / Krishna et al. (2023) — Secret Sharing + OAuth

**Full Citation:**
Krishna, D. P., Ramaguru, R., Praveen, K., Sethumadhavan, M., Ravichandran, K. S., Krishankumar, R., & Gandomi, A. H. (2023). SSH-DAuth: Secret Sharing Based Decentralized OAuth Using Decentralized Identifier. *Scientific Reports*, 13, 18024. DOI: 10.1038/s41598-023-44586-6

**Technical Approach:**
Proposes a decentralized authentication framework replacing centralized OAuth 2.0 with a secret-sharing-based scheme. Uses an ideal (1,3,4)-Secret Sharing Scheme (based on Boolean matrices from Praveen et al. 2017, not Shamir's polynomial scheme) to split the user's Decentralized Identifier (DID) into 4 shares: 1 mandatory share (DIDMS) retained by the user, 3 shares distributed to IPFS. Authentication requires the mandatory share plus at least 2 of the 3 IPFS shares. Implemented on both Hyperledger Fabric (permissioned) and Ethereum TestNet (permissionless).

| Feature | Value |
|---------|-------|
| **Threshold Crypto** | PARTIAL — Secret sharing for DID storage/reconstruction, NOT for token signing |
| **OIDC Compatible** | NO — OAuth 2.0 only, not OIDC; replaces the standard flow entirely |
| **Blockchain** | YES — Hyperledger Fabric + Ethereum TestNet (for DID anchoring) |
| **Misbehavior Detection** | NO — No mechanism for detecting or proving server misbehavior |

**Key Difference from Our Work:**
SSH-DAuth uses secret sharing for *credential storage* (splitting DIDs), not for *threshold token issuance*. It replaces OAuth entirely with a custom DID-based flow, breaking compatibility with standard OIDC relying parties. Our work performs threshold signing of standard OIDC id_tokens (preserving RP compatibility) and adds an on-chain accountability layer that SSH-DAuth completely lacks.

---

## Paper 3: FADID-TT / Liu et al. (2025) — HLF + Secret Sharing, Anonymous Credentials

**Full Citation:**
Liu, Y., Zhao, Z., Zhao, B., Ran, F., Lin, X., Li, D., & Guan, Z. (2025). Fully Anonymous Decentralized Identity Supporting Threshold Traceability with Practical Blockchain. In *Proceedings of the ACM Web Conference 2025 (WWW '25)*, pp. 3628–3638. DOI: 10.1145/3696410.3714762

**Technical Approach:**
Designs a fully anonymous DID system (FADID-TT) combining anonymous signatures and Decentralized Anonymous Credentials (DAC). A committee of distributed issuing authorities uses secret sharing to issue user secret key shares — no single entity can learn the user's real identity or public key. Service providers verify user identity using only the committee public key, reducing public key management from O(n) to O(1). Includes a publicly verifiable threshold tracing mechanism: committee members can collaboratively trace a malicious user's identity via zero-knowledge proofs without compromising other users' privacy. Deployed on both Hyperledger Fabric and Ethereum.

| Feature | Value |
|---------|-------|
| **Threshold Crypto** | YES — Threshold tracing (collaborative de-anonymization), secret sharing for key issuance |
| **OIDC Compatible** | NO — Custom DID/anonymous credential system, not SSO/OIDC |
| **Blockchain** | YES — Hyperledger Fabric + Ethereum |
| **Misbehavior Detection** | PARTIAL — Threshold tracing detects *user* misbehavior (malicious users can be traced), but does NOT detect *server/IdP* misbehavior |

**Key Difference from Our Work:**
FADID-TT focuses on *user anonymity* and *user traceability* (tracing malicious users) in a DID ecosystem. It is not an SSO/OIDC system and does not issue standard identity tokens. Our work focuses on *server-side SPOF elimination* (threshold OIDC token issuance) and *server accountability* (detecting and sanctioning misbehaving IdP nodes), which FADID-TT does not address. FADID-TT's threshold mechanism is for tracing users, ours is for signing tokens.

---

## Paper 4: Bashar (Shuhan) et al. (2024) — Blockchain IdP Federation, No Threshold Crypto

**Full Citation:**
Shuhan, M. K. B., Hasnayeen, S. M., Das, T. K., Sakib, M. N., & Ferdous, M. S. (2024). Decentralised Identity Federations Using Blockchain. *International Journal of Information Security*, 23(4), 2573–2596. DOI: 10.1007/s10207-024-00864-6

**Technical Approach:**
Proposes decentralizing the Identity Provider (IdP) role within an identity federation using blockchain (implemented on both Ethereum private network and Hyperledger Fabric). Modifies the SAML protocol to integrate blockchain for creating decentralized federations, removing the single-point-of-failure of centralized IdP. Security evaluated using ProVerif formal verification tool. The approach replaces centralized IdP with blockchain-based credential management but does NOT use threshold cryptography — the blockchain replaces the IdP rather than distributing its signing capability.

| Feature | Value |
|---------|-------|
| **Threshold Crypto** | NO — Blockchain consensus replaces IdP, no threshold signing |
| **OIDC Compatible** | NO — Based on SAML, not OIDC |
| **Blockchain** | YES — Ethereum (private) + Hyperledger Fabric |
| **Misbehavior Detection** | NO — No mechanism for detecting or proving IdP/node misbehavior |

**Key Difference from Our Work:**
Bashar et al. use blockchain consensus to replace the centralized IdP entirely (SAML-based), while our work distributes the IdP's signing key across multiple nodes via threshold cryptography while maintaining full OIDC protocol compatibility. Their approach breaks OIDC compatibility (uses SAML) and lacks any accountability/misbehavior detection mechanism. Our Accountability Protocol provides on-chain evidence and sanctions for misbehaving IdP nodes — a capability absent in their design.

---

## Paper 5: PROTECT / Zhang et al. (2021) — Password-Based Threshold SSO

**Full Citation:**
Zhang, Y., Xu, C., Li, H., Yang, K., Cheng, N., & Shen, X. (2021). PROTECT: Efficient Password-Based Threshold Single-Sign-On Authentication for Mobile Users Against Perpetual Leakage. *IEEE Transactions on Mobile Computing*, 20(6), 2297–2312. DOI: 10.1109/TMC.2020.2975792

> Note: While the user referenced IEEE TDSC (2020), PROTECT was actually published in IEEE TMC (Transactions on Mobile Computing) in 2021, accepted 2020.

**Technical Approach:**
Introduces a Password-Based Threshold SSO (PbT-SSO) scheme where multiple identity servers collaboratively authenticate mobile users and issue tokens in a threshold manner. Uses Threshold Oblivious Pseudo-Random Function (TOPRF) for password hardening — no single server learns the user's password. Supports proactive key renewal: secrets on each identity server are periodically updated to resist perpetual leakage even if servers are compromised over time. Resistant to offline dictionary guessing attacks (DGA), online DGA, and password testing attacks.

| Feature | Value |
|---------|-------|
| **Threshold Crypto** | YES — Threshold OPRF for password verification + threshold token issuance |
| **OIDC Compatible** | NO — Custom SSO protocol, not OIDC-compatible |
| **Blockchain** | NO — No blockchain component |
| **Misbehavior Detection** | NO — Proactive key renewal limits damage from compromised servers but does NOT detect, prove, or sanction misbehavior |

**Key Difference from Our Work:**
PROTECT is a purely cryptographic threshold SSO scheme without blockchain and without OIDC compatibility. It focuses on password-based authentication resilience against perpetual leakage via proactive key renewal. Our work operates at the OIDC protocol level (standard id_token signing), uses HLF blockchain for transparency and auditability, and critically adds an Accountability Protocol for detecting and sanctioning misbehaving IdP nodes — capabilities entirely absent in PROTECT.

---

## Comparative Summary Table

| Feature | Belfaik '23 | SSH-DAuth '23 | FADID-TT '25 | Bashar '24 | PROTECT '21 | **Ours '26** |
|---------|:-----------:|:-------------:|:------------:|:----------:|:----------:|:------------:|
| **Threshold Crypto** | - | Partial* | Yes** | - | Yes | **Yes** |
| **OIDC Compatible** | Yes | - | - | - (SAML) | - | **Yes** |
| **Blockchain** | Yes (ETH) | Yes (HLF+ETH) | Yes (HLF+ETH) | Yes (HLF+ETH) | - | **Yes (HLF)** |
| **Misbehavior Detection** | - | - | Partial*** | - | - | **Yes** |
| **Server Accountability** | - | - | - | - | - | **Yes** |
| **SPOF Elimination** | - | Yes**** | Yes | Yes | Yes | **Yes** |
| **Formal Verification** | - | - | - | ProVerif | Formal proof | **TBD** |

\* SSH-DAuth: Secret sharing for credential storage, not for token signing.
\** FADID-TT: Threshold tracing for user de-anonymization, not for token signing.
\*** FADID-TT: Detects user misbehavior (traces malicious users), not server misbehavior.
\**** SSH-DAuth: Eliminates centralized IdP but replaces standard OAuth flow entirely.

---

## Key Gap Our Work Fills

None of the five papers simultaneously provides:
1. **Threshold OIDC token issuance** (distributed signing of standard id_tokens)
2. **Full OIDC backward compatibility** (RPs need no modification)
3. **On-chain Accountability Protocol** (misbehavior detection + evidence + sanctions for IdP nodes)
4. **Blockchain-backed audit trail** (HLF ledger for transparency and non-repudiation)

This four-way combination is our unique contribution space.
