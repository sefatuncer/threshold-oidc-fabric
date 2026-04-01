# Background Research: Structured Summaries

Compiled: 2026-03-29

---

## 1. OpenID Connect Core 1.0

### What is OpenID Connect?

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0. It allows clients (Relying Parties) to verify the identity of an end-user based on authentication performed by an Authorization Server (OpenID Provider / IdP), and to obtain basic profile information in an interoperable, REST-like manner.

### Key Components

- **Authorization Code Flow**: The most secure and recommended flow. The client redirects the user to the IdP, which authenticates the user and returns an authorization code. The client exchanges this code at the Token Endpoint (back-channel) for an ID Token and Access Token.
- **ID Token**: A JSON Web Token (JWT) containing claims about the authentication event (issuer, subject, audience, expiration, nonce, etc.). ID Tokens MUST be signed using JWS; encryption is OPTIONAL.
- **JWT Structure**: Three Base64url-encoded parts separated by dots: Header (alg, typ, kid), Payload (claims: iss, sub, aud, exp, iat, nonce, etc.), Signature (computed over Header.Payload using the IdP's signing key).
- **UserInfo Endpoint**: Returns basic profile attributes when presented with a valid Access Token.
- **Three Flows**: Authorization Code Flow, Implicit Flow, and Hybrid Flow.

### Specification Details

- **Current Version**: OpenID Connect Core 1.0 incorporating errata set 2
- **Spec URL**: https://openid.net/specs/openid-connect-core-1_0.html
- **Authors**: N. Sakimura (NRI), J. Bradley (Ping Identity), M. Jones (Microsoft), B. de Medeiros (Google), C. Mortimore (Salesforce)
- **Date**: November 8, 2014 (with errata updates)
- **ITU-T**: Also adopted as ITU-T Recommendation X.1285 (05/2025)

### Relevance to Our Paper

OIDC is the foundational protocol we are extending. The critical security property is that the IdP holds a **single signing key** for ID Tokens. If this key is compromised, all tokens can be forged — this is the Single Point of Failure (SPOF) our threshold-based approach addresses.

---

## 2. Microsoft Storm-0558 Incident (2023)

### What Happened?

Beginning **May 15, 2023**, a China-based threat actor designated **Storm-0558** used forged authentication tokens to access email accounts of approximately **25 organizations** (including U.S. government agencies) and **503 related personal accounts** worldwide. Microsoft was notified by a customer on **June 16, 2023**.

### How Was the OIDC Signing Key Compromised?

1. A **Microsoft Account (MSA) consumer signing key** (created in 2016) was accidentally included in a **crash dump** that was moved to a debugging environment after April 2021.
2. Storm-0558 **compromised a Microsoft engineer's corporate account** that had access to this debugging environment.
3. They extracted the MSA consumer signing key from the crash dump.
4. A **token validation vulnerability** allowed this consumer signing key to also be accepted for **enterprise/Azure AD tokens** — the OIDC endpoint listed signing keys for both consumer and enterprise identity systems, but the SDKs did not properly distinguish between them.

### Impact

- **22 enterprise organizations** and **503 personal accounts** affected
- Included email accounts of **Commerce Secretary Gina Raimondo** and **U.S. Ambassador to China R. Nicholas Burns**
- **~60,000 emails** downloaded from the State Department alone
- Access lasted **at least 6 weeks**
- The **CSRB (Cyber Safety Review Board)** concluded the intrusion "should never have happened" and resulted from a "cascade of security failures at Microsoft"

### Relevance to Our Paper

This is the **canonical real-world example** of IdP Single Point of Failure (SPOF) risk in OIDC:
- A single signing key compromise allowed forging tokens for millions of users
- Demonstrates that even the largest IdPs (Microsoft) are vulnerable
- Shows that a stolen IdP signing key = complete identity infrastructure compromise
- Directly motivates our threshold-based approach: with (t,n)-threshold signing, no single crash dump / no single compromised engineer could leak the full signing key

---

## 3. Threshold ECDSA Key Papers

### GG18: Gennaro & Goldfeder (2018)

- **Title**: "Fast Multiparty Threshold ECDSA with Fast Trustless Setup"
- **Published**: ACM CCS 2018, pp. 1179-1194
- **What they proposed**: The first practical (t,n)-threshold ECDSA scheme with **no trusted dealer** required for key generation. Uses Paillier encryption for the Multiplicative-to-Additive (MtA) sub-protocol during signing. Supports arbitrary thresholds (not just n-of-n).
- **Key innovation**: Trustless setup via distributed key generation, making threshold ECDSA practical for real deployments.

### GG20: Gennaro & Goldfeder (2020)

- **Title**: "One Round Threshold ECDSA with Identifiable Abort"
- **Published**: Cryptology ePrint Archive, Paper 2020/540
- **Improvement over GG18**:
  - Reduced signing from **multiple rounds to a single round** of communication
  - Introduced **identifiable abort**: if the protocol fails, the corrupted party can be identified
  - Significantly improved latency and efficiency

### CGGMP21: Canetti, Gennaro, Goldfeder, Makriyannis & Peled (2020/2021)

- **Title**: "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
- **Published**: ACM CCS 2020, pp. 1769-1787 (ePrint 2021/060)
- **What's new**:
  - **UC-secure** (Universally Composable security framework)
  - **Non-interactive signing**: only the last round requires knowledge of the message
  - **Proactive security**: periodic key refresh withstands adaptive corruption over time
  - **Identifiable aborts**: corrupted signatories can be identified upon failure
  - Considered the **most complete and secure** protocol in this line of work with no known vulnerabilities

### Which is Most Relevant for Our Work?

**CGGMP21** is the most relevant for P-256/ES256 JWT signing because:
1. It provides **UC security** (composable with other protocols in our system)
2. **Identifiable abort** enables our accountability protocol (detect misbehaving signers)
3. **Proactive key refresh** aligns with our key rotation requirements
4. It works with **any elliptic curve**, including NIST P-256 (required for ES256 in JWT/OIDC)
5. It has **no known vulnerabilities** (unlike GG18/GG20 which were broken by Alpha-Rays)

---

## 4. Feldman VSS (Verifiable Secret Sharing)

### What is Feldman's VSS?

Feldman's Verifiable Secret Sharing is a **non-interactive** extension of Shamir's Secret Sharing that allows shareholders to **verify** that their shares are consistent with the secret, without revealing the secret itself.

### How it Works

1. The dealer selects a random polynomial f(x) of degree t-1 where f(0) = secret
2. The dealer distributes shares s_i = f(i) to each party
3. **Key addition**: The dealer publishes **commitments** C_j = g^{a_j} for each coefficient a_j of the polynomial, where g is a generator of a group where the discrete logarithm problem is hard
4. Any party can verify their share by checking: g^{s_i} = Product(C_j^{i^j}) for j=0..t-1
5. This is **non-interactive** — verification requires no communication with the dealer

### Original Paper

- **Author**: Paul Feldman (MIT)
- **Title**: "A Practical Scheme for Non-interactive Verifiable Secret Sharing"
- **Published**: 28th Annual Symposium on Foundations of Computer Science (FOCS), Los Angeles, CA, October 27-29, 1987, pp. 427-437
- **Publisher**: IEEE Computer Society

### Relevance to Our Accountability Protocol

Feldman VSS is critical for our design because:
1. **Detecting invalid partial signatures**: Each signer's key share has public commitments. If a signer produces an invalid partial signature, other parties can verify against the commitments and identify the misbehaving party.
2. **Verifiable key generation**: During DKG, Feldman VSS ensures each party's contribution is consistent — no party can secretly bias the key generation.
3. **Non-interactive verification**: Reduces communication overhead in our threshold signing protocol.
4. **Foundation for accountability**: The public commitments serve as the basis for our on-chain accountability mechanism — invalid partial signatures can be cryptographically proven.

---

## 5. DKG (Distributed Key Generation)

### What is DKG?

Distributed Key Generation (DKG) is a cryptographic protocol where multiple parties jointly compute a shared public/private key pair such that:
- No single party ever knows the complete private key
- Each party holds a share of the private key
- A threshold t of parties is needed to use the key (sign, decrypt)
- No trusted dealer is required

### Key Papers

#### Pedersen (1991)
- **Title**: "A Threshold Cryptosystem without a Trusted Party"
- **Published**: EUROCRYPT '91, LNCS vol. 547, pp. 522-526, Springer
- **Contribution**: First DKG protocol. Each party acts as a dealer in Feldman VSS, sharing a random value. The combined secret is the sum of all individual secrets. Simple and efficient but later shown to not guarantee uniform key distribution.

#### Gennaro, Jarecki, Krawczyk, Rabin (1999/2007)
- **Title**: "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"
- **Published**: EUROCRYPT '99; journal version in Journal of Cryptology, Vol. 20, pp. 51-83, 2007
- **Contribution**: Showed that Pedersen's DKG does **not** guarantee uniformly random key distribution (a malicious party can bias the key). Proposed a new DKG with an **extra round** of communication that ensures uniform distribution.
- **Important nuance**: Later showed that Pedersen's original DKG is still secure for certain threshold cryptosystem applications whose security reduces to discrete log hardness.

### How DKG Works with Threshold ECDSA

In threshold ECDSA (e.g., GG18/CGGMP21):
1. **Key Generation Phase**: Each party i generates a random secret x_i and uses Feldman VSS to distribute shares of x_i to all other parties.
2. **Public Key Computation**: The joint public key Q = sum(x_i * G) is computed from the public commitments without revealing any x_i.
3. **Share Combination**: Each party j computes its final key share as the sum of all received sub-shares.
4. **Result**: The private key x = sum(x_i) is never reconstructed; parties hold Shamir shares of x.
5. **Signing**: t parties can produce a valid ECDSA signature using their shares via the MtA (Multiplicative-to-Additive) sub-protocol.

---

## 6. tss-lib (Binance / BNB Chain)

### What is tss-lib?

tss-lib is an open-source **Go library** implementing multi-party {t,n}-threshold ECDSA (based on GG18) and EdDSA. Originally developed by Binance (now BNB Chain).

- **GitHub**: https://github.com/bnb-chain/tss-lib
- **Language**: Go
- **Latest Version**: v2.0.2 (January 16, 2024)
- **Commits**: 412+ on master
- **Security Audit**: Full review by Kudelski Security (October 2019)

### Alpha-Rays Attack (2021)

- **Authors**: Dmytro Tymokhanov (Velas) and Omer Shlomovits (ZenGo)
- **Paper**: "Alpha-Rays: Key Extraction Attacks on Threshold ECDSA Implementations" (ePrint 2021/1621)
- **Vulnerability**: Two attack vectors exploiting the Multiplicative-to-Additive (MtA) sub-protocol:
  1. **Fast MtA attack**: When range proofs are omitted ("fast" mode), a malicious party gains a powerful oracle that reveals part of the secret key with each signature.
  2. **Full MtA attack**: Even with range proofs, a missing **Paillier key size check** and incorrect bounds in ZK proofs allow a single malicious party to extract the **full secret key** after a single valid signature.
- **Impact**: Complete break of GG18 and GG20 implementations. A single malicious party could extract all other parties' secret key shares.
- **Fix**: tss-lib v2.0.0 patched this vulnerability along with the TSSHOCK vulnerability (by Verichains, 2023).

### P-256 Support Status

- tss-lib uses a **curve registry system** that supports multiple curves
- **secp256k1** is the default/primary ECDSA curve (Bitcoin/Ethereum)
- **NIST P-256** is mentioned as supported (used by NEO) via the curve registration mechanism
- **EdDSA** (Edwards curves) also supported
- For our ES256 JWT signing use case, P-256 support exists but may require verification of the specific implementation path

### Current Maintenance Status

- **Actively maintained**: v2.0.0 released with major security fixes; v2.0.2 (Jan 2024) is latest
- v2.0.0 includes fixes for Alpha-Rays (2021), TSSHOCK (Verichains 2023), and GHSA-5cjx-95fx-68q9 (Fireblocks 2023)
- v2 is **not backward compatible** with v1.3.x; migration via resharing is recommended
- Multiple active forks exist (ZetaChain, Swingby, Circle's robust-tss-lib)

---

## 7. Hyperledger Fabric

### Architecture

- **Peers**: Maintain the state and the ledger. Receive ordered state updates as blocks from the ordering service. Two roles: **endorsing peers** (execute chaincode and endorse results) and **committing peers** (validate and commit blocks).
- **Orderers**: Form the ordering service — a communication fabric that provides delivery guarantees. Orders transactions into blocks. As of v3.0, supports **SmartBFT** (Byzantine Fault Tolerant) consensus in addition to Raft (crash fault tolerant).
- **Channels**: Operate like mini-blockchains, each with their own permissioning policies and separate ledger. Enable data isolation on a single Fabric network.
- **Chaincode**: Smart contracts in Fabric. Supported languages: Go, Node.js/TypeScript, Java. Executes business logic and reads/writes the ledger state.

### Endorsement Policy

Every chaincode has an endorsement policy specifying which peers must execute the chaincode and endorse results for a transaction to be valid. Examples: "AND('Org1.peer', 'Org2.peer')" requires both organizations to endorse. Supports AND, OR, and OutOf expressions.

### Academic Usage in Identity Management

Multiple academic papers use Hyperledger Fabric for decentralized identity:
- **Decentralized PKI (DPKI)**: Using Fabric to create a hierarchy of Certificate Authorities as peers in a decentralized network, eliminating CA single point of failure (directly relevant to our paper).
- **Healthcare IAM**: Fabric + OAuth 2.0 for blockchain-based identity and access management in healthcare.
- **IoT Device Identity**: Smart contracts for device registration, ownership transfer, and anomaly detection.
- **Federated Identity**: Cross-border digital verification systems (e.g., vaccine passports).
- **Permissioned Blockchain IAM**: Decentralized, tamper-resistant identity verification systems.

### IBM and Current Status

- **IBM Blockchain Platform SaaS**: Withdrawn, End of Support July 2023
- **IBM Blockchain Platform Software**: End of Support April 30, 2023
- **Important**: IBM shifted customers to **"IBM Support for Hyperledger Fabric"** — this is a consolidation of commercial offerings, **not a withdrawal** from the project.
- **IBM Research** continues driving code contributions through **Fabric-X** initiative
- **Hyperledger Foundation** became part of **LF Decentralized Trust** (Linux Foundation) in September 2024
- **Fabric v3.0** released September 2024 with SmartBFT consensus
- IBM reinforced its "commitment to open source Hyperledger Fabric" in official blog posts

---

## BibTeX References

```bibtex
% ==============================================================================
% OIDC & OAuth
% ==============================================================================

@misc{oidc-core,
  author       = {Sakimura, Nat and Bradley, John and Jones, Michael B. and
                  de Medeiros, Breno and Mortimore, Chuck},
  title        = {{OpenID Connect Core 1.0 incorporating errata set 2}},
  year         = {2014},
  howpublished = {OpenID Foundation Specification},
  url          = {https://openid.net/specs/openid-connect-core-1_0.html},
  note         = {Accessed: 2026-03-29}
}

% ==============================================================================
% Storm-0558 Incident
% ==============================================================================

@misc{storm0558-microsoft,
  author       = {{Microsoft Threat Intelligence}},
  title        = {{Analysis of Storm-0558 techniques for unauthorized email access}},
  year         = {2023},
  month        = jul,
  howpublished = {Microsoft Security Blog},
  url          = {https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/}
}

@misc{storm0558-msrc,
  author       = {{Microsoft Security Response Center}},
  title        = {{Results of Major Technical Investigations for Storm-0558 Key Acquisition}},
  year         = {2023},
  month        = sep,
  howpublished = {MSRC Blog},
  url          = {https://www.microsoft.com/en-us/msrc/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition}
}

@misc{storm0558-csrb,
  author       = {{Cyber Safety Review Board}},
  title        = {{Review of the Summer 2023 {Microsoft Exchange Online} Intrusion}},
  year         = {2024},
  month        = mar,
  howpublished = {CISA},
  url          = {https://www.cisa.gov/sites/default/files/2025-03/CSRBReviewOfTheSummer2023MEOIntrusion508.pdf}
}

@misc{storm0558-wiz,
  author       = {Shir Tamari and Nir Ohfeld},
  title        = {{Compromised Microsoft Key: More Impactful Than We Thought}},
  year         = {2023},
  month        = jul,
  howpublished = {Wiz Blog},
  url          = {https://www.wiz.io/blog/storm-0558-compromised-microsoft-key-enables-authentication-of-countless-micr}
}

% ==============================================================================
% Threshold ECDSA
% ==============================================================================

@inproceedings{gg18,
  author    = {Gennaro, Rosario and Goldfeder, Steven},
  title     = {{Fast Multiparty Threshold ECDSA with Fast Trustless Setup}},
  booktitle = {Proceedings of the 2018 ACM SIGSAC Conference on Computer and
               Communications Security (CCS '18)},
  year      = {2018},
  pages     = {1179--1194},
  publisher = {ACM},
  address   = {New York, NY, USA},
  doi       = {10.1145/3243734.3243859}
}

@misc{gg20,
  author       = {Gennaro, Rosario and Goldfeder, Steven},
  title        = {{One Round Threshold ECDSA with Identifiable Abort}},
  year         = {2020},
  howpublished = {Cryptology ePrint Archive, Paper 2020/540},
  url          = {https://eprint.iacr.org/2020/540}
}

@inproceedings{cggmp21,
  author    = {Canetti, Ran and Gennaro, Rosario and Goldfeder, Steven and
               Makriyannis, Nikolaos and Peled, Udi},
  title     = {{UC Non-Interactive, Proactive, Threshold ECDSA with
               Identifiable Aborts}},
  booktitle = {Proceedings of the 2020 ACM SIGSAC Conference on Computer and
               Communications Security (CCS '20)},
  year      = {2020},
  pages     = {1769--1787},
  publisher = {ACM},
  doi       = {10.1145/3372297.3423367},
  note      = {Full version: ePrint 2021/060}
}

% ==============================================================================
% Feldman VSS
% ==============================================================================

@inproceedings{feldman1987,
  author    = {Feldman, Paul},
  title     = {{A Practical Scheme for Non-interactive Verifiable Secret Sharing}},
  booktitle = {28th Annual Symposium on Foundations of Computer Science (FOCS)},
  year      = {1987},
  pages     = {427--437},
  publisher = {IEEE Computer Society},
  address   = {Los Angeles, CA, USA},
  doi       = {10.1109/SFCS.1987.4}
}

% ==============================================================================
% Distributed Key Generation
% ==============================================================================

@inproceedings{pedersen1991,
  author    = {Pedersen, Torben Pryds},
  title     = {{A Threshold Cryptosystem without a Trusted Party}},
  booktitle = {Advances in Cryptology --- EUROCRYPT '91},
  year      = {1991},
  pages     = {522--526},
  publisher = {Springer},
  series    = {Lecture Notes in Computer Science},
  volume    = {547},
  address   = {Berlin, Heidelberg},
  doi       = {10.1007/3-540-46416-6_47}
}

@article{gennaro2007dkg,
  author    = {Gennaro, Rosario and Jarecki, Stanislaw and Krawczyk, Hugo and
               Rabin, Tal},
  title     = {{Secure Distributed Key Generation for Discrete-Log Based
               Cryptosystems}},
  journal   = {Journal of Cryptology},
  year      = {2007},
  volume    = {20},
  number    = {1},
  pages     = {51--83},
  publisher = {Springer},
  doi       = {10.1007/s00145-006-0347-3},
  note      = {Extended version of EUROCRYPT '99 paper}
}

% ==============================================================================
% tss-lib & Attacks
% ==============================================================================

@misc{tsslib,
  author       = {{BNB Chain}},
  title        = {{tss-lib}: Threshold Signature Scheme, for ECDSA and EdDSA},
  year         = {2024},
  howpublished = {GitHub Repository},
  url          = {https://github.com/bnb-chain/tss-lib},
  note         = {v2.0.2, Go implementation of GG18}
}

@misc{alpharays2021,
  author       = {Tymokhanov, Dmytro and Shlomovits, Omer},
  title        = {{Alpha-Rays: Key Extraction Attacks on Threshold ECDSA
                  Implementations}},
  year         = {2021},
  howpublished = {Cryptology ePrint Archive, Paper 2021/1621},
  url          = {https://eprint.iacr.org/2021/1621}
}

% ==============================================================================
% Hyperledger Fabric
% ==============================================================================

@misc{hlf-docs,
  author       = {{Hyperledger Foundation}},
  title        = {{Hyperledger Fabric Documentation}},
  year         = {2024},
  howpublished = {Read the Docs},
  url          = {https://hyperledger-fabric.readthedocs.io/en/latest/},
  note         = {v3.0, LF Decentralized Trust}
}

@misc{hlf-v3,
  author       = {{LF Decentralized Trust}},
  title        = {{Version 3.0 of Hyperledger Fabric Now Available}},
  year         = {2024},
  month        = sep,
  howpublished = {Press Release},
  url          = {https://www.prnewswire.com/news-releases/version-3-0-of-hyperledger-fabric-an-lf-decentralized-trust-project-now-available-302248508.html}
}

@article{sutradhar2023hlf-iam,
  author  = {Sutradhar, Shrabani and Karforma, Sunil and Bose, Rajesh and
             Roy, Sandip and Djebali, Sonia and Bhattacharyya, Debnath},
  title   = {{Enhancing Identity and Access Management Using Hyperledger Fabric
             and OAuth 2.0: A Blockchain-Based Approach for Security and
             Scalability for Healthcare Industry}},
  journal = {Blockchain: Research and Applications},
  year    = {2023},
  publisher = {Elsevier},
  doi     = {10.1016/j.bcra.2023.100168}
}

% ==============================================================================
% Additional References (expanded for academic breadth)
% ==============================================================================

% Industry & Standards

@misc{nist-sp800-63b,
  author       = {{National Institute of Standards and Technology}},
  title        = {{Digital Identity Guidelines: Authentication and Lifecycle Management}},
  year         = {2017},
  howpublished = {NIST Special Publication 800-63B},
  url          = {https://doi.org/10.6028/NIST.SP.800-63b},
  note         = {Revision 3, defines multi-factor authentication requirements}
}

@misc{enisa-threshold-2020,
  author       = {{European Union Agency for Cybersecurity (ENISA)}},
  title        = {{Remote ID Proofing: Analysis of Methods to Carry Out Identity
                  Proofing Remotely}},
  year         = {2022},
  howpublished = {ENISA Report},
  url          = {https://www.enisa.europa.eu/publications/remote-id-proofing},
  note         = {Discusses distributed identity verification approaches}
}

@misc{w3c-did-core,
  author       = {Sporny, Manu and Longley, Dave and Sabadello, Markus and
                  Reed, Drummond and Steele, Orie and Allen, Christopher},
  title        = {{Decentralized Identifiers (DIDs) v1.0}},
  year         = {2022},
  howpublished = {W3C Recommendation},
  url          = {https://www.w3.org/TR/did-core/},
  note         = {Core architecture for decentralized identity}
}

@misc{w3c-vc-data-model,
  author       = {Sporny, Manu and Noble, Grant and Longley, Dave and
                  Burnett, Daniel C. and Zundel, Brent and Backes, Kyle Den Hartog},
  title        = {{Verifiable Credentials Data Model v2.0}},
  year         = {2024},
  howpublished = {W3C Recommendation},
  url          = {https://www.w3.org/TR/vc-data-model-2.0/}
}

% Threshold Signing in Practice

@inproceedings{boneh2024accountable,
  author    = {Boneh, Dan and Komlo, Chelsea},
  title     = {{Threshold Signatures with Private Accountability}},
  booktitle = {Financial Cryptography and Data Security (FC 2024)},
  year      = {2024},
  publisher = {Springer},
  note      = {Accountability in threshold signatures — directly related to our work}
}

@misc{fireblocks-mpc,
  author       = {{Fireblocks}},
  title        = {{MPC-CMP: Fireblocks' Next Generation MPC Algorithm}},
  year         = {2023},
  howpublished = {Fireblocks Whitepaper},
  url          = {https://www.fireblocks.com/what-is-mpc/},
  note         = {Industry deployment of threshold ECDSA (CGGMP-based)}
}

% Related SSO/Identity Papers

@inproceedings{verisso2025,
  author    = {Alom, Md Raju and Bhujel, Diwas and Xiao, Yang},
  title     = {{VeriSSO: A Privacy-Preserving OIDC-Compatible Single Sign-On
               Protocol Using Verifiable Credentials}},
  year      = {2025},
  howpublished = {IACR ePrint Archive, Paper 2025/511},
  url       = {https://eprint.iacr.org/2025/511},
  note      = {Preprint — not yet peer-reviewed}
}

@article{lpbt-sso2025,
  author    = {Zhang, Yongjun and Xu, Chungen and Li, Hongwei and Yang, Kan and
               Cheng, Nan and Shen, Xuemin},
  title     = {{LPbT-SSO: Password-Based Threshold Single-Sign-On Authentication
               From LWE}},
  journal   = {IEEE Transactions on Dependable and Secure Computing},
  year      = {2025},
  publisher = {IEEE},
  note      = {Post-quantum threshold SSO}
}

@inproceedings{pesto2020,
  author    = {Baum, Carsten and Frederiksen, Tore Kasper and Hesse, Julia and
               Lehmann, Anja and Yanai, Avishay},
  title     = {{PESTO: Proactively Secure Distributed Single Sign-On, or How to
               Trust a Hacked Server}},
  booktitle = {IEEE European Symposium on Security and Privacy (EuroS\&P)},
  year      = {2020},
  pages     = {587--606},
  publisher = {IEEE},
  doi       = {10.1109/EuroSP48549.2020.00044}
}

@article{tsapp2023,
  author    = {Agrawal, Shashank and Miao, Peihan and Mohassel, Payman and
               Mukherjee, Pratyay},
  title     = {{TSAPP: Threshold Single-Sign-On Authentication Preserving Privacy}},
  journal   = {IEEE Transactions on Dependable and Secure Computing},
  year      = {2023},
  publisher = {IEEE}
}

% Security Foundations

@inproceedings{canetti2001uc,
  author    = {Canetti, Ran},
  title     = {{Universally Composable Security: A New Paradigm for Cryptographic
               Protocols}},
  booktitle = {42nd IEEE Symposium on Foundations of Computer Science (FOCS)},
  year      = {2001},
  pages     = {136--145},
  publisher = {IEEE},
  doi       = {10.1109/SFCS.2001.959888}
}

@misc{rfc7519-jwt,
  author       = {Jones, Michael B. and Bradley, John and Sakimura, Nat},
  title        = {{JSON Web Token (JWT)}},
  year         = {2015},
  howpublished = {IETF RFC 7519},
  url          = {https://www.rfc-editor.org/rfc/rfc7519}
}

@misc{rfc7517-jwk,
  author       = {Jones, Michael B.},
  title        = {{JSON Web Key (JWK)}},
  year         = {2015},
  howpublished = {IETF RFC 7517},
  url          = {https://www.rfc-editor.org/rfc/rfc7517}
}

@misc{rfc6238-totp,
  author       = {M'Raihi, David and Machani, Salah and Pei, Mingliang and Rydell, Johan},
  title        = {{TOTP: Time-Based One-Time Password Algorithm}},
  year         = {2011},
  howpublished = {IETF RFC 6238},
  url          = {https://www.rfc-editor.org/rfc/rfc6238}
}

% Blockchain-Identity Additional

@inproceedings{liu2025fadid,
  author    = {Liu, Yang and Zhao, Zhen and Zhao, Bo and Ran, Fuping and
               Lin, Xiaodong and Li, Dongxiao and Guan, Zhitao},
  title     = {{Fully Anonymous Decentralized Identity Supporting Threshold
               Traceability with Practical Blockchain}},
  booktitle = {Proceedings of the ACM Web Conference (WWW '25)},
  year      = {2025},
  pages     = {3628--3638},
  publisher = {ACM},
  doi       = {10.1145/3696410.3714762}
}

@article{bashar2024,
  author    = {Shuhan, M. K. B. and Hasnayeen, S. M. and Das, T. K. and
               Sakib, M. N. and Ferdous, M. S.},
  title     = {{Decentralised Identity Federations Using Blockchain}},
  journal   = {International Journal of Information Security},
  year      = {2024},
  volume    = {23},
  number    = {4},
  pages     = {2573--2596},
  publisher = {Springer},
  doi       = {10.1007/s10207-024-00864-6}
}

@inproceedings{belfaik2023,
  author    = {Belfaik, Hajar and Bouras, Abdelkrim and Benlahmar, El Habib},
  title     = {{A Novel Secure and Privacy-Preserving Model for OpenID Connect
               Based on Blockchain}},
  journal   = {IEEE Access},
  year      = {2023},
  volume    = {11},
  pages     = {67929--67945},
  doi       = {10.1109/ACCESS.2023.3292143}
}

@article{krishna2023sshdauth,
  author    = {Krishna, D. Prasanna and Ramaguru, R. and Praveen, K. and others},
  title     = {{SSH-DAuth: Secret Sharing Based Decentralized OAuth Using
               Decentralized Identifier}},
  journal   = {Scientific Reports},
  year      = {2023},
  volume    = {13},
  pages     = {18024},
  publisher = {Nature},
  doi       = {10.1038/s41598-023-44586-6}
}
```
