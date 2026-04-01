# Protokol Tasarımı — Threshold-Based OIDC

## Notasyon Tablosu

| Sembol | Anlam |
|--------|-------|
| n | Toplam HLF peer sayısı (IdP node) |
| t | Eşik değeri: geçerli imza için minimum peer sayısı (t ≤ n) |
| P_i | Peer i (i ∈ {1, ..., n}) |
| sk | Ortak ECDSA private key (hiçbir taraf bilmez) |
| sk_i | Peer i'nin private key share'i |
| pk | Ortak ECDSA public key (P-256, ES256 uyumlu) |
| C_j | Feldman VSS commitment j (g^{a_j} mod p) |
| σ_i | Peer i'nin partial ECDSA imzası |
| σ | Birleştirilmiş tam ECDSA imzası (r, s) |
| U | Kullanıcı (End-User) |
| RP | Relying Party (OIDC Client) |
| Coord | Coordinator node — akış yöneticisi (signing authority değil) |
| H() | SHA-256 hash fonksiyonu |
| G | P-256 (secp256r1) curve generator point |
| S | Signing committee — DKG'ye katılan t veya daha fazla peer |

## Sistem Mimarisi

```
┌──────────┐     ┌──────────────────────────────────────────┐     ┌──────────┐
│          │     │         Threshold-OIDC IdP Cluster        │     │          │
│          │     │                                            │     │          │
│  User U  │────▶│  ┌─────────────┐   ┌────┐ ┌────┐ ┌────┐  │     │   RP     │
│          │     │  │ Coordinator │   │ P1 │ │ P2 │ │ Pn │  │     │ (Client) │
│          │     │  │   (Coord)   │◀─▶│    │ │    │ │    │  │     │          │
│          │     │  └──────┬──────┘   └──┬─┘ └──┬─┘ └──┬─┘  │     │          │
│          │     │         │             │      │      │     │     │          │
│          │     │         ▼             ▼      ▼      ▼     │     │          │
│          │     │  ┌──────────────────────────────────────┐  │     │          │
│          │     │  │       Hyperledger Fabric Ledger       │  │     │          │
│          │     │  │  (DKG records, accountability logs)   │  │     │          │
│          │     │  └──────────────────────────────────────┘  │     │          │
│          │     └──────────────────────────────────────────┘     │          │
│          │◀────────────────── id_token (JWT) ──────────────────▶│          │
└──────────┘                                                      └──────────┘
```

## Varsayılan Parametreler

| Parametre | Varsayılan | Gerekçe |
|-----------|-----------|---------|
| n | 5 | PoC için yeterli, gerçek dünyada 7-11 |
| t | 3 | (3,5) = majority threshold, 2 arıza tolere |
| Curve | NIST P-256 | ES256 JWT imzalama standardı |
| DKG | CGGMP21 tabanlı | UC-secure, identifiable abort |
| Hash | SHA-256 | JWT standardı (ES256 = ECDSA + P-256 + SHA-256) |

---

## Phase 1 — Setup (Distributed Key Generation)

### 1.1 Amaç
n adet HLF peer'ı arasında ortak bir ECDSA anahtar çifti (sk, pk) oluşturulması. sk hiçbir tarafta tam olarak bulunmaz; her peer yalnızca kendi share'ini (sk_i) tutar.

### 1.2 DKG Protokolü (Off-Chain)

**Neden off-chain:** HLF chaincode deterministik olmalıdır — aynı input ile aynı output üretmelidir. DKG ise kriptografik rastgelelik gerektirir (her peer rastgele polinom seçer). Bu nedenle DKG off-chain yapılır, yalnızca sonuçları (pk, commitments) ledger'a kaydedilir. (Endişe 4 çözümü)

**Protokol adımları (CGGMP21 DKG):**

```
DKG Protokolü (tek seferlik, off-chain)
═══════════════════════════════════════

Girdiler:
  - n peer: P_1, ..., P_n
  - Eşik değeri: t
  - Curve: P-256

Round 1 — Commitment:
  Her P_i:
    1. Rastgele polinom seç: f_i(x) = a_{i,0} + a_{i,1}·x + ... + a_{i,t-1}·x^{t-1}
       (a_{i,0} peer i'nin secret contribution'ı)
    2. Feldman VSS commitments hesapla:
       C_{i,j} = a_{i,j} · G    (j = 0, ..., t-1)
    3. Her P_j'ye share gönder:
       s_{i→j} = f_i(j)         (güvenli kanal üzerinden)
    4. Commitment'ları tüm peer'lara broadcast et:
       {C_{i,0}, C_{i,1}, ..., C_{i,t-1}}

Round 2 — Verification:
  Her P_j, aldığı her s_{i→j} share'ini doğrular:
    s_{i→j} · G  =?=  Σ_{k=0}^{t-1} j^k · C_{i,k}
  Doğrulama başarısızsa → P_i complaint olarak raporlanır

Round 3 — Key Computation:
  Her P_j kendi final share'ini hesaplar:
    sk_j = Σ_{i=1}^{n} s_{i→j}
  Ortak public key:
    pk = Σ_{i=1}^{n} C_{i,0}   (= sk · G, ama sk hiç hesaplanmaz)
```

### 1.3 DKG Sonuçlarının Ledger'a Kaydı

DKG tamamlandığında aşağıdaki bilgiler HLF ledger'a yazılır (chaincode tx):

```json
{
  "type": "DKG_RESULT",
  "timestamp": "2026-...",
  "publicKey": "<pk, P-256 uncompressed>",
  "threshold": 3,
  "totalPeers": 5,
  "participants": ["P1", "P2", "P3", "P4", "P5"],
  "commitments": {
    "P1": ["C_{1,0}", "C_{1,1}", "C_{1,2}"],
    "P2": ["C_{2,0}", "C_{2,1}", "C_{2,2}"],
    ...
  },
  "status": "ACTIVE"
}
```

### 1.4 OIDC Discovery & JWKS Endpoint

Ortak public key, standart OIDC discovery mekanizması ile yayınlanır:

**`/.well-known/openid-configuration`:**
```json
{
  "issuer": "https://threshold-oidc.example.com",
  "authorization_endpoint": "https://threshold-oidc.example.com/authorize",
  "token_endpoint": "https://threshold-oidc.example.com/token",
  "jwks_uri": "https://threshold-oidc.example.com/.well-known/jwks.json",
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

**`/.well-known/jwks.json`:**
```json
{
  "keys": [{
    "kty": "EC",
    "crv": "P-256",
    "x": "<pk.x base64url>",
    "y": "<pk.y base64url>",
    "kid": "threshold-key-1",
    "use": "sig",
    "alg": "ES256"
  }]
}
```

**RP perspektifi:** RP bu public key'i standart OIDC kütüphanesiyle çeker ve id_token imzasını doğrular. RP'nin threshold mekanizmadan haberi yoktur — tam geriye uyumluluk.

---

## Phase 2 — User Authentication (Multi-Factor)

### 2.1 OIDC Authorization Code Flow (Uyumlu)

Standart OIDC Authorization Code Flow korunur. RP ve kullanıcı perspektifinden akış değişmez:

```
User Authentication Flow
═══════════════════════

1. RP → User:    HTTP 302 Redirect
   Location: https://threshold-oidc.example.com/authorize?
     response_type=code
     &client_id=rp-client-1
     &redirect_uri=https://rp.example.com/callback
     &scope=openid profile
     &state=<csrf_token>
     &nonce=<replay_protection>

2. User → Coord:  Authorization Request gelir
   Coord oturum oluşturur, login sayfası sunar

3. User → Coord:  Credentials gönderir (username + password + MFA)

4. Coord → P_i:   MFA doğrulama isteği (en az t peer'a)
   {
     "type": "AUTH_REQUEST",
     "sessionId": "<uuid>",
     "userHash": H(username || realm),
     "mfaToken": "<totp_or_webauthn>",
     "nonce": "<oidc_nonce>",
     "timestamp": "<iso8601>"
   }

5. Her P_i:
   a. Kullanıcı credential'ını kendi veritabanından doğrular
   b. MFA token'ı doğrular (TOTP/WebAuthn)
   c. Onay veya red yanıtı döner:
   {
     "type": "AUTH_RESPONSE",
     "peerId": "P_i",
     "sessionId": "<uuid>",
     "approved": true,
     "signature": sign(H(sessionId || approved), peer_auth_key_i)
   }

6. Coord:
   - En az t adet onay toplar
   - t'den az onay → authentication failed
   - t veya fazla onay → authorization code üretir, Phase 3'e geçer

7. Coord → User:  HTTP 302 Redirect
   Location: https://rp.example.com/callback?
     code=<authorization_code>
     &state=<csrf_token>
```

### 2.2 MFA Mekanizması

Her peer bağımsız olarak kullanıcıyı doğrular. Bu, tek bir peer'ın ele geçirilmesiyle kimlik doğrulamanın atlatılmasını önler:

- **Faktör 1:** Password hash doğrulama (her peer'da ayrı hash saklanır)
- **Faktör 2:** TOTP (RFC 6238) veya WebAuthn/FIDO2
- **Threshold:** En az t peer kullanıcıyı başarıyla doğrulamalı

### 2.3 Coordinator Rolü

Coordinator bir **akış yöneticisi**dir, güvenlik açısından ayrıcalıklı değildir:

- Private key share TUTMAZ
- Token imzalama yeteneği YOKTUR
- Görevi: HTTP endpoint sunma, oturum yönetimi, peer yanıtlarını toplama
- Coordinator ele geçirilse bile: DoS yapabilir ama token forge EDEMEZ
- Tek hata noktası riski: Coordinator birden fazla çalıştırılabilir (load balancer arkasında)

---

## Phase 3 — Token Production (Partial Signing + Aggregation)

### 3.1 JWT Payload Hazırlama

Coordinator, authentication başarılı olduktan sonra standart OIDC id_token payload'ını oluşturur:

```json
{
  "iss": "https://threshold-oidc.example.com",
  "sub": "user-12345",
  "aud": "rp-client-1",
  "exp": 1711900800,
  "iat": 1711897200,
  "nonce": "<oidc_nonce>",
  "auth_time": 1711897195,
  "amr": ["pwd", "otp"],
  "threshold_peers": 3
}
```

JWT Header:
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "threshold-key-1"
}
```

Signing input: `message = Base64url(header) || "." || Base64url(payload)`

### 3.2 Partial Signing (Threshold ECDSA)

```
Threshold Signing Protocol (CGGMP21-based)
══════════════════════════════════════════

Girdiler:
  - message: JWT signing input (header.payload)
  - S ⊆ {P_1,...,P_n}: signing committee, |S| ≥ t
  - Her P_i ∈ S: kendi share'i sk_i

Pre-signing (message-independent, önceden hesaplanabilir):
  1. Her P_i ∈ S:
     - Rastgele k_i, γ_i seç
     - Paillier encryption ile MtA sub-protocol çalıştır
     - Sonuç: her P_i, (k_i, χ_i) değerlerine sahip olur
       burada k = Σ k_i  ve  k·sk = Σ χ_i  (mod q)

Signing (message-dependent):
  2. Her P_i ∈ S:
     - R = (Σ Γ_i) noktasını hesapla
     - r = R.x mod q
     - Partial signature hesapla:
       σ_i = k_i · H(message) + r · χ_i   (mod q)
     - σ_i'yi Coordinator'a gönder

  3. Coordinator:
     - Signature birleştir: s = Σ σ_i  (mod q)
     - Final ECDSA signature: (r, s)
     - DER encode → Base64url → JWT signature kısmı
```

### 3.3 Partial Signature Doğrulama (Feldman VSS)

Bu adım Accountability Protocol'ün (Faz 2B) temelidir. Signing sırasında her partial signature'ın geçerliliği doğrulanabilir:

```
Feldman VSS Doğrulama
═════════════════════

Her P_j, P_i'nin partial signature σ_i'sini doğrulayabilir:

1. DKG'den bilinen commitment'lar: {C_{i,0}, ..., C_{i,t-1}}
2. P_i'nin public key share'i:
   pk_i = Σ_{k=0}^{t-1} i^k · C_{k}   (Lagrange interpolasyonu ile)
3. σ_i ile pk_i tutarlılığını kontrol et

Doğrulama başarısızsa:
  → P_i kötü niyetli (misbehaving)
  → Evidence = {σ_i, pk_i, commitments, message}
  → Accountability Protocol'e aktar (Phase 2B)
```

### 3.4 JWT Oluşturma

```
Final JWT = Base64url(header) || "." || Base64url(payload) || "." || Base64url(signature)

Burada signature = ECDSA-Sig-Value (r, s) DER encoded → Base64url
```

Bu JWT, herhangi bir standart OIDC kütüphanesi (jose, nimbus-jose-jwt, go-jose) tarafından pk ile doğrulanabilir. RP'nin threshold mekanizmadan haberi yoktur.

---

## Phase 4 — Token Delivery

### 4.1 Authorization Code Exchange

Standart OIDC back-channel token exchange korunur:

```
Token Delivery (Authorization Code Flow)
═════════════════════════════════════════

1. RP → Coord:  Token Request (back-channel, HTTPS POST)
   POST /token HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=<authorization_code>
   &redirect_uri=https://rp.example.com/callback
   &client_id=rp-client-1
   &client_secret=<client_secret>

2. Coord:
   - Authorization code doğrula (one-time use, expiry check)
   - Phase 3'te üretilmiş id_token'ı al

3. Coord → RP:  Token Response
   HTTP/1.1 200 OK
   Content-Type: application/json

   {
     "access_token": "<opaque_access_token>",
     "token_type": "Bearer",
     "expires_in": 3600,
     "id_token": "<threshold_signed_jwt>",
     "scope": "openid profile"
   }

4. RP:
   - id_token'ı jwks_uri'den aldığı pk ile doğrular (standart OIDC)
   - Claims'leri okur (sub, aud, exp, nonce, vb.)
   - Kullanıcıya oturum açar
```

### 4.2 RP Uyumluluk Garantisi

RP perspektifinden Threshold-OIDC ile klasik OIDC arasında SIFIR fark vardır:

| Özellik | Klasik OIDC | Threshold-OIDC | RP Değişikliği |
|---------|------------|----------------|---------------|
| Discovery | /.well-known/openid-configuration | Aynı | Yok |
| JWKS | jwks_uri'den public key | Aynı (threshold pk) | Yok |
| Auth Flow | Authorization Code Flow | Aynı | Yok |
| Token Format | JWT (ES256/RS256) | JWT (ES256) | Yok |
| Token Validation | pk ile signature doğrulama | Aynı | Yok |
| Claims | iss, sub, aud, exp, iat, nonce | Aynı + threshold_peers | Yok |

---

## Tam Protokol Akışı (End-to-End)

```
┌──────┐        ┌────────┐        ┌──────┐ ┌──────┐ ┌──────┐        ┌─────────┐
│ User │        │ Coord  │        │  P1  │ │  P2  │ │  P3  │        │   RP    │
└──┬───┘        └───┬────┘        └──┬───┘ └──┬───┘ └──┬───┘        └────┬────┘
   │                │                │        │        │                  │
   │  ──────────────────────── SETUP (one-time) ────────────────────────  │
   │                │                │        │        │                  │
   │                │  DKG Round 1   │        │        │                  │
   │                │◄──────────────▶│◄──────▶│◄──────▶│                  │
   │                │  DKG Round 2   │        │        │                  │
   │                │◄──────────────▶│◄──────▶│◄──────▶│                  │
   │                │  Record pk     │        │        │                  │
   │                │──────────────▶ HLF Ledger ◀──────│                  │
   │                │  Publish JWKS  │        │        │                  │
   │                │────────────────────────────────────────────────────▶│
   │                │                │        │        │                  │
   │  ──────────────────────── AUTH REQUEST ─────────────────────────── │
   │                │                │        │        │                  │
   │  1. Login Page │                │        │        │  0. Redirect     │
   │◀───────────────│◀───────────────────────────────────────────────────│
   │  2. Credentials│                │        │        │                  │
   │───────────────▶│                │        │        │                  │
   │                │  3. MFA verify │        │        │                  │
   │                │───────────────▶│        │        │                  │
   │                │───────────────────────▶ │        │                  │
   │                │────────────────────────────────▶ │                  │
   │                │  4. Approvals  │        │        │                  │
   │                │◀───────────────│        │        │                  │
   │                │◀──────────────────────  │        │                  │
   │                │◀─────────────────────────────── │                  │
   │                │                │        │        │                  │
   │  ──────────────────────── TOKEN PRODUCTION ────────────────────── │
   │                │                │        │        │                  │
   │                │  5. Sign req   │        │        │                  │
   │                │───────────────▶│        │        │                  │
   │                │───────────────────────▶ │        │                  │
   │                │────────────────────────────────▶ │                  │
   │                │  6. σ_i        │        │        │                  │
   │                │◀───────────────│        │        │                  │
   │                │◀──────────────────────  │        │                  │
   │                │◀─────────────────────────────── │                  │
   │                │  7. Aggregate  │        │        │                  │
   │                │  σ = Σσ_i      │        │        │                  │
   │                │  JWT = h.p.σ   │        │        │                  │
   │                │                │        │        │                  │
   │  ──────────────────────── TOKEN DELIVERY ──────────────────────── │
   │                │                │        │        │                  │
   │  8. Redirect   │                │        │        │                  │
   │◀───────────────│ (code)         │        │        │                  │
   │────────────────────────────────────────────────────────────────────▶│
   │                │                │        │        │  9. Token Req    │
   │                │◀───────────────────────────────────────────────────│
   │                │                │        │        │  10. id_token    │
   │                │────────────────────────────────────────────────────▶│
   │                │                │        │        │  11. Verify(pk)  │
   │                │                │        │        │                  │
```

---

## Güvenlik Özellikleri (Phase 2A Kapsamında)

| Özellik | Sağlayan Mekanizma |
|---------|-------------------|
| SPOF eliminasyonu | t-of-n threshold — tek peer'ın key share'i işe yaramaz |
| Key compromise resistance | sk hiç hesaplanmaz, yalnızca share'ler var |
| Byzantine fault tolerance | t-1 arızalı/kompromize peer tolere edilir |
| Forward secrecy | Proactive key refresh (CGGMP21) ile sağlanabilir |
| Replay protection | OIDC nonce + exp claim |
| OIDC backward compatibility | Standart JWT, standart JWKS, standart flows |
| Identifiable abort | CGGMP21'in built-in özelliği → Accountability Protocol temeli |

## Accountability Protocol (Özgün Katkı #2 — RQ2)

Bu protokol makalenin **en özgün katkısı**dır. VeriSSO, PASTA, PESTO, TSAPP, LPbT-SSO, PROTECT — hiçbirinde server-side misbehavior detection + immutable evidence + automated sanctions mekanizması yoktur.

### Misbehavior Tipleri

| Tip | Açıklama | Tespit Mekanizması |
|-----|----------|-------------------|
| **M1 — Invalid Partial Signature** | P_i geçersiz σ_i gönderir | Feldman VSS commitment doğrulama |
| **M2 — Timeout / Non-Response** | P_i süresi içinde yanıt vermez | Timeout watchdog (Coord) |
| **M3 — Inconsistent Share** | P_i farklı oturumlarda çelişkili share kullanır | Cross-session commitment karşılaştırma |
| **M4 — Equivocation** | P_i aynı oturumda farklı peer'lara farklı σ_i gönderir | Peer-to-peer σ_i karşılaştırma |

### Aşama 1 — Tespit (Detection)

#### 1.1 Feldman VSS Doğrulama (M1 Tespiti)

Token üretimi sırasında (Phase 3), her partial signature σ_i kriptografik olarak doğrulanabilir:

```
Misbehavior Detection — Feldman VSS Verification
═════════════════════════════════════════════════

Girdiler:
  - σ_i: P_i'nin partial signature'ı
  - C = {C_0, ..., C_{t-1}}: DKG'den Feldman commitments
  - message: imzalanacak JWT (header.payload)
  - i: peer indeksi

Doğrulama:
  1. P_i'nin public key share'ini hesapla:
     pk_i = Σ_{k=0}^{t-1} i^k · C_k

  2. Partial signature konsistans kontrolü:
     σ_i · G  =?=  k_i · H(message) · G + r · χ_i · G

     Bu kontrol, CGGMP21 identifiable abort mekanizmasının
     bir parçasıdır. σ_i, pk_i ve commitment'lar ile
     tutarlı olmalıdır.

  3. Sonuç:
     - Doğrulama BAŞARILI → P_i dürüst (bu oturumda)
     - Doğrulama BAŞARISIZ → M1 misbehavior tespit edildi

Önemli özellik:
  - FALSE POSITIVE İMKANSIZ: Doğrulama tamamen kriptografik.
    Dürüst bir peer'ın σ_i'si Feldman commitment'larıyla
    HER ZAMAN tutarlıdır. Matematiksel garanti.
  - Tespit edilen peer KENDİNİ AKLAYAMAZ: Geçersiz σ_i
    kanıtın kendisidir — peer "yanlış anladım" diyemez.
```

#### 1.2 Timeout Detection (M2 Tespiti)

```
Timeout Detection
═════════════════

Parametreler:
  - T_sign: Signing timeout (varsayılan: 5 saniye)
  - T_auth: Authentication timeout (varsayılan: 10 saniye)

Akış:
  1. Coord, signing isteğini t+f peer'a gönderir
     (f = yedek peer sayısı, f ≤ n-t)
  2. T_sign süresi içinde σ_i gelmezse:
     → P_i TIMEOUT olarak işaretlenir
     → M2 misbehavior kaydı oluşturulur
  3. En az t yanıt gelirse:
     → Timeout olan peer'lar atlanır, signing devam eder
  4. t yanıt gelmezse:
     → Signing başarısız, yeniden deneme (farklı peer seti)

Not: Timeout tek başına kötü niyet göstermez (ağ sorunu
olabilir). Bu yüzden yaptırım eşiği M1'den yüksektir:
  - M1 (geçersiz σ_i): 3 ihlal → devre dışı
  - M2 (timeout): 10 ihlal → devre dışı
```

### Aşama 2 — Kanıt Üretimi (Evidence Generation)

#### 2.1 Evidence Package Formatı

```json
{
  "evidenceId": "ev-<uuid>",
  "type": "M1_INVALID_SIGNATURE | M2_TIMEOUT | M3_INCONSISTENT | M4_EQUIVOCATION",
  "timestamp": "2026-03-30T12:00:00Z",
  "accusedPeer": "P_3",
  "sessionId": "sess-<uuid>",

  "cryptographicEvidence": {
    "invalidPartialSignature": "<σ_3 — base64>",
    "expectedCommitments": ["<C_0>", "<C_1>", "<C_2>"],
    "message": "<JWT signing input — base64>",
    "peerIndex": 3,
    "verificationResult": false
  },

  "witnesses": [
    {
      "peerId": "P_1",
      "attestation": "I verified σ_3 against commitments and it failed",
      "signature": "<P_1's signature over this evidence>"
    },
    {
      "peerId": "P_2",
      "attestation": "I verified σ_3 against commitments and it failed",
      "signature": "<P_2's signature over this evidence>"
    }
  ],

  "requiredWitnesses": 2,
  "collectedWitnesses": 2,
  "evidenceHash": "H(evidenceId || type || accusedPeer || cryptographicEvidence)"
}
```

#### 2.2 Evidence Generation Akışı

```
Evidence Generation Flow
════════════════════════

1. Tespit:
   P_j, P_i'nin σ_i'sini doğrular → BAŞARISIZ

2. Corroboration (doğrulama):
   P_j, diğer peer'lardan (P_k, k ≠ i,j) doğrulama ister:
   "P_i'nin bu σ_i'si sizde de başarısız mı?"
   → En az (t-1) peer onaylamalı (false accusation koruması)

3. Paketleme:
   P_j evidence package oluşturur:
   - Geçersiz σ_i
   - DKG commitment'ları (public, ledger'da zaten var)
   - Witness imzaları (t-1 peer)
   - Zaman damgası

4. Blockchain Kaydı:
   P_j, RecordMisbehavior chaincode fonksiyonunu çağırır
```

#### 2.3 False Positive Analizi

| Senaryo | False Positive Riski | Açıklama |
|---------|---------------------|----------|
| M1 — Geçersiz σ_i | **İMKANSIZ** | Feldman VSS doğrulaması deterministik ve kriptografik. Dürüst peer'ın σ_i'si commitment'larla HER ZAMAN tutarlıdır. |
| M2 — Timeout | **DÜŞÜK** | Ağ gecikmesi false positive yaratabilir. Hafifletme: yüksek yaptırım eşiği (10 ihlal) ve timeout süresi ayarlanabilir. |
| M3 — Inconsistent | **İMKANSIZ** | Commitment'lar ledger'da, karşılaştırma deterministik. |
| M4 — Equivocation | **İMKANSIZ** | Farklı σ_i değerleri peer imzalarıyla kanıtlanır. |

**Kritik güvenlik özelliği:** M1, M3 ve M4 tespitlerinde false positive kriptografik olarak imkansızdır. Bu, yaptırım mekanizmasının güvenilirliğini garanti eder.

### Aşama 3 — Blockchain Kaydı ve Yaptırımlar (Immutable Logging)

#### 3.1 Chaincode API

```go
// AccountabilityChaincode — HLF Smart Contract
// Channel: accountability-channel

// RecordMisbehavior — Kanıt doğrula ve ledger'a kaydet
// Endorsement: en az t-1 peer'ın onayı gerekli
func RecordMisbehavior(ctx contractapi.TransactionContextInterface,
    evidenceJSON string) error {

    var evidence EvidencePackage
    json.Unmarshal([]byte(evidenceJSON), &evidence)

    // 1. Evidence format doğrulama
    if err := validateEvidenceFormat(evidence); err != nil {
        return fmt.Errorf("invalid evidence format: %w", err)
    }

    // 2. Kriptografik doğrulama: σ_i gerçekten geçersiz mi?
    if evidence.Type == "M1_INVALID_SIGNATURE" {
        valid := verifyPartialSignature(
            evidence.CryptographicEvidence.InvalidPartialSignature,
            evidence.CryptographicEvidence.ExpectedCommitments,
            evidence.CryptographicEvidence.Message,
            evidence.CryptographicEvidence.PeerIndex,
        )
        if valid {
            return fmt.Errorf("evidence invalid: partial signature is actually valid")
        }
    }

    // 3. Witness imzalarını doğrula (en az t-1)
    if len(evidence.Witnesses) < t-1 {
        return fmt.Errorf("insufficient witnesses: need %d, got %d", t-1, len(evidence.Witnesses))
    }
    for _, w := range evidence.Witnesses {
        if !verifyWitnessSignature(w) {
            return fmt.Errorf("invalid witness signature from %s", w.PeerId)
        }
    }

    // 4. Ledger'a kaydet
    key := fmt.Sprintf("MISBEHAVIOR_%s_%s", evidence.AccusedPeer, evidence.EvidenceId)
    ctx.GetStub().PutState(key, []byte(evidenceJSON))

    // 5. İhlal sayacını artır
    countKey := fmt.Sprintf("STRIKE_COUNT_%s", evidence.AccusedPeer)
    count := incrementStrikeCount(ctx, countKey, evidence.Type)

    // 6. Yaptırım eşiği kontrolü
    checkAndApplySanction(ctx, evidence.AccusedPeer, count, evidence.Type)

    return nil
}

// QueryMisbehaviorHistory — Peer'ın ihlal geçmişini sorgula
func QueryMisbehaviorHistory(ctx contractapi.TransactionContextInterface,
    peerId string) ([]EvidencePackage, error) {
    // Range query: MISBEHAVIOR_<peerId>_*
    ...
}

// GetPeerStatus — Peer'ın aktif/devre dışı durumunu kontrol et
func GetPeerStatus(ctx contractapi.TransactionContextInterface,
    peerId string) (PeerStatus, error) {
    // PEER_STATUS_<peerId> oku
    ...
}

// GetAllPeerStatuses — Tüm peer'ların durumunu toplu sorgula
func GetAllPeerStatuses(ctx contractapi.TransactionContextInterface) ([]PeerStatus, error) {
    // Range query: PEER_STATUS_*
    ...
}
```

#### 3.2 Yaptırım Mekanizması (Strike System)

```
Sanction Mechanism — Strike-Based
══════════════════════════════════

İhlal Tipleri ve Eşikleri:
  ┌───────────────────┬─────────────┬────────────────────────┐
  │ İhlal Tipi        │ Eşik        │ Yaptırım               │
  ├───────────────────┼─────────────┼────────────────────────┤
  │ M1 (Geçersiz σ_i) │ 1. ihlal    │ WARNING — log kaydı    │
  │                   │ 2. ihlal    │ PROBATION — izleme      │
  │                   │ 3. ihlal    │ DISABLED — devre dışı   │
  ├───────────────────┼─────────────┼────────────────────────┤
  │ M2 (Timeout)      │ 1-5. ihlal  │ WARNING                │
  │                   │ 6-9. ihlal  │ PROBATION              │
  │                   │ 10. ihlal   │ DISABLED               │
  ├───────────────────┼─────────────┼────────────────────────┤
  │ M3 (Inconsistent) │ 1. ihlal    │ DISABLED (kritik)      │
  ├───────────────────┼─────────────┼────────────────────────┤
  │ M4 (Equivocation) │ 1. ihlal    │ DISABLED (kritik)      │
  └───────────────────┴─────────────┴────────────────────────┘

Devre dışı bırakılan peer:
  1. Signing committee'den çıkarılır
  2. DKG share'i geçersizleştirilir (key refresh tetiklenir)
  3. Yeniden etkinleştirme: yalnızca konsorsiyum yönetim kararıyla
     (off-chain governance → chaincode tx)

Peer durumları ledger'da:
  {
    "peerId": "P_3",
    "status": "DISABLED",
    "totalStrikes": {"M1": 3, "M2": 1, "M3": 0, "M4": 0},
    "disabledAt": "2026-04-15T10:30:00Z",
    "disabledReason": "M1_THRESHOLD_EXCEEDED",
    "history": ["ev-uuid-1", "ev-uuid-2", "ev-uuid-3"]
  }
```

#### 3.3 Key Refresh After Disabling

Bir peer devre dışı bırakıldığında, kalan peer'lar **proactive key refresh** çalıştırır:

```
Key Refresh (post-disabling)
════════════════════════════

Tetikleyici: P_i DISABLED durumuna geçti

1. Kalan n-1 peer (veya n-k peer, k = disabled count)
   yeni bir DKG çalıştırır:
   - Yeni threshold: t' = ceil((n-k)/2) + 1 veya aynı t (n-k ≥ t ise)
   - Yeni share'ler üretilir
   - Yeni pk' hesaplanır

2. Yeni pk' ledger'a kaydedilir
3. JWKS endpoint güncellenir (kid değişir)
4. Eski pk → "retired keys" listesine (grace period boyunca
   mevcut token'lar doğrulanabilir)

Not: CGGMP21 proactive key refresh bunu verimli şekilde
destekler — sıfırdan DKG gerekmez, resharing yeterlidir.
```

### "Neden Blockchain Gerekli?" — 4 Argüman

| # | Argüman | Alternatif | Blockchain Avantajı |
|---|---------|-----------|-------------------|
| 1 | **Kanıtın değiştirilemezliği** | Merkezi veritabanı | Kompromize peer kanıtı silebilir/değiştirebilir. Ledger immutable — kanıt kalıcı. |
| 2 | **Yaptırım kararının dağıtık onayı** | Tek otoriteye güven | Endorsement policy ile t-1 peer'ın onayı gerekli. Tek taraflı yaptırım imkansız. |
| 3 | **Denetlenebilirlik** | Kapalı log dosyaları | Tüm misbehavior geçmişi şeffaf, herhangi bir peer denetleyebilir. |
| 4 | **Güven modeli — hiçbir tek taraf kanıtı silemez** | Trusted third party | Kötü niyetli peer sayısı < t olduğu sürece kanıt güvende. TTP gerektirmez. |

**Kritik nokta:** Argüman 1 ve 4 birlikte, blockchain kullanımının "gerçekten gerekli" olduğunu kanıtlar. Basit bir veritabanında kompromize peer(lar) kanıtı manipüle edebilir — blockchain bunu önler. Bu, akademik hakemlerin "blockchain neden gerekli?" sorusuna güçlü bir yanıttır.

### Accountability Protocol — Tam Akış

```
┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐    ┌─────────────┐
│  P1  │    │  P2  │    │ P3*  │    │  P4  │    │ HLF Ledger  │
└──┬───┘    └──┬───┘    └──┬───┘    └──┬───┘    └──────┬──────┘
   │           │           │           │               │
   │  ─────── SIGNING REQUEST ─────────────────────── │
   │           │           │           │               │
   │  σ_1 ────▶│           │           │               │
   │           │  σ_2 ────▶│           │               │
   │           │           │  σ_3* ───▶│  (geçersiz!)  │
   │           │           │           │               │
   │  ─────── DETECTION ──────────────────────────── │
   │           │           │           │               │
   │  Verify σ_3*          │           │               │
   │  FAILED ──┤           │           │               │
   │           │  Verify σ_3*          │               │
   │           │  FAILED ──┤           │               │
   │           │           │           │  Verify σ_3*  │
   │           │           │           │  FAILED ──────│
   │           │           │           │               │
   │  ─────── EVIDENCE GENERATION ────────────────── │
   │           │           │           │               │
   │  Witness  │           │           │               │
   │  sign ───▶│           │           │               │
   │           │  Witness  │           │               │
   │           │  sign ───▶│           │               │
   │           │           │           │               │
   │  Build evidence package (P1 or P2 initiates)     │
   │  {σ_3*, commitments, witnesses: [P1, P2, P4]}   │
   │           │           │           │               │
   │  ─────── BLOCKCHAIN RECORD ─────────────────── │
   │           │           │           │               │
   │  RecordMisbehavior(evidence) ─────────────────────▶│
   │           │           │           │  Chaincode:   │
   │           │           │           │  1. Verify σ_3* │
   │           │           │           │  2. Check witnesses │
   │           │           │           │  3. Store evidence │
   │           │           │           │  4. Increment strikes │
   │           │           │           │  5. Check threshold │
   │           │           │           │               │
   │  ─────── SANCTION (if threshold exceeded) ──── │
   │           │           │           │               │
   │           │           │  P3 status │               │
   │           │           │  = DISABLED◀──────────────│
   │           │           │           │               │
   │  ─────── KEY REFRESH ───────────────────────── │
   │           │           │           │               │
   │  New DKG (P1, P2, P4) │           │               │
   │◄─────────▶│◄─────────────────────▶│               │
   │  pk' → Ledger ────────────────────────────────────▶│
   │           │           │           │               │

* P3 = kötü niyetli peer (geçersiz partial signature gönderen)
```

---

## Entegrasyon: Normal vs Misbehavior Akışı

### Normal Akış (Happy Path)

Tüm peer'lar dürüst davranıyor:

```
User → Coord → [P1..Pn] (MFA) → t onay → [Signing committee] →
t adet geçerli σ_i → Feldman doğrulama BAŞARILI → σ = Σσ_i →
JWT oluştur → User → RP → Token doğrulama (pk ile) → Oturum aç

Accountability Protocol: DEVREDışı (tetiklenmez)
Blockchain etkileşimi: YOK (signing sırasında ledger kullanılmaz)
Ek latency: ~0ms (Feldman doğrulama in-memory, <1ms)
```

### Misbehavior Akışı (Unhappy Path)

En az 1 peer geçersiz partial signature gönderiyor:

```
User → Coord → [P1..Pn] (MFA) → t onay → [Signing committee] →
P_i geçersiz σ_i gönderir → Feldman doğrulama BAŞARISIZ →

  ┌── Normal signing devam eder mi? ──┐
  │                                    │
  │ EVET (t geçerli σ_i varsa):        │ HAYIR (t geçerli σ_i yoksa):
  │ → Geçersiz σ_i atlanır             │ → Yedek peer'lardan σ_i istenir
  │ → t geçerli σ_i ile JWT üretilir   │ → Yine t toplanamadıysa FAIL
  │ → User token'ı alır               │ → User hata mesajı alır
  │                                    │
  └────────────────────────────────────┘

  Paralel olarak (signing'i bloklamaz):
  → Evidence generation başlar
  → t-1 witness onayı toplanır
  → RecordMisbehavior chaincode çağrılır
  → Strike sayacı artırılır
  → Eşik aşıldıysa → peer DISABLED + key refresh
```

### Etkileşim Noktaları

| Olay | Threshold-OIDC Etkisi | Accountability Etkisi |
|------|----------------------|----------------------|
| Tüm σ_i geçerli | JWT üretilir, normal akış | Tetiklenmez |
| 1 geçersiz σ_i, t geçerli var | JWT üretilir (geçersiz atlanır) | Evidence → ledger kaydı |
| >n-t geçersiz σ_i | JWT üretilemez, FAIL | Evidence → ledger → olası disabling |
| Peer DISABLED | Committee'den çıkar | Key refresh tetiklenir |
| Key refresh tamamlanır | Yeni pk, yeni JWKS | Yeni DKG kaydı ledger'a |

---

## VeriSSO Farklılaşma Kontrolü

| Boyut | VeriSSO | Bizim Çalışma | Farklılaşma Notu |
|-------|---------|---------------|------------------|
| **Birincil odak** | Gizlilik (unlinkability) | SPOF eliminasyonu + accountability | TAMAMEN FARKLI motivasyon |
| **Threshold mekanizma** | AS komitesi, lightweight threshold sig | HLF peer'ları, CGGMP21 threshold ECDSA | Farklı altyapı ve kriptografik primitif |
| **Credential tipi** | BBS + ZKP (Verifiable Credentials) | Klasik OIDC claims (JWT) | Farklı identity model |
| **Blockchain** | YOK | HLF (accountability + DKG kaydı) | BİZDE VAR — özgün katkı |
| **Server misbehavior detection** | YOK | Feldman VSS + 4 misbehavior tipi | BİZDE VAR — özgün katkı |
| **Immutable evidence** | YOK | HLF ledger kaydı | BİZDE VAR — özgün katkı |
| **Automated sanctions** | YOK | Strike system + auto-disable | BİZDE VAR — özgün katkı |
| **User privacy** | Güçlü (unlinkability, selective disclosure) | Standart OIDC seviyesinde | VeriSSO ÜSTÜN |
| **RP uyumluluğu** | Evet (token doğrulama standart) | Evet (JWT ES256 standart) | EŞİT |
| **Post-disabling recovery** | Belirsiz | Key refresh (CGGMP21 resharing) | BİZDE VAR |

**Sonuç:** 4 boyutta (blockchain, detection, evidence, sanctions) tamamen özgün. 1 boyutta (privacy) VeriSSO üstün. Complementary çalışmalar — future work olarak birleşilebilir.
