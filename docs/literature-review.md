# Literatür Taraması

## Doğrudan Rakipler — Karşılaştırma Tablosu

| Çalışma | Yıl | Venue | Threshold | OIDC Uyumlu | Blockchain | Misbehavior Tespiti | Accountability |
|---------|-----|-------|:---------:|:-----------:|:----------:|:-------------------:|:--------------:|
| PASTA (Agrawal) | 2018 | CCS | ✓ | ✗ | ✗ | ✗ | ✗ |
| PESTO (Baum) | 2020 | EuroS&P | ✓ | Kısmen** | ✗ | Kısmen† | ✗ |
| PROTECT | 2020 | IEEE TDSC | ✓ | ✗ | ✗ | ✗ | ✗ |
| TSAPP | 2023 | IEEE TDSC | ✓ | ✗ | ✗ | ✗ | ✗ |
| Belfaik et al. | 2023 | — | ✗ | ✓ | ✓ | ✗ | ✗ |
| Bashar et al. | 2024 | — | ✗ | — | ✓ | ✗ | ✗ |
| VeriSSO | 2025 | ePrint | ✓ | ✓ | ✗ | ✗ | Kısmen* |
| LPbT-SSO (Zhang) | 2025 | — | ✓ | ✗ | ✗ | ✗ | ✗ |
| **Bizim** | **2026** | — | **✓** | **✓** | **✓ (HLF)** | **✓** | **✓** |

\** PESTO RSA-JWT ürettiği için OIDC RP'lerle kısmen uyumlu (RS256, standart ES256 değil).
\† PESTO proactive key refresh ile compromised sunucunun etkisini sınırlar ama tespit/kanıt/yaptırım mekanizması yok.
\* VeriSSO "Kısmen" accountability: Lawful de-anonymization ile kullanıcı accountability sağlıyor (AS komitesi kullanıcıyı de-anonim edebilir). Ancak **server/peer misbehavior accountability** yok — kötü niyetli AS tespiti, kanıt üretimi ve otomatik yaptırım mekanizması bulunmuyor. Bizim Accountability Protocol'ümüz server-side misbehavior'a odaklanıyor.

## VeriSSO Detaylı Analiz

**Kaynak:** Alom, Bhujel, Xiao — "VeriSSO: A Privacy-Preserving OIDC-Compatible Single Sign-On Protocol Using Verifiable Credentials" (IACR ePrint 2025/511)

### Teknik Özet

- **Yaklaşım:** Verifiable Credentials (VC) tabanlı, bağımsız Authentication Server (AS) komitesi ile threshold token üretimi
- **Threshold İmza:** Lightweight threshold signature scheme — AS komitesi identity token'ı threshold imza ile üretir, RP standart public-key kriptografi ile doğrular
- **Credential Altyapısı:** BBS signature ile VC issuance, ZKP-augmented verification ile selective disclosure
- **Token Formatı:** OIDC-uyumlu identity token — RP mevcut doğrulama rutinlerini değiştirmeden kullanabilir
- **OIDC Uyumluluğu:** Authorization Code Flow (ACF) ile tam uyumlu
- **Performans:** Tek SSO akışı ~30 milisaniye içinde tamamlanıyor
- **Blockchain:** KULLANMIYOR — bağımsız AS komitesi, merkezi olmayan ama blockchain'siz

### Odak ve Güvenlik Hedefleri

VeriSSO'nun birincil odağı **gizlilik (privacy)**:
- **User Unlinkability:** IdP kullanıcıyı RP'ler arasında takip edemiyor
- **RP Authentication:** RP'nin legal kimliği doğrulanıyor
- **Lawful De-anonymization:** Yasal gereklilik halinde AS komitesi kullanıcıyı anonim VP'den de-anonim edebilir (kullanıcı accountability — bizimkinden farklı)

### VeriSSO'da OLMAYAN Özellikler

1. **Server/Peer Misbehavior Detection:** Kötü niyetli AS tespiti mekanizması yok. Geçersiz partial imza gönderen AS'ı tespit edip kanıtlama mekanizması yok.
2. **Immutable Evidence:** Misbehavior kanıtının değiştirilemez kaydı yok.
3. **Automated Sanctions:** Kötü niyetli AS'ı otomatik devre dışı bırakma yok.
4. **Blockchain Integration:** Hiç yok — AS komitesi bağımsız çalışır.
5. **SPOF Eliminasyonu Odağı:** VeriSSO IdP'yi ortadan kaldırmak yerine gizlilik sağlamaya odaklanıyor.

### Örtüşme Analizi

| Boyut | VeriSSO | Bizim Çalışma | Örtüşme |
|-------|---------|---------------|---------|
| **Threshold token üretimi** | ✓ (AS komitesi) | ✓ (HLF peer'ları) | ÖRTÜŞÜYOR — her ikisi de threshold imza ile OIDC token üretiyor |
| **OIDC uyumluluk** | ✓ (ACF) | ✓ (ACF) | ÖRTÜŞÜYOR — RP değişikliği gerektirmiyor |
| **Birincil odak** | Gizlilik (unlinkability) | SPOF eliminasyonu + accountability | FARKLI |
| **Altyapı** | Bağımsız AS komitesi | Hyperledger Fabric | FARKLI |
| **Misbehavior detection** | Yok | Feldman VSS doğrulama | FARKLI — bizim özgün katkı |
| **Immutable evidence** | Yok | HLF ledger kaydı | FARKLI — bizim özgün katkı |
| **Otomatik yaptırım** | Yok | Chaincode ile (3 ihlal → devre dışı) | FARKLI — bizim özgün katkı |
| **Credential tipi** | Verifiable Credentials (BBS+ZKP) | Klasik OIDC credentials (MFA) | FARKLI |
| **Gizlilik** | Güçlü (unlinkability, selective disclosure) | Standart OIDC seviyesinde | VeriSSO ÜSTÜN |
| **Performans** | ~30ms | Ölçülecek (Faz 5) | — |

### KARAR: ✅ DEVAM — Örtüşme Kabul Edilebilir

**Gerekçe:**

1. **Teknik örtüşme sınırlı:** Her ikisi de threshold + OIDC yapıyor ama tamamen farklı motivasyon ve mimariyle. VeriSSO → gizlilik, biz → SPOF eliminasyonu + accountability.

2. **Accountability Protocol tamamen özgün:** VeriSSO'da misbehavior detection, immutable evidence ve automated sanctions yok. Bu bizim en güçlü farklılaşma noktamız.

3. **Blockchain gereklilik argümanı sağlam:** VeriSSO blockchain kullanmıyor, biz kullanıyoruz — ve Accountability Protocol blockchain'in neden gerekli olduğunu kesin olarak kanıtlıyor.

4. **Farklı problem alanları:** VeriSSO gizlilik sorununu çözüyor (IdP kullanıcıyı takip edemesin), biz güvenlik sorununu çözüyoruz (IdP ele geçirilirse sistem çökmesin + kötü niyetli peer cezalandırılsın).

5. **Complementary çalışmalar:** VeriSSO ile bizim çalışma aslında birbirini tamamlıyor — VeriSSO'nun gizlilik yaklaşımı bizim accountability yaklaşımıyla birleştirilirse daha güçlü bir sistem oluşabilir (future work).

**Makalede pozisyonlama stratejisi:**
- VeriSSO'yu Section 2'de "en yakın çalışma" olarak detaylı karşılaştırma
- "VeriSSO gizlilik odaklı, biz güvenlik ve accountability odaklıyız" ayrımını net koy
- Karşılaştırma tablosunda VeriSSO'da Misbehavior Detection ve Accountability sütunlarının boş olması bizim farkımızı görsel olarak gösterir
- VeriSSO'nun güçlü yönlerini (gizlilik, performans) dürüstçe kabul et — hakemler bunu takdir eder

## PASTA Analizi

**Kaynak:** Agrawal, Miao, Mohassel, Mukherjee — "PASTA: PASsword-based Threshold Authentication" (ACM CCS 2018)

- **Yaklaşım:** Password-based threshold token authentication. IdP rolünü n sunucuya dağıtır. Herhangi t sunucu birlikte parola doğrulayıp token üretebilir.
- **Temel Primitifler:** Threshold OPRF (Oblivious PRF) + distributed token generation
- **Token Formatı:** Kendi token formatı — **standart OIDC/JWT değil**
- **Güvenlik:** t-1 sunucu geçerli token forge edemez, offline dictionary attack yapamaz
- **Misbehavior Detection:** Yok
- **Blockchain:** Yok
- **Performans:** Kurucu çalışma — sonraki tüm threshold SSO (PESTO, TSAPP, LPbT-SSO) buna dayanır
- **Bizden farkı:** OIDC uyumlu değil (kendi token formatı), accountability yok, blockchain yok. Biz OIDC standardına uyumlu JWT üretiyoruz + Accountability Protocol ekliyoruz.

## PESTO Analizi

**Kaynak:** Baum, Frederiksen, et al. — "PESTO: Proactively Secure Distributed Single Sign-On, or How to Trust a Hacked Server" (IEEE EuroS&P 2020)

- **Yaklaşım:** Proactive security ile dağıtık SSO. Tüm sunucular aynı anda ele geçirilmediği sürece güvenli.
- **Temel Primitifler:** Partially-oblivious distributed PRFs + distributed RSA signature scheme, non-interactive key refreshing
- **Token Formatı:** **RSA-signed JWT** — standart OIDC/OAuth akışıyla uyumlu (bu önemli — PESTO kısmen OIDC uyumlu)
- **Güvenlik:** UC framework'te kanıtlanmış, adaptive corruptions tolere eder
- **Proactive Security:** Key material periyodik olarak yenilenir (key refresh) — bir sunucu geçici olarak ele geçirilse bile, key refresh sonrası güvenlik geri kazanılır
- **Misbehavior Detection:** Kısmen — proactive key refresh mekanizması compromised sunucunun etkisini sınırlar ama tespit/kanıt/yaptırım yok
- **Blockchain:** Yok
- **Performans:** 2-round protokol, 124ms sign-in (sunucular farklı ülkelerde)
- **Bizden farkı:** RSA-JWT (biz ES256/ECDSA), proactive security var ama misbehavior detection/evidence/sanctions yok, blockchain yok. Biz Feldman VSS ile kötü niyetli peer'ı tespit edip blockchain'e kanıt yazıyoruz — PESTO bunu yapmıyor.

**Not:** PESTO RSA-JWT ürettiği için OIDC RP'lerle kısmen uyumlu. Ancak ES256 değil RS256 kullanıyor. Bizim çalışma ES256 (P-256) ile standart OIDC uyumluluğu hedefliyor.

## TSAPP Analizi

**Kaynak:** "TSAPP: Threshold Single-Sign-On Authentication Preserving Privacy" (IEEE TDSC 2023/2024)

- **Yaklaşım:** Threshold SSO'da gizlilik koruması. Her identity server kullanıcıya pseudonym üzerinde partial token (partial signature) verir, kullanıcı t adet partial token'ı birleştirip blind ederek servis erişimi sağlar.
- **Temel Primitifler:** Threshold signature on pseudonyms + token blinding
- **Token Formatı:** Kendi formatı — **standart OIDC/JWT değil**
- **Odak:** Kullanıcı gizliliği — kimlik ve erişim örüntüsü token'dan öğrenilememeli
- **Misbehavior Detection:** Yok
- **Blockchain:** Yok
- **Bizden farkı:** OIDC uyumlu değil, gizlilik odaklı (biz güvenlik + accountability odaklıyız), misbehavior detection yok, blockchain yok.

## LPbT-SSO Analizi

**Kaynak:** Zhang et al. — "LPbT-SSO: Password-Based Threshold Single-Sign-On Authentication From LWE" (IEEE TDSC 2025)

- **Yaklaşım:** LWE (Learning With Errors) problemi üzerine kurulu ilk quantum-resistant threshold SSO. Post-quantum güvenlik sağlar.
- **Temel Primitifler:** Threshold OPRF (LWE-based) + Threshold Homomorphic Aggregate Signature (THAS) over lattices + updatable server private key
- **Token Formatı:** Lattice-based signature — **standart OIDC/JWT değil**
- **Güvenlik:** Quantum adversary'ye karşı dayanıklı (LWE intractability), offline dictionary saldırılarına dayanıklı
- **Misbehavior Detection:** Yok
- **Blockchain:** Yok
- **Bizden farkı:** OIDC uyumlu değil, farklı kriptografik temel (lattice vs ECDSA), post-quantum odaklı (biz klasik ECDSA), misbehavior detection yok, blockchain yok. Post-quantum threshold SSO bizim future work'ümüz olabilir.

## Diğer İlgili Çalışmalar

### Belfaik et al. (2023)
**Kaynak:** "A Novel Secure and Privacy-Preserving Model for OpenID Connect Based on Blockchain" — IEEE Access, 2023
- **Yaklaşım:** Ethereum ERC-721 NFT kullanarak OIDC parametrelerini güvenceye alır
- **Threshold:** Yok — IdP hâlâ merkezi
- **OIDC:** Uyumlu
- **Blockchain:** Evet (Ethereum)
- **Misbehavior Detection:** Yok
- **Bizden farkı:** SPOF sorununu çözmüyor, IdP merkezi kalıyor, threshold yok

### SSH-DAuth / Krishna et al. (2023)
**Kaynak:** Scientific Reports, 2023
- **Yaklaşım:** (1,3,4)-Secret Sharing Scheme (Boolean matrix-based) ile DID'leri IPFS üzerinde dağıtır
- **Threshold:** Secret sharing credential saklama için, token imzalama için değil
- **OIDC:** Hayır (OAuth 2.0)
- **Blockchain:** Evet (HLF + Ethereum)
- **Misbehavior Detection:** Yok
- **Bizden farkı:** SSO değil, OIDC değil, threshold token üretimi yok

### FADID-TT / Liu et al. (2025)
**Kaynak:** ACM WWW 2025
- **Yaklaşım:** Fully anonymous DID sistemi, DAC + threshold tracing (ZKP ile)
- **Threshold:** Kötü niyetli kullanıcı takibi için, token imzalama için değil
- **OIDC:** Hayır (DID sistemi)
- **Blockchain:** Evet (HLF + Ethereum)
- **Misbehavior Detection:** Kullanıcı misbehavior'u için (server misbehavior değil)
- **Bizden farkı:** SSO/OIDC sistemi değil, threshold kullanıcı takibi için, server accountability yok

### Bashar et al. (2024)
**Kaynak:** International Journal of Information Security, 2024
- **Yaklaşım:** Blockchain ile IdP'yi merkeziyetsizleştirme (SAML-based federasyonlar)
- **Threshold:** Yok — blockchain konsensüsüne dayanıyor
- **OIDC:** Hayır (SAML)
- **Blockchain:** Evet (Ethereum + HLF)
- **Misbehavior Detection:** Yok
- **Formal doğrulama:** ProVerif ile (referans olarak değerli)
- **Bizden farkı:** OIDC değil (SAML), threshold kripto yok, accountability yok

### PROTECT / Zhang et al. (2020/2021)
**Kaynak:** IEEE Transactions on Mobile Computing, 2021 (TDSC serisi)
- **Yaklaşım:** Password-based threshold SSO, proactive key renewal ile perpetual leakage'a dayanıklı
- **Threshold:** Evet (Threshold OPRF)
- **OIDC:** Hayır (kendi protokolü)
- **Blockchain:** Yok
- **Misbehavior Detection:** Yok
- **Bizden farkı:** OIDC uyumlu değil, blockchain yok, accountability yok. PASTA serisinin devamı.

---

## Arka Plan Kaynakları

### OIDC (OpenID Connect)
- **OIDC Core 1.0** \[oidc-core\]: Sakimura, Bradley, Jones et al. (2014). Authorization Code Flow, ID Token (JWT), UserInfo endpoint.
- **Kritik nokta:** IdP tek imza anahtarını tutar → SPOF. Anahtar ele geçirilirse tüm token'lar forge edilebilir.
- **Storm-0558 (2023)** \[storm0558-microsoft, storm0558-csrb\]: Çin merkezli aktör, Microsoft'un MSA consumer signing key'ini çaldı. Crash dump'tan sızan anahtar → kompromize mühendis hesabı üzerinden erişim. **25 organizasyon**, **503 kişisel hesap**, sadece State Department'tan ~60,000 e-posta etkilendi. CSRB: "cascade of security failures". **Makalemizin birincil motivasyonu: tek imza anahtarı = total identity compromise. Threshold signing bunu önlerdi.**

### Threshold ECDSA
- **GG18** \[gg18\]: Gennaro & Goldfeder (CCS 2018). İlk pratik (t,n)-threshold ECDSA, trustless setup.
- **GG20** \[gg20\]: Gennaro & Goldfeder (ePrint 2020/540). Single-round signing + identifiable abort.
- **CGGMP21** \[cggmp21\]: Canetti, Gennaro, Goldfeder, Makriyannis, Peled (CCS 2020, ePrint 2021/060). UC-secure, proactive, non-interactive, identifiable abort. **Bizim çalışma için en ilgili: P-256/ES256 JWT signing desteği, bilinen zayıflık yok** (GG18/GG20 Alpha-Rays'den etkilendi).

### Feldman VSS
- **Feldman (1987)** \[feldman1987\]: Non-interactive verifiable secret sharing. Shamir SSS üzerine public commitment ekler → share doğrulama mümkün. FOCS 1987, pp. 427-437.
- **Bizim için önemi:** Accountability Protocol'de geçersiz partial imza tespiti için Feldman commitment'ları kullanıyoruz.

### DKG (Distributed Key Generation)
- **Pedersen (1991)** \[pedersen1991\]: İlk DKG protokolü. EUROCRYPT '91. Basit ama non-uniform key distribution.
- **Gennaro et al. (1999/2007)** \[gennaro2007dkg\]: Uniform distribution düzeltmesi. Journal of Cryptology, Vol. 20, pp. 51-83.

### tss-lib
- **BNB Chain tss-lib** \[tsslib\]: Go kütüphanesi, v2.0.2 (Ocak 2024). GG18 implementasyonu, ECDSA + EdDSA.
- **Alpha-Rays (2021)** \[alpharays2021\]: Tymokhanov & Shlomovits. MtA sub-protokolünde Paillier boyut kontrolü eksikliği → tam anahtar çıkarma. v2.0.0'da düzeltildi.
- **P-256 desteği:** Curve registry üzerinden mevcut (secp256k1 varsayılan). PoC için yeterli (Endişe 3).

### Hyperledger Fabric
- **HLF v3.0** \[hlf-docs, hlf-v3\]: Eylül 2024, LF Decentralized Trust altında. SmartBFT consensus (ilk BFT ordering service).
- **Mimari:** Peer'lar (endorsing + committing), Orderer'lar (Raft/SmartBFT), Channel'lar, Chaincode (Go/Node.js/Java).
- **IBM durumu (Endişe 8):** IBM ticari SaaS platformunu sonlandırdı ama core katkılara Fabric-X üzerinden devam ediyor. Proje aktif, v3.0 yayınlandı.
- **Akademik kullanım:** Kimlik yönetimi alanında güçlü (DPKI, healthcare IAM, IoT identity) \[sutradhar2023hlf-iam\].
