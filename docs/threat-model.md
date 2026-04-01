# Tehdit Modeli ve Güvenlik Analizi

## Aktörler

| Aktör | Rol | Güvenilirlik |
|-------|-----|-------------|
| **U (Kullanıcı)** | Kimlik doğrulama isteyen taraf | Dürüst (MFA ile doğrulanır). Phishing kurbanı olabilir — scope dışı. |
| **P_i (HLF Peer)** | Token üretim altyapısı, key share sahibi | En fazla t-1 tanesi kompromize olabilir (Byzantine) |
| **Coord (Coordinator)** | Akış yöneticisi, HTTP endpoint | Key share TUTMAZ. DoS yapabilir, token forge EDEMEZ. |
| **RP (Relying Party)** | Token doğrulayan uygulama | Dürüst (standart OIDC doğrulama). Kötü niyetli RP scope dışı. |
| **A (Saldırgan)** | Sistemi kötüye kullanmak isteyen | Dış veya iç (kompromize peer). PPT (Probabilistic Polynomial Time). |

## Saldırgan Modeli

### A1 — Dış Saldırgan (External Adversary)

Ağ üzerinden saldıran, hiçbir peer'ın secret key share'ine sahip olmayan saldırgan.

**Yetenekleri:**
- Ağ trafiğini dinleme (eavesdropping) — TLS ile hafifletilir
- Mesaj değiştirme (tampering) — TLS + authenticated channels ile hafifletilir
- Replay saldırısı — OIDC nonce + token expiration ile hafifletilir
- Man-in-the-middle — TLS mutual authentication ile hafifletilir
- JWKS endpoint'i manipüle etme — ledger'dan pk doğrulama ile hafifletilir

**Dış saldırganın YAPAMAYACAKLARI:**
- Token forge etme (pk'yı bilse bile sk olmadan imkansız — ECDSA güvenliği)
- t adet geçerli partial signature toplama (share'lere erişimi yok)

### A2 — İç Saldırgan (Compromised Peer)

En fazla t-1 adet HLF peer'ını ele geçirmiş saldırgan. Her kompromize peer'ın secret key share'ine sahip.

**Yetenekleri:**
- Kendi share'ini kullanarak geçersiz partial signature gönderme (M1)
- Yanıt vermeme / geciktirme (M2)
- Share'ini başka oturumlarda tutarsız kullanma (M3)
- Farklı peer'lara farklı partial signature gönderme — equivocation (M4)
- Diğer kompromize peer'larla coalition oluşturma (en fazla t-1 peer)
- Coordinator'ı ele geçirme → DoS ama token forge yok

**İç saldırganın YAPAMAYACAKLARI (t-1 veya daha az kompromize peer ile):**
- Geçerli token forge etme (t share gerekli, t-1 yetersiz)
- Tam private key'i reconstruct etme (t share gerekli)
- Dürüst peer'ın share'ini öğrenme (Feldman VSS gizliliği)
- Accountability kanıtını silme/değiştirme (ledger immutability)
- Kendini false evidence ile aklama (kriptografik doğrulama)

### A3 — Coordinator Compromise

Coordinator ele geçirilmiş ama hiçbir peer kompromize olmamış.

**Etki:**
- DoS: Kullanıcı isteklerini bloke edebilir veya yanlış yönlendirebilir
- Bilgi sızıntısı: Oturum bilgileri, kullanıcı credential'ları (Coord üzerinden geçiyor)
- Token forge: İMKANSIZ — Coordinator key share tutmuyor

**Hafifletme:**
- Coordinator replika olarak çalıştırılabilir (load balancer)
- Credential'lar peer'lara direct TLS ile de gönderilebilir

## Güvenlik Hedefleri

### SG1 — Key Secrecy
Hiçbir adversary (dış veya t-1 kompromize peer ile), joint private key sk'yi öğrenemez.

**Garanti:** CGGMP21 UC-security. t-1 share ile sk reconstruct edilemez (Shamir'in bilgi-teorik güvenliği).

### SG2 — Unforgeability
t-1 veya daha az kompromize peer, geçerli bir ECDSA imzası (dolayısıyla geçerli JWT) forge edemez.

**Garanti:** CGGMP21 unforgeability — EU-CMA (Existential Unforgeability under Chosen Message Attack) güvenliği, ECDLP'nin zorluğuna indirgenir.

### SG3 — Authentication Integrity
Sadece t veya daha fazla peer tarafından bağımsız olarak doğrulanmış kullanıcılar token alabilir.

**Garanti:** t-of-n MFA — her peer bağımsız doğrulama yapar, t-1 kompromize peer yanlış onay verse bile yeterli değil.

### SG4 — Replay Resistance
Aynı token ikinci kez kullanılamaz; ele geçirilmiş token sınırlı süre geçerlidir.

**Garanti:** OIDC nonce mekanizması (tekrar kullanım tespiti) + exp claim (zaman sınırı) + aud claim (RP binding).

### SG5 — Accountability
Kötü niyetli peer davranışı tespit edilebilir, kanıtlanabilir ve yaptırım uygulanabilir. Dürüst peer yanlışlıkla cezalandırılamaz (false positive imkansızlığı).

**Garanti:** Feldman VSS kriptografik doğrulama (M1/M3/M4 tespitinde false positive matematiksel olarak imkansız) + HLF ledger immutability (kanıt silinemez) + t-1 witness requirement (false accusation koruması).

### SG6 — Availability
t-1 peer arızalanmış veya kötü niyetli olsa bile sistem token üretmeye devam edebilir.

**Garanti:** t peer yeterli (n arasından). Kalan n-(t-1) ≥ t+1 peer ile signing devam eder. Timeout olan peer atlanır.

## Static vs Adaptive Corruption Modeli

Çalışmamız **statik corruption** modeli kullanmaktadır: saldırgan, protokol başlamadan önce hangi peer'ları kompromize edeceğini seçer ve protokol sırasında yeni peer kompromize edemez.

### Neden Statik Corruption?

1. **Operasyonel gerekçe:** HLF peer'ları kurumsal sınırlarla ayrılmış ortamlarda çalışır (farklı organizasyonlar, farklı veri merkezleri). Bir peer'ı kompromize etmek, o organizasyonun güvenlik çevresini ihlal etmeyi gerektirir — bu, protokol yürütme süresi (milisaniye) içinde gerçekleştirilmesi son derece düşük olasılıklı bir saldırıdır.

2. **CGGMP21 uyumu:** CGGMP21'in UC-security kanıtı statik corruption altında verilmiştir. Proactive key refresh mekanizması, adaptive corruption'ın etkisini sınırlamak için tasarlanmıştır.

3. **Proactive key refresh ile hafifletme:** Periyodik key refresh (CGGMP21'in built-in özelliği) sayesinde, her refresh döneminde saldırganın yeni bir t-1 peer alt kümesi kompromize etmesi gerekir. Refresh periyodu τ ile bir peer'ı kompromize etme süresi T_comp arasında τ << T_comp olduğu sürece, adaptive corruption pratik olarak etkisizleştirilir. Bu, statik corruption modelinin pratikte yeterli olduğunu destekler.

4. **Formal sınırlama:** Adaptive corruption altında tam güvenlik kanıtı, UC-framework'te önemli ölçüde daha karmaşıktır ve bu çalışmanın kapsamını aşar. Adaptive corruption altında formal güvenlik analizi future work olarak planlanmaktadır.

## Privacy-Accountability Gerilimi (Tension)

Çalışmamız SPOF eliminasyonu ve server-side accountability'ye odaklanırken, kullanıcı gizliliği (unlinkability, minimal disclosure) scope dışında bırakılmıştır. Bu bilinçli bir tasarım kararıdır.

### Mevcut Gizlilik Durumu

Mevcut tasarımda kullanıcı gizliliği standart OIDC seviyesindedir:
- IdP (threshold cluster) kullanıcının tüm RP'lerdeki oturumlarını görebilir
- sub claim'i RP'ler arasında sabit (linkable)
- Bu, klasik OIDC'nin doğal sınırlamasıdır

### VeriSSO ile Karşılaştırma

VeriSSO (Alom et al., 2025) BBS imzaları ve ZKP ile güçlü kullanıcı gizliliği (unlinkability, selective disclosure) sağlar. Ancak VeriSSO'da server-side accountability mekanizması yoktur. Bu iki yaklaşım arasında doğal bir gerilim vardır:

- **Unlinkability → Accountability zorlaşır:** Kullanıcı takip edilemezse, kötü niyetli bir signing oturumunun hangi kullanıcıya ait olduğu tespit edilemez
- **Accountability → Privacy sınırlanır:** Misbehavior evidence'ında oturum bilgileri kaydedilir, bu da minimal disclosure ile çelişebilir

### Entegrasyon Fizibilitesi (Future Work)

VeriSSO'nun BBS-tabanlı gizlilik yaklaşımı ile bizim Accountability Protocol'ümüzün birleştirilmesi teorik olarak mümkündür:
- **Server-side accountability** (bizim katkımız): Peer'ların misbehavior'ı kullanıcı kimliğinden bağımsız tespit edilebilir (Feldman VSS doğrulaması kullanıcı bilgisi gerektirmez)
- **User unlinkability** (VeriSSO'nun katkısı): BBS imzaları ile kullanıcıya ait claim'ler selective disclosure ile sunulabilir

Bu entegrasyon, accountability'nin kullanıcı gizliliğini ihlal etmeden sağlanıp sağlanamayacağını araştıran ayrı bir çalışma konusudur.

## Varsayımlar

1. **Kriptografik varsayımlar:**
   - ECDLP (Elliptic Curve Discrete Logarithm Problem) P-256 üzerinde zordur
   - SHA-256 collision-resistant'tır
   - Paillier encryption semantically secure'dur (CGGMP21 MtA sub-protocol için)

2. **Ağ varsayımları:**
   - Asenkron ağ modeli (eventual delivery), TLS ile güvenli kanallar
   - Peer'lar arası iletişim authenticated (HLF MSP/sertifika altyapısı)

3. **Güvenilirlik varsayımları:**
   - En fazla t-1 peer Byzantine davranır — statik corruption modeli (bkz. yukarıda gerekçe)
   - Coordinator key material tutmaz (mimari garanti)
   - HLF ordering service dürüsttür (Raft/SmartBFT varsayımı)

4. **Scope varsayımları:**
   - Kullanıcı phishing'e karşı korunmaz (MFA ile hafifletilir ama tamamen çözülmez)
   - Kötü niyetli RP scope dışıdır
   - Side-channel saldırıları (timing, power) scope dışıdır
   - Kullanıcı gizliliği (unlinkability) scope dışıdır — standart OIDC seviyesinde (bkz. Privacy-Accountability tartışması)

---

## Güvenlik Özellikleri Analizi (Yarı-Formal)

### Analiz Yaklaşımı

Yarı-formal güvenlik analizi: her güvenlik hedefini (SG1-SG6) sistematik olarak incele, hangi mekanizmalarla sağlandığını göster, mevcut kriptografik kanıtlara referans ver.

**Neden formal (ProVerif) değil:**
- Threshold ECDSA'nın iç mekanizmaları (Paillier, MtA) ProVerif'te modellenemez
- CGGMP21'in UC-security kanıtı zaten peer-reviewed ve accepted
- Bizim katkımız protokol seviyesinde (OIDC + Accountability), kriptografik primitif seviyesinde değil
- Q2 hedef (IEEE Access) için yarı-formal yeterli

### SG1 — Key Secrecy Analizi

**İddia:** Joint private key sk, t-1 veya daha az kompromize peer tarafından öğrenilemez.

**Kanıt taslağı:**
1. sk = Σ x_i (tüm peer'ların secret contribution'ları toplamı)
2. Her peer yalnızca kendi share'ini sk_i = f(i) bilir (Shamir SSS)
3. Shamir SSS bilgi-teorik güvenli: t-1 share, sk hakkında SIFIR bilgi verir
4. Feldman VSS commitment'ları public ama DLP varsayımı altında share'i ifşa etmez
5. CGGMP21 signing protokolü sırasında partial signature'lar share'i ifşa etmez (UC-security kanıtı [cggmp21])

**Karşı-senaryo:** Saldırgan t-1 share topladı → kalan 1 share'i bulmak = DLP çözmek. P-256'da infeasible (~2^128 güvenlik).

### SG2 — Unforgeability Analizi

**İddia:** t-1 kompromize peer geçerli bir ECDSA imzası forge edemez.

**Kanıt taslağı:**
1. Geçerli ECDSA imzası (r,s) üretmek için k (random nonce) ve sk gerekli
2. Threshold signing'de k = Σ k_i, her k_i farklı peer'da
3. t-1 peer'ın k_i değerleri tek başına k'yı belirlemez
4. CGGMP21 EU-CMA güvenliği kanıtlanmış [cggmp21]: t-1 corrupted party ile forge olasılığı negligible
5. Dolayısıyla geçerli JWT forge etmek = geçerli ECDSA imzası forge etmek = negligible

### SG3 — Authentication Integrity Analizi

**İddia:** t-1 kompromize peer, meşru olmayan kullanıcı için token üretilmesini sağlayamaz.

**Kanıt taslağı:**
1. Token üretimi için t onay gerekli
2. t-1 kompromize peer + 1 dürüst peer = t, ama dürüst peer yalnızca geçerli credential ile onay verir
3. Saldırganın kullanıcı credential'ını (password + TOTP/WebAuthn) bilmesi gerekir
4. TOTP: 6-digit, 30-saniye pencere, brute force T_sign süresi içinde impractical
5. Sonuç: Authentication bypass = credential theft, bu scope dışı (phishing)

### SG4 — Replay Resistance Analizi

**İddia:** Ele geçirilmiş bir token yeniden kullanılamaz (sınırlı etki).

**Kanıt taslağı:**
1. OIDC nonce: RP her auth request'te unique nonce gönderir, token'daki nonce eşleşmeli
2. exp claim: Token belirli süre sonra geçersiz (varsayılan: 1 saat)
3. aud claim: Token yalnızca belirtilen RP'de geçerli
4. Token theft scope dışı — ama etki sınırlı (exp + aud)
5. Standart OIDC replay koruması ile eşdeğer

### SG5 — Accountability Analizi

**İddia:** (a) Kötü niyetli peer HER ZAMAN tespit edilir, (b) dürüst peer ASLA yanlış suçlanmaz, (c) kanıt silinemez.

**Kanıt taslağı:**
(a) Tespit completeness:
- M1: Geçersiz σ_i, Feldman commitment'larla doğrulanır — deterministic, her doğrulayıcı aynı sonucu alır
- CGGMP21 identifiable abort: Protokol abort ederse suçlu taraf identify edilir [cggmp21]

(b) False positive imkansızlığı:
- Dürüst peer'ın σ_i'si commitment'larla HER ZAMAN tutarlıdır (Feldman VSS'in temel özelliği [feldman1987])
- Ek koruma: t-1 bağımsız witness onayı — tek peer false accusation yapamaz

(c) Evidence immutability:
- HLF ledger append-only, endorsement policy ile t-1 peer onayı gerekli
- Kompromize peer(lar) kanıtı silemez (t-1 < t — endorsement yetersiz)

### SG6 — Availability Analizi

**İddia:** t-1 peer arızalanmış olsa bile sistem çalışmaya devam eder.

**Kanıt taslağı:**
1. n peer'dan t-1 tanesi offline/kompromize → kalan n-t+1 peer
2. n-t+1 ≥ t+1 (n ≥ 2t gereksinimi varsayılır; (3,5) durumunda: 5-2=3 ≥ t=3)
3. Coord, t+f peer'a istek gönderir (f = yedek). İlk t yanıt ile devam eder.
4. Signing latency artabilir (yedek peer kullanımı) ama hizmet kesilmez

---

## Tehdit Kapsamı Tablosu

| # | Tehdit | Karşılanan | Mekanizma | Not |
|---|--------|:----------:|-----------|-----|
| T1 | IdP signing key theft | ✓ | t-of-n threshold — tek key yok | Storm-0558 senaryosu önlenir |
| T2 | Token forgery | ✓ | CGGMP21 EU-CMA unforgeability | t-1 peer bile forge edemez |
| T3 | Compromised peer (≤t-1) | ✓ | Threshold security + Accountability | Tespit + yaptırım |
| T4 | Replay attack | ✓ | OIDC nonce + exp + aud | Standart OIDC mekanizması |
| T5 | MITM | ✓ | TLS + HLF MSP mutual auth | Standart ağ güvenliği |
| T6 | DKG manipulation | ✓ | Feldman VSS commitment doğrulama | Biased key generation tespiti |
| T7 | Evidence tampering | ✓ | HLF ledger immutability | Kanıt silinemez/değiştirilemez |
| T8 | False accusation | ✓ | t-1 witness requirement + chaincode re-verification | Kriptografik garanti |
| T9 | Coordinator DoS | ◐ | Replika Coordinator | DoS hafifletilir ama tamamen önlenemez |
| T10 | Phishing | ◐ | MFA (TOTP/WebAuthn) | Hafifletir ama tamamen çözmez |
| T11 | Side-channel attack | ✗ | Scope dışı | Timing, power analysis — ayrı çalışma |
| T12 | Malicious RP | ✗ | Scope dışı | RP güvenilir varsayılır |
| T13 | Quantum adversary | ✗ | Scope dışı | P-256 ECDSA quantum-safe değil — future work |

**Muhafazakâr iddia:** Sistemimiz 13 potansiyel tehditten 8'ini tam olarak karşılar (T1-T8), 2'sini kısmen hafifletir (T9-T10), ve 3'ünü scope dışı bırakır (T11-T13). Bu, mevcut en iyi threshold SSO şemalarından (PASTA, PESTO) anlamlı bir iyileştirmedir — özellikle T3 (accountability), T7 (evidence immutability) ve T8 (false accusation koruması) konularında benzersiz katkı sağlar.

---

## Formal Accountability Game Tanımı

Aşağıdaki formalizm, Boneh & Komlo (FC 2024) "Threshold Signatures with Private Accountability" çalışmasındaki accountability game yapısından uyarlanmıştır. Amacımız, Accountability Protocol'ün iki temel güvenlik özelliğini — completeness ve soundness — game-based olarak tanımlamaktır.

### Definition 1: Accountability Completeness

**Gayri resmi ifade:** Dürüst bir peer asla yanlış suçlanamaz ve cezalandırılamaz.

**Game G_Comp^A(λ):**

1. Setup: Challenger (t,n)-DKG çalıştırır, her P_i'ye share sk_i ve tüm commitment'lar C = {C_0,...,C_{t-1}} verir.
2. Adversary A, en fazla t-1 peer'ı corrupt eder.
3. Signing oturumlarında, A corrupt peer'lar adına mesajlar gönderebilir.
4. A, dürüst bir peer P_j hakkında bir evidence package E_j üretir ve RecordMisbehavior(E_j) çağrısı yapar.
5. A kazanır ancak ve ancak: chaincode E_j'yi kabul eder (dürüst P_j hakkında misbehavior kaydı oluşturulur).

**Theorem 1 (Completeness):** Feldman VSS'nin bağlayıcılığı (binding property) altında, herhangi bir PPT adversary A için:

  Pr[G_Comp^A(λ) = 1] = negl(λ)

**Kanıt taslağı (M1 için):**
- Dürüst P_j'nin share'i sk_j, DKG sırasında doğru üretilmiştir.
- Feldman VSS doğrulaması deterministic'tir: sk_j · G = Σ_{k=0}^{t-1} j^k · C_k
- Bu eşitlik DKG sonrasında HER ZAMAN sağlanır (Feldman VSS'nin temel özelliği).
- A'nın false evidence üretmesi için: ya (a) sk_j'yi değiştirmesi gerekir (P_j'nin private share'ine erişimi yok) ya da (b) commitment'ları değiştirmesi gerekir (ledger immutable — t-1 < t endorsement ile değiştirilemez).
- Chaincode `verifyShareFromEvidence()` ile bağımsız doğrulama yapar → dürüst share kabul edilir → evidence reddedilir.
- Ek koruma: t-1 witness gereksinimi — tek corrupt peer false accusation yapamaz.
- Dolayısıyla Pr[G_Comp^A(λ) = 1] ≤ Pr[Feldman VSS kırılır] = negl(λ) (ECDLP varsayımı altında).

### Definition 2: Accountability Soundness

**Gayri resmi ifade:** Kötü niyetli bir peer'ın misbehavior'ı her zaman tespit edilir ve kanıtlanır.

**Game G_Sound^A(λ):**

1. Setup: Challenger (t,n)-DKG çalıştırır.
2. Adversary A, en fazla t-1 peer'ı corrupt eder.
3. Corrupt peer P_i bir signing oturumunda M1 misbehavior gerçekleştirir (geçersiz σ_i gönderir).
4. Dürüst peer'lar Feldman VSS doğrulaması yaparak misbehavior tespit eder.
5. A kazanır ancak ve ancak: misbehavior tespit EDİLEMEZ (hiçbir dürüst peer invalid σ_i'yi yakalayamaz).

**Theorem 2 (Soundness):** Herhangi bir PPT adversary A için:

  Pr[G_Sound^A(λ) = 1] = 0

**Kanıt taslağı:**
- Corrupt P_i geçersiz σ_i gönderirse, Feldman VSS doğrulaması σ_i · G ≠ Σ j^k · C_k sonucunu verir.
- Bu kontrol deterministik ve hatasızdır — her dürüst peer aynı sonuca ulaşır.
- Dolayısıyla tespit olasılığı 1'dir (false negative imkânsız).
- CGGMP21'in identifiable abort özelliği bu sonucu destekler: protokol abort ederse, suçlu taraf identify edilir.
- Sonuç: Pr[G_Sound^A(λ) = 1] = 0 (information-theoretic garanti, hesaplama varsayımı gerektirmez).

### CGGMP21 Identifiable Abort ile İlişki

Çalışmamızın Accountability Protocol'ü, CGGMP21'in identifiable abort'unun ÜZERİNE inşa edilmiştir:

| Özellik | CGGMP21 Identifiable Abort | Bizim Accountability Protocol |
|---------|---------------------------|------------------------------|
| Tespit | Protokol abort → suçlu party identify | Aynı + Feldman VSS independent check |
| Kanıt | Ephemeral (bellek içi) | Persistent (HLF ledger, immutable) |
| Yaptırım | Yok (uygulama bırakılmış) | Otomatik (strike system → disable) |
| Tarihçe | Yok | Tam denetim izi (QueryMisbehaviorHistory) |
| False accusation koruması | Yok (trust-based) | t-1 witness + chaincode re-verification |

---

## M2 (Timeout) False Accusation Nicel Analizi

M2 (timeout) misbehavior'ı için kriptografik doğrulama mümkün değildir — timeout bir operasyonel olaydır. Bu nedenle M2 false accusation riskinin nicel analizi kritiktir.

### Saldırı Senaryosu

t-1 malicious peer, koordineli olarak bir dürüst peer P_j'ye timeout iftirası atarak devre dışı bırakmaya çalışır.

**Parametreler:** (3,5) konfigürasyonu, yani t=3, n=5, t-1=2 malicious peer.

### Analiz

1. **Her oturum başına:** 2 malicious peer, P_j hakkında timeout raporu gönderir. Ancak her rapor için t-1=2 witness gereklidir. Malicious peer'lar birbirlerine witness olabilir → her oturumda 1 false M2 kaydı oluşturulabilir.

2. **Devre dışı bırakma eşiği:** M2 için 10 strike gereklidir.

3. **Gerekli oturum sayısı:** 2 malicious peer, her oturumda 1 false M2 kaydı oluşturabilir → **10 oturum** gerekir.

4. **Paralel saldırı:** Malicious peer'lar aynı anda birden fazla dürüst peer'a saldırabilir mi? Evet — ancak her bir hedef için ayrı 10 oturum gerekir. 3 dürüst peer'ı devre dışı bırakmak: 3 × 10 = **30 oturum**.

5. **Operasyonel bağlam:** Her oturum bir gerçek kullanıcı authentication isteği gerektirir. Saldırganın 30 meşru oturum başlatması veya beklemesi gerekir — bu, gerçek dünya koşullarında önemli bir zaman penceresi ve fırsat maliyeti oluşturur.

### Hafifletme Mekanizmaları

| Mekanizma | Etki |
|-----------|------|
| Yüksek M2 eşiği (10) | 10 false timeout = 10 ayrı oturum gerekli |
| t-1 witness gereksinimi | Tek malicious peer saldıramaz |
| Monitoring / anomaly detection | Aynı peer'ların sürekli timeout raporları anormal pattern oluşturur |
| Timeout süresi ayarlanabilirliği | T_sign artırılarak network jitter'dan kaynaklanan false positive azaltılabilir |
| Dürüst peer'ların M2 counter izlemesi | Peer kendi M2 sayısını görebilir ve operatöre bildirebilir |

### Sonuç

(3,5) konfigürasyonunda, 2 malicious peer'ın 1 dürüst peer'ı M2 ile devre dışı bırakması **minimum 10 oturum** gerektirir. Bu, anlık bir saldırı değil, uzun süreli ve gözlemlenebilir bir kampanyadır. Tüm dürüst peer'ları devre dışı bırakmak (sistem tamamen çökertmek) ise t adet dürüst peer × 10 oturum = 30 oturum gerektirir — bu noktada sistem zaten t-1'den fazla arıza ile karşılaşmış olur ve SG6 (availability) garantisi devreye girer. M2 eşiğinin 10'dan daha yüksek tutulması (örn. 20) bu saldırı maliyetini ikiye katlar.
