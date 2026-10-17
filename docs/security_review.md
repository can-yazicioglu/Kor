# AI 4 — Birleşik MVP güvenlik ve bağımsız doğrulama sonucu

**Tarih:** 17 Ekim 2026 · **Çalışma dalı:** `integration/full-mvp`

AI 1–4 teslimleri birleştirildi; ilk denetimdeki çalışmayı engelleyen veri, model ve demo sözleşmesi hataları giderildi. Yerel sentetik demo çalışıyor. **Bu sonuç üretim güvenliği veya gerçek dünyada tespit başarısı onayı değildir.** Özellikle normal seyahat/yeni cihaz bağlamındaki yanlış alarmlar devam ediyor.

İlk salt okunur branch denetimi [tarihsel raporda](reviews/security_review_2026-10-17_initial.md) saklanmıştır. Kullanıcının sonraki “dört AI'ın bütün eksiklerini tamamla ve test et” talebiyle düzeltme, sentetik veri üretimi ve eğitim kapsamı açılmıştır. Bu belge düzeltilmiş birleşik çalışma ağacını değerlendirir; eski branch'lerin kendiliğinden güncellendiği veya remote'a push edildiği anlamına gelmez.

## 1. İncelenen teslim ve yöntem

Kaynak snapshot'lar: A1 `590802c718341cef62428a57dbb83561ff7a4d0e`, a2 `ca44fccf96df108f8882d21b41e045b98df229dc`, a3 `8fee079990f028cd0dcfe7d82350fa38b634f7cc`. Kaynak branch'ler korunmuştur.

- CSV: `data/mvp_synthetic_logins.csv`, **10.000 olay / 4.036 oturum / 573 hesap / 800 şüpheli etiket**.
- CSV SHA-256: `41383a34524cefb434a66608c74a6554bada4377968298c6d7b7a43e4168b625`.
- Veri kökeni: yalnız yerel sentetik üretici v2; üçüncü taraf veri dosyası veya gerçek müşteri kaydı alınmamıştır.
- Model: `els-lr-41383a34524c-s42`, `models/demo_model.json`; gerçek sentetik eğitimden taşınabilir lojistik model.
- Bölmeler: 6.000 fit / 2.000 validation / 2.000 test. Kimlik, zaman ve episode denetimi eğitimden önce yapılır.
- Yöntem: kod/kontrat incelemesi, ayrı veri denetimi, mevcut artefaktlarla çıkarım eşliği, hata enjeksiyonu, HTTP ve DOM davranış testleri. Denetim testleri modeli yeniden eğitmez.

Kaynak araştırmasının kapsamı ve lisans kayıtları [veri kaynağı denetiminde](data_source_audit.md); veri semantiği [sentetik veri belgesinde](synthetic_data.md) bulunur.

## 2. İlk bulguların kapanışı

| İlk bulgu | Son durum | Düzeltme ve kanıt |
| --- | --- | --- |
| A4-01 · ağ aşinalığı tip uyuşmazlığı | **Kapandı** | CSV, eğitim ve JS `familiar/unfamiliar` kullanıyor. Gerçek 10.000 olay demo okuyucusundan geçiyor. 17 alanlı şema değişmedi. |
| A4-02 · çalışmayan A3 kolonları / geceyi saldırı sayan baseline | **Kapandı** | Ortak şemaya bağlı eğitim/değerlendirme script'leri, üç saldırı örüntüsünü kapsayan açık kural referansı ve çıktıları temiz notebook var. Gece/VPN/yeni cihaz tek başına kural alarmı değil. |
| A4-03 · sezgisel kimlik dışlama | **Kapandı** | Python ve JS aynı tam 11 özellik allowlist'ini kullanıyor. Kimlik, etiket ve metaveri değişikliği tahmini değiştirmiyor; yasak özellik kabul edilmiyor. |
| A4-04 · tutarsız ve nedensel olmayan pencereler | **Kapandı, sentetik akış kapsamıyla** | Hesap ve kaynak sayaçları sıralı geçmişten hesaplanıyor; bağımsız test yeniden hesaplıyor. `attempts_2m > attempts_1h` yok. Mevcut/gelecek sonuç 24 saat oranına girmiyor. |
| A4-05 · zor normal durumlar ve eksiklik yokluğu | **Veri/test açığı kapandı; yanlış alarm sınırı açık** | VPN, seyahat/yeni cihaz, gece, yanlış parola ve cold-start var. Alt grup FPR ve çekimserlik raporlanıyor; başarı iddiası yapılmıyor. |
| A4-06 · model/demo bağlantısı yokluğu | **Kapandı** | Sürüm, tamsayı puan ve katkı gerekçeleri taşıyan yerel JSON çıkarımı bağlı. 10.000 olayda Python–JS tam puan/gerekçe eşliği. |
| A4-07 · uygun eşik yokken sessiz 50 varsayımı | **Kapandı** | Validation kısıtları sağlanmazsa `feasible=false`, `threshold=null`. Kural referansında bu durum gerçekten raporlanıyor; başarısız seçim metriği uydurulmuyor. |
| A4-08 · silme ve notebook kalıcılığı belirsizliği | **Demo kapsamında kapandı** | 5/10/15 dakika, sıfırlama ve sayfadan ayrılma ile referans bırakma; askı sonrası son tarih kontrolü. Notebook ham satır göstermiyor. Dosya, cookie ve sayaç ömürleri ayrı belgeleniyor. |

Son çapraz incelemede ayrıca giderilen hatalar:

- Gece yarısından farklı üretim başlangıcında gelecekteki sentetik profil/ısınma verisinin okunabilmesi: başlangıç zamanı testi eklendi; varsayılan teslimin hash'i değişmedi.
- Modelde sonlu katsayı değişmesine rağmen eski checksum ile puan üretilebilmesi: Python ve HTTP model sunumunda SHA-256 doğrulama var. Eksik/bozuk dosya kontrollü biçimde reddediliyor.
- Eksik `model_version` nedeniyle Python'da `KeyError`: bozuk model puan üretmiyor.
- Bütün test zamanları `NaT` olduğunda zaman ayrımı kontrolünün atlanması: boş/geçersiz zamanlar reddediliyor.
- Bozuk HTTP hedefinde `urlsplit` hatası ve varsayılan istemci adresi logu: kontrollü 400; sunucunun hata/access logları kapalı.
- Raporun değiştirilebilir validation hedeflerini sabit yazması: gerçek çalıştırma ayarları rapora aktarılıyor.

Checksum imza değildir. Dosyayı ve checksum'ı birlikte değiştiren saldırganın özgünlüğünü doğrulamaz; yerel güvenilen model dağıtımı varsayımı sürer.

## 3. Gizlilik ve sızıntı kararları

| Kontrol | Sonuç / sınır |
| --- | --- |
| Gerçek kullanıcı adı, ham parola/IP, sızdırılmış liste | **İncelenen artefaktlarda bulgu yok.** Üretici ve gizlilik testleri incelendi; gerçek veri dosyası kullanılmadı. Biçim/örüntü kontrolü tek başına anonimlik kanıtı değildir. |
| Kimlik/etiket modele girişi | **Geçti.** `event_id`, `event_ts_utc`, `session_token`, `account_token`, `is_suspicious`, `attack_type` ve manifest alanları özellik dışında. |
| Eğitim/test kullanıcı ve zincir sızıntısı | **Geçti, bu sentetik teslimde.** Her bölme çiftinde hesap, oturum, episode ve kaynak kesişimi 0. En az 120 saniyelik zaman boşluğu zorunlu. |
| Ön işleme / eşik sızıntısı | **Geçti.** Ölçekleme fit'te; eşik validation'da. Holdout ile model/hyperparametre seçilmedi. |
| Senaryo bağımsızlığı | Aynı episode bölünmüyor; **aynı üreticinin senaryo şablonları tüm bölmelerde var.** Bilinmeyen üretici veya gerçek saldırı genellemesi doğrulanmadı. |
| Gelecek bilgi / pencere | **Geçti, sentetik akışta.** `(t−120s,t]`, aynı zamanlı olaylarda bilinen ingestion sırası ve mevcut sonuçtan önce 24 saat oranı. Cookie dönüşümü hesap/kaynak sayacını sıfırlamıyor. |
| Müşteri verisinin dışarı çıkışı | **İncelenen akışta yok.** CSV File API ile bellekte işleniyor; tek fetch aynı origin'den model GET. Harici API/telemetri/CSV upload yok. |
| Sunucu dosya sınırı | **Geçti.** Loopback + Host/dosya allowlist; CSV/manifest/joblib dizinleri sunulmuyor; POST reddediliyor. |
| Kalıcı cihaz izi / biyometri / browser storage | **İncelenen uygulamada yok.** Form/arama etkileşimleri davranış kaydına çevrilmiyor; cookie oluşturulmuyor. |
| Eksik geçmiş / model yokluğu | **Geçti.** Puan 0 yapılmıyor. Oturumdaki tek bir eksik olay tüm oturumu puansız/inceleme durumunda tutuyor. |
| Silme | **Uygulama referansı bırakma testleri geçti.** Fiziksel bellek/disk silme garantisi veya gerçek IdP TTL servisi yok. |
| Otomatik kilitleme | **Yok.** MFA ve insan incelemesi yalnız öneri; gerçek kimlik sağlayıcısına işlem gönderilmiyor. |
| Sentetik performansın sunumu | UI ve belgeler mock, sentetik model ve gerçek dünya iddiasını ayırıyor. Puan kalibre saldırı olasılığı olarak sunulmuyor. |

30 günlük geçmiş yalnız sentetik profildir. `device_new`, cookie değişiminden türetilen kalıcı parmak izi değildir. CSV'de giriş başarı alanı yoktur; şüpheli başarılı girişin başarı sonucu yalnız sentetik denetim manifestinde sınanır, gerçek IdP başarısı doğrulanmış sayılamaz.

## 4. Yanlış alarm, kapsam ve öncelikli kalan sınırlar

Tam metrikler, dört yaklaşımın karşılaştırması ve paydaları [model sonuçlarında](model_results.md) ve `outputs/evaluation.json` içindedir. Aşağıdakiler **demo Logistic Regression** modeline aittir.

Testin 2.000 olayından **1.631'i puanlanır, 369'u çekimserdir**. 811 test oturumundan **537'si puanlanır, 274'ü çekimserdir**. Çekimserlik doğru negatif veya başarılı tespit sayılmaz; puansız incelemeler operasyon yükünü ayrıca artırabilir.

| Politika | Olay FPR | Oturum FPR | Oturum recall |
| --- | ---: | ---: | ---: |
| Puan ≥30 · MFA/inceleme | %26,07 | %30,91 | %90,91 |
| Puan ≥70 · inceleme | %9,67 | %14,52 | %72,73 |

Validation'da seçilen ayrı benchmark eşiğinde LR olay FPR **%6,47**, recall **%59,54**. Bu eşik demo 30/70 politikası değildir; daha iyi görünen benchmark değerleri gerçek UI yanlış alarm oranının yerine kullanılamaz.

| Öncelik | Açık sınır | Düzeltme / sonraki doğrulama |
| --- | --- | --- |
| **P1 · üretim kullanımını engeller** | Demo oturumlarında MFA ve inceleme yanlış alarmı yüksek. Normal seyahat/yeni cihaz olaylarında ≥30 FPR %50,60, VPN/yeni cihazda %41,18. | Üretim kullanımından önce müşteri içi bağımsız validation, oturum düzeyinde eşik seçimi ve kabul edilebilir alarm bütçesi belirlenmeli. Mevcut holdout'a bakıp eşik oynatılmamalı; yeni bağımsız değerlendirme gerekir. |
| **P2** | Şüpheli başarılı giriş benchmark recall %41,67; bazı spraying olaylarında bağlam eksik. | Gerçek IdP başarı bağlamı ve kaynak korelasyonu müşteri içinde bağlanmalı; yeni veriyle kapsam/çekimserlik ayrı ölçülmeli. |
| **P2** | Model ve şablonlar tamamen sentetik; gerçek kalibrasyon/drift/kurumsal NAT davranışı bilinmiyor. | Gerçek veriyi dışarı çıkarmadan müşteri ortamında doğrulama tasarlanmalı. Bu rapordan gerçek başarı oranı çıkarılmamalı. |
| **P2 · kapsam dışı üretim bileşeni** | Canlı IdP, kısa ömürlü gerçek cookie ve sürekli TTL özellik servisi uygulanmadı. | [Yaşam döngüsü](retention_policy.md) gereksinimleri o bileşenler yapılınca ayrıca test edilmeli; mevcut demo belleği bunların yerine geçmez. |
| **P3 · doğrulama sınırı** | Gerçek tarayıcı görsel/erişilebilirlik kontrolü bu ortamda yapılamadı. | İnsan tarafından masaüstü/dar ekran, klavye ve ekran okuyucu kontrolü tamamlanmalı. DOM testi görsel test olarak sunulmaz. |

Bu açık noktalar gizlenmemiştir. Yerel prototipin çalışması ve sözleşme güvenliği doğrulanmış olsa da “yanlış alarm sorunu tamamen çözüldü” veya “üretime hazır” denemez.

## 5. Çalıştırılan testler

| Test grubu | Sonuç |
| --- | --- |
| `tests/test_data.py` | **12 geçti**: nedensel sayaçların bağımsız yeniden hesabı, şema, provenance, ayrım, TTL, başlangıç/sınır durumları |
| `tests/test_models.py` | **22 geçti**: özellik/etiket sınırı, fit-only ön işleme, eşikler, ayrım, hata/eksiklik, katkılar, oturum politikası |
| `tests/test_demo_integration.py` | **3 geçti**: gerçek teslim entegrasyonu ve 10.000 olayın Python–JS puan/gerekçe eşliği |
| `app/tests/test_server.py` | **11 geçti**: HTTP, Host/dosya sınırı, upload reddi, headers/logs, bozuk model/URL |
| Entegrasyon içinden çalıştırılan JS | **17 sözleşme + 10 model/yaşam döngüsü + 12 DOM kontrolü geçti** |
| Notebook | 5 kod hücresi derlendi; execution_count/outputs boş, ham satır önizlemesi yok |
| Canlı loopback smoke | `/`, `/main.js`, `/demo-model.json` 200; veri/joblib yolları 404; POST 501; model sürümü/headers doğrulandı |
| Çalışma ağacı | `git diff --check` geçti |

**Toplam 48 Python testi**. 39 JS/DOM kontrolü, Python entegrasyon testlerinin çağırdığı alt kontrollerdir; birbirinden bağımsız 87 uçtan uca senaryo gibi sayılmamalıdır. Testler model yeniden eğitmez. Canlı smoke 8001 portunda çalıştırıldı ve sunucu kapatıldı; 8000 meşgul olduğunda sunucu anlaşılır hata verdi, mevcut sürece dokunulmadı.

Tam komutlar [README](../README.md#testler) içindedir. CI tanımı eklendi; uzak GitHub Actions çalışması veya push yapılmadı.

## 6. Demo sırasında kullanılabilecek altı senaryo

`python3 app/serve.py` ile açın; port doluysa `--port 8001`. Başlangıç kartlarının **MOCK** olduğunu gösterin. Ardından mevcut `data/mvp_synthetic_logins.csv` dosyasını içe aktarın; yerel model sürümünü doğrulayın. Filtreyi tüm risklerde tutup aşağıdaki **sentetik oturum anahtarını** arayın.

Örnekler yeni üretilmemiştir: mevcut test bölmesinde her senaryonun kronolojik ilk tam puanlanabilir oturumu; N3 için ilk eksik bağlamlı oturum seçilmiştir. Bunlar gösterim örnekleridir, toplu başarı ölçümü değildir. CSV/model değişirse beklenen sonuç da değişebilir.

| Senaryo | Arama anahtarı (yalnız sentetik) | Beklenen mevcut sonuç |
| --- | --- | --- |
| N1 · birkaç yanlış parola | `ses_4732fbbf41fbbfe4e20247fe44e42a9e` | 6 olay; puan **3**, izleme. Yanlış parola etiketi otomatik saldırı sayılmıyor. |
| N2 · normal VPN/yeni cihaz | `ses_4923b8b94e83f9b0d80e274702492c6c` | 1 olay; puan **8**, izleme. Bu örnek genel VPN FPR sorununu ortadan kaldırmaz. |
| N3 · seyahat/yeni cihaz/eksik bağlam | `ses_f5f25006e2cf2461e70fd0a9c4fb5e08` | 4 olay; **puan bekliyor**, eksik bağlam incelemesi. 0 risk gösterilmemeli. |
| S1 · brute force | `ses_5475680d64569902d078c89038af43c7` | 8 olay; puan **99**, MFA + inceleme. |
| S2 · password spraying | `ses_37cfe3f491af5982e97167defc800429` | 1 olay; puan **95**, MFA + inceleme. Kaynak yayılımı özellikte; kaynak token'ı model girdisi değil. |
| S3 · şüpheli başarılı giriş | `ses_0193c3cae5df6e92b1f51190fc1282ca` | 2 olay; puan **74**, MFA + inceleme. Başarı bilgisi modelden bağımsız sentetik manifestte. |

Sonra aramayı temizleyip sayfalama/filtreyi deneyin, 5 dakikalık tutma süresini seçin ve süre sonu davranışını gösterin. “Mock görünüm” sıfırlaması da veriyi bırakır. Model bulunamazsa CSV oturumlarına örnek puan kopyalanmamalıdır. Ağ gözleminde CSV upload veya harici hedef olmamalıdır; yalnız yerel model/uygulama dosyaları okunur. Hiçbir adım hesap kilitlemez veya gerçek MFA başlatmaz.
