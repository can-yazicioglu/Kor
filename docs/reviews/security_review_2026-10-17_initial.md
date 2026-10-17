> Tarihsel ilk denetim. Güncel sonuçlar için [son incelemeye](../security_review.md) bakın.

# AI 4 — Güvenlik ve bağımsız doğrulama raporu

**Proje:** Ephemeral Login Sentinel  
**İnceleme tarihi:** 17 Ekim 2026  
**Rapor branch'i:** `A4`, A1 tabanından oluşturuldu.  
**Test planı:** [docs/test_plan.md](../test_plan.md)

## 1. Karar

**Birleşik CSV → model → oturum riski demosu şu an geçmez.** A2 CSV'si A1 okuyucusundan geçmiyor; A3 notebook'u ortak şemanın kolon adlarıyla çalışmıyor ve kaydedilmiş model/çıkarım çıktısı içermiyor. A1'in açıkça işaretlenmiş mock ekranı, model çalışıyormuş izlenimi verilmeden sunulabilir.

Mevcut dosyalarda ham müşteri kaydı veya dışarı veri aktarımına ilişkin bir bulgu tespit edilmedi. CSV'de e-posta, IP, özel anahtar ve yaygın API anahtarı örüntüsü eşleşmesi yok; üretici kaynak kodu değerleri sentetik olarak oluşturuyor. Bu, kapsam dışındaki geçmiş commit'ler, başka ortamlar veya verinin kaynağı için mutlak anonimlik/gizlilik garantisi değildir.

**Eğitim, yeniden eğitim, yeni veri üretimi, model çıkarımı veya dashboard değişikliği yapılmadı.** Notebook hücreleri çalıştırılmadı. Sayımlar veri/entegrasyon denetimidir; aşağıdaki hiçbir sayı model başarı metriği değildir. Sadece AI 4'ün iki Markdown raporu oluşturuldu. A1/a2/a3 dosyaları değiştirilmedi; uzak depoya push yapılmadı.

## 2. İncelenen teslimler ve yöntem

`git fetch origin` sonrası aşağıdaki commit'ler incelendi. `A1` ile `origin/A1` aynı commit'teydi. `origin/main` yalnızca `LICENSE` içeriyordu; ayrıca veri/model teslimi yoktu.

| Branch | İncelenen commit | Teslim |
| --- | --- | --- |
| `A1` / `origin/A1` | `590802c718341cef62428a57dbb83561ff7a4d0e` | Mimari, demo, CSV okuyucusu, model bağdaştırıcısı ve testler |
| `origin/a2` | `ca44fccf96df108f8882d21b41e045b98df229dc` | CSV, sentetik üretici ve veri belgeleri |
| `origin/a3` | `8fee079990f028cd0dcfe7d82350fa38b634f7cc` | Kök dizinde `model_pipeline.ipynb` |

Kaynak konumları bu commit'lere aittir. Notebook hücre numaraları Markdown hücreleri dâhil, **1'den başlayan tüm hücre sırası** ile verilmiştir; yürütme sayacı değildir.

Kontroller ortak brief'ten türetildi. A1'in kendi testlerinin geçmesi tek başına entegrasyon başarısı kabul edilmedi; a2'nin gerçek teslim edilmiş dosyası A1 okuyucusuna doğrudan verildi. CSV yalnızca yerel işlemlerde okundu; ham satırlar, hesap/oturum anahtarları veya örüntü eşleşmelerinin değerleri sohbete/rapora çıkarılmadı. Veri üreticisi yalnızca kaynak olarak okundu; çalıştırılmadı.

İnceleme branch uçlarındaki takip edilen dosyaları kapsar. Tüm Git geçmişi, erişilemeyen müşteri ortamı, gerçek IdP, üretim cookie'si, canlı ağ veya fiziksel bellek silme doğrulanmadı. Tarayıcı üzerinden görsel/uçtan uca etkileşim testi yapılmadı. A2'nin dış veri kaynaklarına ilişkin lisans iddiaları yeniden araştırılmadı; bu inceleme veri/model güvenliği üzerinedir.

## 3. Doğrulanan temel sayımlar

| Kontrol | Sonuç |
| --- | --- |
| CSV dosyası | `data/mvp_synthetic_logins.csv`, 1.392.163 bayt |
| SHA-256 | `f95b83d0649a0adfad55ab7de9e75bf7f012f2594e3457c5a0795054a66b003d` |
| Başlık | Ortak 17 alan ve sıra ile tam eşleşiyor |
| Olay / etiket | 10.000 olay; 9.200 normal etiket, 800 şüpheli etiket |
| Boş hücre / fazla hücreli kayıt | 0 / 0 |
| Benzersiz olay / oturum / hesap | 10.000 / 10.000 / 2.885 |
| Sentetik anahtar biçimi dışındaki değer | 0 |
| CSV hassas örüntü taraması | E-posta, IPv4, IPv6, özel anahtar ve yaygın API anahtarında 0 eşleşme |
| Üç teslimin dosya taraması | 18 + 5 + 2 takip edilen dosyada e-posta/özel anahtar/yaygın API anahtarı eşleşmesi 0 |
| Temel negatif değer, flag ve başarısızlık oranı kontrolleri | İncelenen sayısal/boolean alanlarda sınır ihlali yok |
| `attempts_2m > attempts_1h` | **30 satır**; tamamı `suspicious_success` |
| A1 Python sunucu kontrolleri | **7/7 geçti** |
| A1 JavaScript sözleşme kontrolleri | **17/17 geçti** |
| Gerçek A2 dosyası → A1 okuyucusu | **Reddedildi:** `Kayıt 2 · network_familiarity: negatif olmayan sayı bekleniyor.` |
| A3 notebook | 27 kod hücresi; 0 kaydedilmiş yürütme sayacı, 0 kaydedilmiş çıktı |
| A3 takip edilen model/metrik dosyası | Yok; yalnızca notebook ve lisans var |

Son iki satır notebook'un başka bir yerde hiç çalıştırılmadığını ispatlamaz; **bu commit'te doğrulanabilir eğitim/çıkarım çıktısı teslim edilmediğini** gösterir.

## 4. Öncelikli bulgular

P0: bu kapsamda tespit edilmedi. P1: birleşik demoyu veya temel güvenilirlik sözleşmesini engelleyen sorun. P2: doğrulama/gizlilik kapsamı veya sağlamlık eksikliği. Durumlar fiilen gözlenen hata ile gelecekteki entegrasyon riskini ayırır.

| Kimlik | Öncelik | Bulgu | Durum / sorumlu |
| --- | --- | --- | --- |
| A4-01 | **P1** | A2 ağ aşinalığı kodlaması A1 okuyucusuyla uyumsuz | Yeniden üretildi · AI 1 + AI 2 |
| A4-02 | **P1** | A3 şema yapılandırması yanlış; baseline da ortak özellikleri kullanmıyor | Kaynak ve başlık kontrolüyle doğrulandı · AI 3 |
| A4-03 | **P2** | A3 kimlikleri kesin bir özellik listesi yerine blacklist/benzersizlik sezgisiyle dışlıyor | Kod kusuru; fiilen eğitilmiş modelde sızıntı gözlenmedi · AI 3 |
| A4-04 | **P2** | Sayaç tutarsızlığı ve gerçek kayan pencere doğrulamasının eksikliği | 30 kesin tutarsız kayıt + belgelenmiş sentetik özet sınırı · AI 2 |
| A4-05 | **P2** | Normal zor durumlar ve eksik geçmiş yeterince temsil edilmiyor | Veri kapsamı doğrulandı; yanlış alarm oranı ölçülemedi · AI 2 + AI 3 |
| A4-06 | **P1** | A3'ün tasarladığı çıktı A1 oturum/puan/gerekçe sözleşmesine bağlanamıyor | Kaynak sözleşmesi uyumsuz; model çıktısı ayrıca eksik · AI 1 + AI 3 |
| A4-07 | **P2** | Yanlış alarm koşuluna uyan eşik yoksa notebook sessizce 50 döndürüyor | Kod yolu doğrulandı; mevcut veriyle gerçekleştiği iddia edilmiyor · AI 3 |
| A4-08 | **P2** | Silme yaşam döngüsü uçtan uca uygulanmış değil; notebook kayıt kalıcılığı ayrı ele alınmamış | Tasarım/uygulama kapsamı eksikliği; mevcut ham veri sızıntısı değil · AI 1 + AI 3 |

### A4-01 — CSV kodlama uyumsuzluğu

**Kanıt:** A2 üreticisi `src/data/generate_synthetic.py:136` satırında `network_familiarity` için `familiar/unfamiliar` metinlerini üretir. Teslim edilen CSV'de 7.434 `familiar`, 2.566 `unfamiliar` vardır. A1 `app/schema.js:14` alanı oran sayar; `app/schema.js:87` sayısal olmayan değeri reddeder. Dosya 2 MiB ve 10.000 olay sınırları içindedir; ret sebebi boyut değildir.

**Etki:** İlk veri kaydında içe aktarım durur; kullanılabilir CSV ile dahi oturum görünümüne geçilemez. A1'in birim testleri bu branch'ler arası uyumsuzluğu kapsamamıştır.

**Öneri:** Sütun adı ve sırası değişmeden ortak veri sözlüğünde kategori/sayı kararı verin. Mevcut A2 teslimi esas alınacaksa AI 1 okuyucusu ve AI 3 kategorik ön işleme sözleşmesi buna uyarlansın. Açık bir anlaşma olmadan `familiar→1` gibi örtülü dönüşüm yapılmasın. Kabul ölçütü, aynı sabit CSV'nin 10.000 kaydının okuyucudan geçmesi ve model yokken puanların hâlâ beklemesidir.

### A4-02 — Notebook yapılandırması ve baseline

**Kanıt:** A3 hücre 2, satır 23–27 `TARGET='label'`, `TIME_COL='timestamp'`, `USER_COL='user_id'` kullanır. Üçü de CSV'de yoktur. Hücre 4, satır 12–13 bu nedenle duracaktır. A3 branch'i tek başına CSV de içermez; yoksa dosya guard'ı önce durur. Ortak teslimler yerel olarak bir araya getirilse bile kolon guard'ı engeli devam eder.

Ek olarak hücre 9'daki beş baseline kuralının dördü ortak şemada bulunmayan `failed_attempts_last_hour`, `is_new_device`, `is_new_country`, `ip_reputation_score` alanlarına dayanır. Yalnızca üç yapılandırma adı düzeltilirse aktif kalan tek kural, hücre 5'te sonradan türetilen `hour <= 5` olur. Puan aktif kuralların toplamına bölündüğü için bu tek gece kuralı **0 veya 100** üretir. Bu matematiksel kod davranışıdır; çalıştırılmış model sonucu değildir.

**Etki:** Eğitim şu hâliyle başlayamaz. Yüzeysel bir kolon adı düzeltmesi de üç saldırı senaryosuna uygun bir baseline sağlamaz; gece girişleri tek başına en yüksek risk olabilir. İki dakikalık yoğunluk/yayılım baseline'a yansımaz.

**Öneri:** AI 3, sabit şemayı değiştirmeden kendi yapılandırmasını `is_suspicious`, `event_ts_utc`, `account_token` ile eşleştirsin; baseline yalnızca mevcut ve anlamı kararlaştırılmış özellikleri kullansın. Eksik zorunlu özellikler sessizce atlanmasın. N1–N3 karşı örnekleriyle anlamlılık kontrolünden sonra değerlendirmeye geçilsin. Bu denetimde düzeltme veya eğitim yapılmadı.

### A4-03 — Kesin özellik sınırı yerine sezgisel dışlama

**Kanıt:** A3 hücre 2'deki `ID_COLS`, ortak şemanın üç kimlik alanını ismen dışlamaz. Hücre 5 `df.drop(...)` sonrası bütün kalan alanları aday alır; yalnızca metin olup benzersizlik oranı `>0.5` olanları siler. Bu karar tüm veri üzerinde, bölmeden önce hesaplanır. Hücre 5 ayrıca `hour/dayofweek` ekler; bunlar A1'in 11 özellikli bağlantı sözleşmesinde yoktur.

Mevcut CSV'de olay ve oturum tokenları tekildir. Zorunlu üç ayar doğru eşlenirse `account_token` açıkça düşer, olay ve oturum anahtarları da bu örnekte benzersizlik sezgisiyle düşer. Dolayısıyla **“mevcut model kimliklerle eğitildi” sonucu çıkarılamaz**: model yok ve ham yapılandırma zaten çalışmıyor. Ancak tekrar eden oturumlar veya pandas tarafından sayısal okunan kimlikler aynı korumadan geçmeyebilir. `is_suspicious`ın dışlanması da doğru `TARGET` ayarına bağlıdır; `attack_type` açıkça dışlanmıştır.

**Etki:** İleride geçerli farklı bir CSV, eğitim özelliklerine kimlik sokabilir. Test kümesinin benzersizlik dağılımı özellik seçimini etkiler; ön işleme pipeline'ının yalnızca eğitimde fit edilmesi bu önceki seçimi düzeltmez.

**Öneri:** AI 3'te A1 ile aynı açık özellik listesi kullanılsın; yasak alanların dönüştürülmüş model özelliklerinde de bulunmadığını doğrulayan kontrol eklensin. Kimlik/etiket/metaveri değişince özelliklerin değişmediği test edilsin. Timestamp'ten ek özellik isteniyorsa CSV şemasını değiştirmeden ayrı bir bağlantı sözleşmesi önerisi olarak onaylansın; sessizce 13 özellikli modele geçilmesin.

### A4-04 — Pencere ve sayaç tutarlılığı

**Kanıt:** A2 `src/data/generate_synthetic.py:275` aynı kayıt için iki dakikalık sayıyı 1–3, bir saatlik sayıyı 1–8 aralığından bağımsız seçer. Teslim edilen CSV'de **30 kayıtta `attempts_2m > attempts_1h`** bulunur; ilk dosya satır numaraları 1227, 1279, 1291, 1292, 1382'dir. Değerler/anahtarlar burada yayımlanmamıştır.

Aynı hesap kapsamı ve aynı bitiş zamanı varsayımıyla iki dakikalık pencere bir saatlik pencerenin alt kümesidir; bu 30 kayıt tutarsızdır. Ayrıca brute force sayıları episode zamanlarından önce atanır (`:231–239`); spraying'de bütün episode'un hesap sayısı her kayda yazılır (`:249–258`). Bunlar olay anındaki geçmiş satırlardan yeniden hesaplanmış kayan sayaçlar değildir. A2 belgesi de 24 saat oranının ve coğrafi hızın örneklendiğini açıkça belirtir (`docs/synthetic_data.md:45`).

CSV gözlenen bütün girişleri içerdiğini iddia etmediği için, dosyadaki geçmiş satır sayısı ile sayacın her uyuşmazlığı ayrı bir hata veya gerçek gelecek-veri sızıntısı sayılmadı. **Kesin bulgu 30 alt-küme tutarsızlığıdır; kalan konu gerçek pencere doğrulamasının yokluğudur.** Kaynak anahtarı ve giriş sonucu olmadığı için spraying gruplaması ile başarısızlık oranı bu CSV'den bağımsız olarak yeniden kurulamaz.

**Öneri:** AI 2 aynı kapsamda `attempts_1h >= attempts_2m` değişmezini sağlamalı. Özelliklerin sentetik özet mi, olaylardan türetilmiş sayaç mı olduğu açıkça ayrılmalı. Kaynak/episode denetim metaverisi gerekiyorsa sabit CSV'ye eklenmeden, müşteri/sentetik test ortamındaki ayrı bir manifestte tutulmalı ve modele verilmemeli. 120 saniye sınırı, yinelenen/geç olay ve cookie yenileme kontrolleri özellik çıkarıcı tesliminde yürütülmeli.

### A4-05 — Yanlış alarm ve zor normal bağlam kapsamı

**Kanıt:** 9.200 negatif örneğin tamamında `hour_deviation` 0–1, `geo_velocity_kmh` 0–250 aralığında; boş özellik yoktur. 1.495 `user_error` ve 1.132 `vpn_new_device` örneği bulunması yararlıdır. Ancak VPN/yeni cihaz örneklerinin de saati olağandır; bu alt grubun 379 kaydı gerçekten `asn_category='vpn'` taşır, tamamı VPN değildir. Ayrı bir normal seyahat senaryosu yoktur.

Brute force örneklerinde saat sapması 5–12 ve 24 saat başarısızlık oranı 0,623–0,999; `suspicious_success` örneklerinde saat sapması 5–12 ve hız 500–5.994'tür. Bu ayrımlar üretici kurallarıyla güçlü biçimde sınıfı işaretler. Bu bir model metriği veya yasak etiket kolonunun doğrudan modele verildiği kanıtı değildir; **sentetik görevin kolaylaşması ve gerçek normal davranışın dar temsil edilmesi** sorunudur.

**Etki:** Gelecekte yüksek sentetik skor alınsa dahi VPN konum sıçraması, seyahat, gece çalışma, yeni cihaz + yeni ağ ve eksik geçmiş için yanlış alarm davranışı bilinmez. Hiç eksik değer olmaması A1'in `null` politikasını ve AI 3'ün imputasyon kararını bu veriyle sınamayı engeller. A3 median/most-frequent imputasyon tasarlar; eksikliğin nasıl işaretleneceği veya ne zaman puan üretilemeyeceği ortak sözleşmede netleştirilmelidir.

**Öneri:** AI 2/AI 3 normal zor durumları ayrı değerlendirme grupları olarak planlasın; AI 4 bu çalışmada veri üretmez. Mevcut çıktılar geldiğinde N1/N2/N3 için ayrı destek sayısı ve yanlış alarm ölçümü raporlansın. N3 temsil edilmeden “seyahatte gereksiz alarm vermiyor” denmesin. Başarı sonucunun CSV'de bulunmadığı açık tutulmalı; `attack_type='suspicious_success'` girişin başarılı olduğuna bağımsız kanıt sayılmamalı.

### A4-06 — Model çıktısı ve oturum entegrasyonu eksik

**Kanıt:** A1 `app/model-adapter.js:6` her zaman `null` döndürür. Doğrulayıcı, 0–100 **tamsayı** `risk_score`, `reasons` ve `model_version` ister. `app/sessions.js` sonuçları gerçek `session_token` üzerinden ilişkilendirir.

A3 hücre 7 olasılığı 100 ile çarpar; hücre 36 çıkışta bir ondalıklı model skorlarıyla `user_id`, `timestamp`, `label` sütunları yazar. Planlanan CSV'de `event_id/session_token`, olay bazlı `reasons` ve `model_version` yoktur; model açıklama hücreleri küresel katsayı/SHAP özetleri üretir, oturumun gerekçe sözleşmesini sağlamaz. A3'ün takip edilen çıktısı bulunmadığı için gerçek skorun aralığı, eşlemesi veya doğruluğu denetlenemedi.

**Etki:** Bu export doğrudan A1'e bağlanamaz. Hesap/zaman çifti bir olay/oturum anahtarının güvenilir yerine geçmez. Ondalıklı puan doğrudan verilirse A1 reddeder. Yeni dosyada özellikleri yeniden türetmek veya etiketten gerekçe üretmek çözüm değildir.

**Öneri:** AI 1 + AI 3, müşteri içinde çalışan bir çıkarım sözleşmesini ortaklaştırmalı. Model sadece 11 özellik almalı; olay/oturum korelasyonu model dışında korunmalı. Puan dönüşümü/yuvarlama ve eşik uygulama sırası, neden üretme yöntemi ve model versiyonu birlikte tanımlanmalı. Nihai bağlama kadar mock ibaresi ve CSV için “puan bekleniyor” korunmalı. Model yokluğu güvenli oturum demek değildir.

### A4-07 — Uygun eşik bulunamaması sessiz geçiliyor

**Kanıt:** A3 hücre 14, satır 11–19 `best_t=50` ile başlar; sadece 1–99 adaylarını dener. Hiçbir aday `FAR_TARGET` koşulunu sağlamazsa yine 50 döndürür ve bunun başarısız seçim olduğunu belirtmez. Hücre 9 baseline ayrıca eksik girdileri `fillna(0)` ile etkisiz sinyal yapar.

**Etki:** Kod, koşulu karşılayan eşik bulunmadığı bir durumda bile seçilmiş eşik varmış gibi sonraki raporlara devam edebilir. Koşulun test kümesinde ayrıca garanti edilmesi zaten mümkün değildir; doğrulama kümesindeki seçim başarısızlığının da görünmesi gerekir. Bu yolun mevcut CSV'de gerçekleştiği ölçülmedi.

**Öneri:** Uygun eşik yokluğu ayrı bir sonuç/hata olmalı; varsayılan 50'ye sessiz dönüş kaldırılmalı. Eşik uçları, alarm üretmeme seçeneği ve tüm eşiklerin başarısız olduğu durum için sözleşme testleri eklenmeli. Eksik sinyal normal davranışla eşitlenmemeli. Gerçek yanlış alarm sonuçları ancak AI 3'ün teslim ettiği tahminlerle değerlendirilmeli.

### A4-08 — Silme ve notebook kalıcılığı

**Kanıt:** A1 `app/main.js:159–165` sıfırlamada veri referanslarını bırakır; ayrıca sayfa kapanışı/yenileme davranışı belgelenmiştir. Otomatik 120 saniyelik bellek temizliği veya gerçek cookie uygulanmamıştır. `docs/architecture.md:51,60,146` cookie TTL'si, kaynak bağlamının silinmesi ve 1 saat/24 saat yardımcı sayaçları **hedef tasarım** olarak anlatır; uygulanan üretim yaşam döngüsü değildir.

A3 hücre 4, satır 10 doğrulama öncesi `display(df.head())` ile kayıtları notebook çıktısına yazar. Hücre 36 hesap kimliği, zaman ve hedef etiketi içeren `demo_risk_scores.csv` dosyasını kalıcılaştırmayı planlar. Bu çıktılar mevcut commit'te yoktur; bugün gerçekleşmiş ham hassas veri sızıntısı denmiyor. Ancak müşteri kayıtlarıyla tekrar kullanılırsa notebook/output klasörlerinin saklama, erişim ve paylaşım sınırı ayrıca gerekir.

**Etki:** “Tüm veri iki dakikada siliniyor” veya “hiçbir kayıt kalıcılaşmıyor” denemez. İki dakikalık analiz penceresi, cookie ömrü ve dosya saklama süresi farklı kavramlardır. A2'nin açıkça sentetik CSV'sinin depoda kalması tek başına müşteri verisi silme kuralı ihlali değildir.

**Öneri:** CSV, notebook çıktıları, model, geçici kaynak bağlamı ve uzun pencere sayaçları için ayrı yaşam döngüsü tablosu oluşturulmalı. AI 3 satır önizlemesini güvenli özetlerle değiştirmeli; gerekmedikçe kimlik/etiketi export etmemeli. Kimlik eşlemesi gerekiyorsa müşteri içi geçici katmanda tutulmalı. Gerçek özellik servisi geldiğinde TTL dolması/silme testi çalıştırılmalı; yalnızca tasarımdan geçti sonucu çıkarılmamalı.

## 5. Kullanıcı, zaman ve senaryo sızıntısı denetimi

**A1:** Açık 11 özellik listesi ve `selectFeatures` sayesinde `event_id`, `session_token`, `account_token`, `is_suspicious`, `attack_type` ile ham zaman modele aktarılmaz. Mevcut sözleşme testleri bunu doğruluyor. A1 modeli olmadığı için bu, özellik aktarım sınırının kontrolüdür.

**A3:** Gerçekte üretilmiş bir eğitim/test bölmesi veya model yok. Hücre 6'nın amaçladığı kullanıcı + zaman ayrımını değerlendirmek için, yalnızca üç zorunlu alan adının doğru eşleneceği varsayımıyla mevcut CSV üzerinde **salt okunur bir bölme tanısı** yapıldı. Notebook değiştirilmedi; eğitim/çıkarım/performans hesabı yapılmadı. Tanıda NumPy 2.3.5, seed 42, kronolojik sıralama, %20 kullanıcı ayırma, 0,70 zaman yüzdeliği ve eğitim içi 0,80 doğrulama yüzdeliği kullanıldı.

| Geçici tanı | Sonuç |
| --- | ---: |
| Fit / doğrulama / test satırı | 4.492 / 1.124 / 605 |
| İki koşulun dışında kaldığı için dışlanan satır | 3.779 |
| Eğitim (fit + doğrulama) ile test arasında hesap kesişimi | **0** |
| Fit ile doğrulama arasında hesap kesişimi | **727** |
| Eğitim sonu ile test başlangıcı arasındaki fark | 1.410 saniye |
| Fit sonu ile doğrulama başlangıcı arasındaki fark | 54 saniye |
| Fit ile testte ortak tam 11 özellik vektörü | 1 |
| Hesap + 120 saniye yakınlığıyla gruplanan brute force kümelerinin fit/doğrulama kesişimi | 0 |

Bu tanı fiilen eğitilmiş bir modele ait ayrım olarak sunulamaz; sürüm/sıralama ve gerçek çalıştırma çıktısı geldiğinde tekrar doğrulanmalıdır. 727 ortak hesap, fit/doğrulama ayrımının kullanıcıdan bağımsız olmadığını gösterir; **eğitim/test kullanıcı sızıntısı bulunduğu anlamına gelmez**. Aynı özellik vektörünün bir kez tekrarı da düşük ayrıntılı sentetik normal kayıtlarda mümkün olduğundan tek başına kopya olay veya sızıntı kanıtı değildir.

Bu snapshot'taki 1.410 saniyelik eğitim/test boşluğu kısa saldırı episode'larını ayırmak bakımından olumludur. Bununla birlikte kodda açık bir pencere boşluğu/episode gruplama şartı yoktur. CSV kaynak/episode kimliği taşımadığından spraying episode bağımsızlığı tam ispatlanamaz; fit/doğrulama sınırı da sadece 54 saniyedir. Aynı `attack_type` sınıflarının iki kümede bulunması normaldir; senaryo sızıntısı diye tek başına sayılmamalıdır. Asıl sınanması gereken aynı episode'un veya aynı kolay üretim şablonunun genelleme iddiasını şişirip şişirmediğidir.

Preprocessor pipeline'ları fit aşamasında eğitim dilimine uygulanacak şekilde yazılmıştır; bu olumlu bir tasarım kontrolüdür. Buna karşılık tüm veri üzerindeki kimlik-benzerliği seçimi A4-03'te belirtilmiştir. Model tesliminden sonra gerçek bölme manifesti ve senaryo bazlı çıktılar kontrol edilmeden “tamamen sızıntısız değerlendirme” onayı verilmez.

## 6. Gizlilik ve iddia kontrolünün sonucu

| Kontrol | Karar | Gerekçe |
| --- | --- | --- |
| Ham parola / kullanıcı adı / IP / sızdırılmış liste | **İncelenen teslimlerde bulgu yok** | Sabit alanlar, sentetik üretim kodu ve örüntü kontrolleri; kapsam dışı köken için garanti değil |
| A1'den dışa veri gönderimi | **Geçti, mevcut statik sınır kapsamında** | File API ile yerel okuma, CSP `connect-src 'none'`, dış script/font/telemetri yok, upload endpoint'i yok |
| A1 erişim logu / cookie / kalıcı browser storage | **Geçti, kod ve sunucu testleri kapsamında** | Erişim logu kapalı; cookie ve web storage kullanımı yok |
| Fare/klavye biyometrisi ve kalıcı cihaz izi | **İncelenen kodda yok** | Arama/form etkileşimleri davranış kaydı için kullanılmıyor |
| Kimlik/etiket/model ayrımı | **A1 geçti; A3 için sağlamlaştırma gerekli** | A1 allowlist; A3 blacklist/sezgi ve çalışmayan yapılandırma |
| Gerçek 30 günlük geçmiş varsayımı | **Geçti, belge/kaynak kapsamında** | A2 geçmişi açıkça sentetik, A1 bilinmeyeni `null` tutuyor |
| 120 saniyelik gerçek sayaç ve silme | **Kısmen tasarım; çalışma davranışı doğrulanamadı** | Özellik servisi/cookie yok; A4-04 ve A4-08 |
| VPN/seyahat/yeni cihaz/yanlış parola yanlış alarmı | **Doğrulanamadı** | Veri kapsamı sınırlı; model/tahmin teslimi yok |
| Otomatik kilitleme | **İncelenen uygulamada yok** | A1 yalnızca MFA/inceleme önerisi gösteriyor |
| Sentetik sonucun gerçek başarı gibi sunulması | **Mevcut A1/A2 belgelerinde bulunmadı** | Açık mock/sentetik uyarıları var. A3'te henüz metrik yok; gelecekteki çıktı raporuna aynı sınırlama eklenmeli. |

“Gerçek CSV” ifadesi A3'te **AI 2 tarafından fiilen teslim edilen sentetik dosya** olarak anlaşılmalıdır; gerçek müşteri kaydı talebi değildir. Hiçbir gerçek kayıt AI sohbetine yüklenmemelidir.

## 7. Demo sırasında kullanılabilecek test akışı

Bu bölüm uygulamaya senaryo eklemez veya veri üretmez. Mevcut mock ekranında yalnızca dört kart vardır. Altı bağımsız senaryonun tamamı bugün çalıştırılmış gibi sunulamaz.

### Bugünkü demo

1. `python3 app/serve.py` ile yerel ekranı açın. **MOCK** uyarısını gösterin; örnek puanların model sonucu olmadığını söyleyin.
2. Brute force mock kartında 86, spraying kartında 74, yeni bağlamdan başarı kartında 61 örnek puanı ve gerekçeleri gösterin. Bunlar sırasıyla S1/S2/S3'ün yalnızca arayüz anlatımıdır; saldırı tespit testi değildir.
3. Olağan bağlam kartındaki 18 puanın da mock olduğunu gösterin. Bu kart N1/N2/N3'ün ayrı doğrulamasının yerine geçmez.
4. Risk filtresi ve arama üzerinden bir oturumu seçin. Aksiyonların MFA/inceleme önerisi olduğunu, otomatik kilitleme veya gerçek IdP işlemi olmadığını kontrol edin.
5. A2'nin mevcut, onaylı sentetik CSV'si seçildiğinde beklenen mevcut sonuç **A4-01 doğrulama hatasıdır**. Önceki mock görünüm korunmalı; hata satır değerini/tokenı göstermemeli. Bu olumsuz entegrasyon testi raporda kapanana kadar geçerli veri içe aktarıldı denmemeli.
6. Veri sözleşmesi ve gizlilik ekranlarını gösterin. CSV'nin sunucuya yüklenmediğini, “2 dakika”nın modelin/özellik servisininki gibi uygulanmış bir silme garantisi olmadığını açıklayın.

### Veri/model uyumu düzeltildikten sonraki kabul testleri

| Senaryo | Mevcut veri desteği | Sonraki demo/doğrulama koşulu |
| --- | --- | --- |
| N1 · yanlış parola | 1.495 `user_error`; gerçek başarı sonucu yok | Alt grupta tahmin çıktısı geldiğinde alarm sayısı incelensin; kısa hata dizisi otomatik saldırı sayılmasın. |
| N2 · VPN | `vpn_new_device` içinde 379 VPN kaydı; diğer negatiflerde de VPN var | VPN alt grubunun tamamı ayrıca değerlendirilsin; yüksek konum sıçramalı normal durumun mevcut veride eksik olduğu belirtilsin. |
| N3 · seyahat + yeni cihaz + eksik geçmiş | Tam senaryo temsil edilmiyor | **Şu an doğrulanamaz.** AI 2/AI 3 uygun ayrı test teslimi sağladığında incelensin. |
| S1 · brute force | 320 kayıt, kısa aynı-hesap episode'ları | Gerçek 120 saniye sayacı ve cookie yenilemesine dayanım ayrıca doğrulansın; sadece yüksek sentetik sayı yeterli değil. |
| S2 · password spraying | 240 kayıt; kaynak kimliği yok | Müşteri içi kaynak korelasyonu/ayrı episode manifesti olmadan uçtan uca spraying tespiti iddia edilmesin. |
| S3 · şüpheli başarılı giriş | 240 senaryo etiketi; bağımsız giriş sonucu yok | Başarı IdP seviyesinde doğrulansın; `attack_type` tahmin girdisi veya açıklaması yapılmasın. |

A4-01 kapandıktan sonra model hâlâ bağlı değilse içe aktarılan tüm oturumlar **puan bekliyor** görünmelidir. Etiketler değişse bile model özellikleri değişmemelidir. Model hata/null döndürdüğünde veya bir oturumun bir olayı puanlanamadığında oturum düşük risk sayılmamalıdır. Gerçek model bağlandıktan sonra puan 0–100, nedenler aynı puanlanan olaya ait ve aksiyon MFA/inceleme olmalıdır.

## 8. Tekrar üretme ve kapanış sırası

Mevcut A1 testleri, A4 branch'inde aynı kaynaklar üzerinde:

```bash
python3 -m unittest discover -s app/tests -p 'test_*.py' -v
node app/tests/contracts.test.mjs
```

Node.js komutu Node 20+ gerektirir; demoyu çalıştırmak için gerekmez. Denetimde JavaScript kontrolleri mevcut Node çalışma aracı üzerinden aynı dosyalarda çalıştırıldı. Bu komutlar eğitim veya veri üretimi çalıştırmaz.

CSV sayımı ve alt-pencere tutarsızlığını satır içeriğini yazdırmadan tekrar üretme:

```bash
python3 - <<'PY'
import csv, hashlib, io, subprocess
ref = 'ca44fccf96df108f8882d21b41e045b98df229dc'
blob = subprocess.check_output(['git', 'show', ref + ':data/mvp_synthetic_logins.csv'])
rows = list(csv.DictReader(io.StringIO(blob.decode('utf-8-sig'))))
print('sha256:', hashlib.sha256(blob).hexdigest())
print('rows:', len(rows))
print('attempts_2m > attempts_1h:', sum(
    int(r['attempts_2m']) > int(r['attempts_1h']) for r in rows
))
PY
```

Beklenen sonuç: yukarıdaki SHA-256, 10.000 satır ve 30 tutarsız kayıt. CSV veya notebook'u terminale bütünüyle dökmek, sohbet ortamına yüklemek ya da notebook'un eğitim hücrelerini çalıştırmak bu denetimin parçası değildir.

**Kapanış sırası:**

1. **AI 1 + AI 2:** Ağ aşinalığı kodlamasını ortaklaştır; A4-01 çapraz branch testi geçsin. AI 2 30 sayaç tutarsızlığını düzeltsin ve veri sürümünü belgelesin.
2. **AI 3:** Sabit alan adları, açık özellik listesi ve uygun baseline ile kendi kodunu düzelt; yokluk/eksiklik guard'larını koru. AI 4 bu işlem kapsamında eğitim yapmaz.
3. **AI 1 + AI 3:** Çıkarım sonucu, kimliklerin model dışı eşlemesi, gerekçe ve versiyon sözleşmesini bağla. Model teslimi olmadan başarı/yanlış alarm oranı yayınlama.
4. **AI 2 + AI 3:** Normal zor durumlar, gerçek bölme manifesti ve senaryo bazlı tahminleri teslim et; AI 4 N1–N3/S1–S3'ü ve sızıntı kontrollerini tekrar değerlendirir.
5. **Entegrasyon sahipleri:** Pencere, cookie, bellekteki geçici bağlam ve diskteki çıktılar için uygulanabilir silme/erişim politikasını tamamla. Model/sentetik başarı iddialarının sınırlarını demo ve sonuç raporunda koru.

Bu değişiklikler bu raporda **öneridir**; A1/a2/a3 koduna uygulanmamıştır. Yeni commit veya gerçek model çıktısı gelirse bu incelemenin kanıt kapsamı güncellenmelidir.
