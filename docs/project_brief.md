# Ephemeral Login Sentinel

## Problem ve amaç

Giriş olayları tek başına sıradan görünebilir; kısa bir zaman penceresinde bir araya geldiklerinde tek hesaba yoğun denemeler, çok hesaba yayılım veya alışılmadık giriş bağlamı ortaya çıkabilir. Amaç, ham parola, gerçek kullanıcı adı, ham IP veya kalıcı cihaz parmak izi saklamadan bu sinyallerden **oturum başına 0–100 risk puanı** üreten bir prototip tasarlamaktır. **100 en yüksek risktir.**

Yüksek riskin sonucu otomatik hesap kilitleme değildir. Sistem MFA veya insan incelemesi önerir. Puan bir saldırı olasılığı, kimlik doğrulama kararı veya güvenlik garantisi olarak sunulmaz.

## MVP kapsamı

| Senaryo | Aranan sinyal | Sınır |
| --- | --- | --- |
| Brute force | Kayan iki dakikada tek hesaba çok sayıda deneme | Hesap bağlamı müşteri içinde, opak kimlikle ilişkilendirilir. |
| Password spraying | Kayan iki dakikada ortak kaynak bağlamından çok sayıda hesaba deneme | Kaynak gruplaması özellik çıkarımında yapılır; ham kaynak veya IP CSV'ye konmaz. Dağıtık kaynaklı saldırıları kapsama garantisi yoktur. |
| Şüpheli başarılı giriş | Yeni cihaz/ağ ve olağan dışı bağlamla birlikte başarı | Başarı bilgisi müşteri kimlik sağlayıcısında bulunur. Ortak CSV tek olayın başarılı olduğunu kanıtlayan alan içermez. |

MVP; ortak CSV sözleşmesi, geçici ve yerel özellik çıkarımı tasarımı, ileride bağlanacak model arayüzü, açıklanabilir risk görünümü ve MFA/inceleme önerisini kapsar. Kritik kısa pencere **120 saniyedir**; `attempts_1h` ve `failed_ratio_24h` yardımcı bağlamlardır.

## AI 1 tesliminin durumu

- `app/`: Python standart kütüphanesiyle açılan, dış bağımlılıksız yerel web demosu.
- Dört elle yazılmış **mock arayüz kartı**: üç saldırı senaryosu ve olağan bağlam. Bunlar olay veri seti, eğitim örneği veya değerlendirme sonucu değildir.
- Oturum seçimi, anahtar araması, risk filtresi, risk nedenleri, aksiyon önerileri, veri sözleşmesi ve gizlilik görünümü.
- Ortak 17 alanı doğrulayan CSV içe aktarımı; dosya içeriği tarayıcı belleğinde işlenir.
- Model girdisini 11 özellikle sınırlandıran bağdaştırıcı. Model bağlı değildir; içe aktarılan oturumlarda puan **bekliyor** görünür.
- Tek oturumun olaylarını bir araya getiren, tamamı puanlandığında en yüksek olay riskini oturum riski olarak sunan entegrasyon iskeleti.

**AI 1 veri seti üretmez, veri seti araştırmaz, model eğitmez ve başarı metriği hesaplamaz.** Testlerdeki küçük sabit girdiler yalnızca parser ve entegrasyon sözleşmesi testleridir.

## Gizlilik ilkeleri

1. Gerçek kullanıcı kayıtlarını, ham parolaları, ham IP'leri ve sızdırılmış dosyaları hiçbir AI sohbetine yüklemeyin.
2. Müşteri giriş verileri müşteri ortamından çıkmaz. Dış model servisi, telemetri, analitik veya uzaktaki bir CSV yükleme servisi bu tasarımın parçası değildir.
3. Kullanıcı adı gerekmiyorsa tutulmaz. Hesap gruplaması gerektiğinde kimlik sağlayıcısının opak kimliği veya sunucuda üretilen takma kimlik kullanılır. Ham ad loglanmaz ve modele verilmez.
4. Cookie, üretim tasarımında yalnızca kısa ömürlü rastgele oturum anahtarıdır; kalıcı cihaz izi değildir. Demo cookie oluşturmaz.
5. Fare/klavye hareketleri, biyometrisi ve kalıcı cihaz parmak izi toplanmaz.
6. Sızdırılmış parola listeleri giriş olaylarıyla birleştirilmez. Parola sızıntısı kontrolü MVP dışıdır.
7. Gerçek 30 günlük kullanıcı geçmişinin mevcut olduğu varsayılmaz. Bu geçmiş yalnızca AI 2'nin sentetik veri çalışmasında açıkça simüle edilebilir. Eksik geçmiş sıfır veya normal davranış değildir.

## Kapsam dışı

- Gerçek IdP bağlantısı, kimlik doğrulama veya MFA işlemi; otomatik hesap kilitleme.
- Parola toplama, sızdırılmış veri kullanımı, parola sızıntısı kontrolü.
- Kalıcı cihaz tanıma, canvas/font parmak izi, hareket veya tuş vuruşu analizi.
- AI 1 kapsamında veri üretimi, veri araştırması, eğitim, model seçimi ve model değerlendirmesi.
- Üretim erişim kontrolü, çok kiracılı servis, yüksek erişilebilirlik, dağıtık saldırı önleme veya kanıtlanmış gerçek dünya başarısı iddiası.

## İş bölümü ve teslim sınırları

AI 1 yalnızca `docs/project_brief.md`, `docs/architecture.md`, `docs/integration_notes_ai1.md`, `app/` ve kök `README.md` dosyalarının sahibidir. AI 2'nin veri dosyaları, AI 3'ün model dosyaları ve diğer AI'nın raporları bu teslimde oluşturulmaz veya değiştirilmez.

AI 2 ilk kullanılabilir CSV'yi erken teslim eder. AI 3, AI 2'nin fiilen teslim ettiği CSV gelmeden eğitim yapmaz veya metrik üretmez. Bu teslimde CSV beklenmeden yalnızca arayüz ve entegrasyon sözleşmesi hazırlanmıştır. AI 1'in mock kartları AI 2 tesliminin yerine geçmez.

Şema sabittir. Kodlama ve anlam belirsizlikleri [ayrı entegrasyon notunda](integration_notes_ai1.md) raporlanır; sütun eklenmez, çıkarılmaz veya yeniden adlandırılmaz. Model bağlantısı sırasında bağdaştırıcı değişikliğini AI 1 yapar; diğer AI'lar kendi teslimlerini ayrı dosyalarda tutar.

## Kabul ölçütleri

- Ekranda 0–100 risk ölçeği, gerekçeler ve MFA/inceleme önerisi görülebilir.
- Mock puanlar ve açıklamalar her ilgili görünümde açıkça işaretlenir.
- Gerçek model yokken içe aktarılan CSV'ye uydurma veya etiketten türetilmiş puan verilmez.
- Kimlikler, zaman damgası, hedef etiket ve saldırı metaverisi model girdisine sızmaz.
- Puanlanmayan oturum düşük risk olarak gösterilmez; hatalı içe aktarım önceki görünümü korur.
- Hiçbir ekran veya işlem otomatik kilitleme, gerçek MFA isteği veya veri dışa aktarımı yapmaz.
- Kurulum ve demo adımları yeni bir yerel ortamda uygulanabilir.
- Sonuçlar gerçek dünyada doğrulanmış başarı olarak sunulmaz.
