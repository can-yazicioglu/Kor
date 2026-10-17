# Ephemeral Login Sentinel

Ham parola, gerçek kullanıcı adı, ham IP ve kalıcı cihaz parmak izi saklamadan giriş bağlamını değerlendirmek için hazırlanan **AI 1 mimari ve yerel demo teslimi**.

Oturum riski **0–100** aralığındadır; **100 en yüksek risktir**. Yüksek riskte MFA veya insan incelemesi önerilir. Otomatik hesap kilitleme bulunmaz.

> **Durum:** Model bağlı değil. Açılıştaki dört kart elle yazılmış **MOCK arayüz önizlemesidir**; veri seti, eğitim çıktısı veya başarı metriği değildir. CSV içe aktarılabilir; gerçek model bağlanmadan bu CSV'ye puan verilmez.

## Çalıştırma

Python 3.10 veya üzeri yeterlidir. Paket kurulumu, API anahtarı, Node.js veya ağ bağlantısı gerekmez.

Depo kökünde:

```bash
python3 app/serve.py
```

Tarayıcıda **http://127.0.0.1:8000** adresini açın. Windows'ta uygun kurulumda `py -3 app/serve.py` kullanılabilir. Durdurmak için terminalde `Ctrl+C`.

Port doluysa:

```bash
python3 app/serve.py --port 8001
```

Bu durumda **http://127.0.0.1:8001** adresini açın. Sunucu yalnızca loopback'te dinler. `index.html` dosyasını doğrudan `file://` olarak açmayın; ES modülleri HTTP üzerinden sunulmalıdır. Depo kökünü genel bir dosya sunucusuyla paylaşmak yerine verilen sunucuyu kullanın; yalnızca demo varlıkları erişilebilir olur.

## Demo akışı

1. Genel görünümde **MOCK** uyarısını ve dört gösterim kartını görün.
2. Tek hesaba yoğun deneme kartını seçin: 86/100 örnek risk, örnek nedenler ve **MFA + inceleme öner** aksiyonu görünür.
3. Çok hesaba yayılım ve yeni bağlamdan başarılı giriş kartları arasında geçin. Puanların örnek olduğunu koruyun; bu kartlar gerçek olay değildir.
4. Risk filtresini değiştirin veya `mock-session-03` arayın. Filtre seçimi değiştirir; üstteki sayaçlar ve dağılım tüm yüklü oturumların özetidir.
5. **Veri sözleşmesi** ve **Gizlilik sınırı** görünümlerini inceleyin.
6. AI 2'nin kullanıma hazır, onaylı sentetik CSV'si geldiğinde **CSV içe aktar** ile yerelden seçin. Bu teslim bir veri seti içermez. Gerçek müşteri dosyalarını AI sohbetine yüklemeyin.
7. Geçerli CSV'de olaylar `session_token` ile gruplanır. Model bağlı olmadığı için risk **— / Puan bekleniyor** görünür; hedef etiket ve saldırı türü skora dönüştürülmez.
8. Hatalı CSV değerleri loglanmadan reddedilir, önceki görünüm korunur. **Mock görünüm** düğmesi içe aktarılan kayıtlara uygulama referanslarını bırakır ve mock kartları geri getirir.

Öneriler yalnızca ekranda gösterilir. Demo gerçek MFA isteği, hesap kilitleme veya başka bir dış işlem yapmaz.

## CSV sözleşmesi

```csv
event_id,event_ts_utc,session_token,account_token,attempts_2m,attempts_1h,distinct_accounts_2m,failed_ratio_24h,hour_deviation,typical_weekday,geo_velocity_kmh,network_familiarity,asn_category,device_managed,device_new,is_suspicious,attack_type
```

- Tam 17 alan, aynı sıra, UTF-8 ve virgül ayırıcı gerekir. BOM ve CRLF desteklenir.
- En fazla **2 MiB / 10.000 olay**. Yinelenen `event_id` ve geçersiz zaman/tip reddedilir.
- Boş özellikler bilinmiyor (`null`) kalır; 30 günlük gerçek geçmiş varsayılmaz.
- Üç kimlik, olay zamanı, hedef etiket ve saldırı metaverisi model girdisi değildir. Model sadece **11 izinli özelliği** alır.
- Alan türleri ve kaynak/sayaç kapsamı için [mimari sözleşmesini](docs/architecture.md) ve [geçici entegrasyon kararlarını](docs/integration_notes_ai1.md) okuyun.

## Dosyalar ve sahiplik

```text
README.md                       AI 1 — kurulum ve demo
docs/
  project_brief.md               Problem, amaç, MVP ve kapsam dışı işler
  architecture.md                Akış, gizlilik, sabit şema ve model çıktısı
  integration_notes_ai1.md        Şema değişmeden açık entegrasyon konuları
app/
  index.html / styles.css         Türkçe, duyarlı demo ekranı
  main.js                       Ekran ve yerel CSV içe aktarımı
  mock-view.js                  Yalnızca sabit sunum kartları
  schema.js                     Parser, doğrulama, özellik allowlist'i
  sessions.js                   Oturum gruplaması ve hata davranışı
  model-adapter.js               AI 3 bağlantı sınırı; bugün null döner
  serve.py                      Bağımlılıksız loopback statik sunucu
  tests/                        Sözleşme ve sunucu sınırı testleri
```

Bu teslim yalnızca AI 1 dosyalarını içerir. Veri üretimi/araştırması, eğitim ve değerlendirme yapılmaz. Diğer AI'ların dosyaları değiştirilmez. AI 3 fiilen kullanılabilir CSV gelmeden eğitim veya metrik üretmemelidir.

## Modeli bağlama

AI 3'ün teslimi geldiğinde `app/model-adapter.js` içindeki `predictRisk(features)` müşteri ortamında çalışan çıkarıma bağlanır. Fonksiyon yalnızca 11 özellik alır ve `null` veya `{ risk_score, reasons, model_version }` döndürür. Ayrıntılı çıktı sözleşmesi [mimaride](docs/architecture.md) yer alır.

Mevcut sunucu ağ isteklerini CSP ile kapatır (`connect-src 'none'`). Bir yerel API kullanılacaksa aynı müşteri sınırında kalacak şekilde sunucu/CSP ve yetkilendirme birlikte tasarlanmalıdır. Dış AI API'si veya uzaktaki model servisi eklemeyin.

Tüm olaylar puanlandığında oturumun en yüksek olay puanı gösterilir. Herhangi bir olay puanlanamazsa oturum **bekliyor** kalır. 30 ve 70 eşikleri demo varsayımlarıdır; kalibrasyon veya gerçek dünya başarısı iddiası yoktur.

## Kontroller

Python ile statik sunucu ve gizlilik sınırı testleri:

```bash
python3 -m unittest discover -s app/tests -p 'test_*.py' -v
```

İsteğe bağlı JavaScript geliştirme kontrolü için Node.js 20+ kuruluysa:

```bash
node app/tests/contracts.test.mjs
```

JavaScript kontrolleri CSV doğrulaması, eksik değer, etiket sızıntısı, model çıktısı, oturum toplulaştırma ve hata durumlarını kapsar. Node.js demoyu çalıştırmak için gerekli değildir. Testler model performansını ölçmez.

## Gizlilik ve sınırlamalar

CSV tarayıcı belleğinde işlenir; sunucuya yüklenmez, diske yazılmaz ve üçüncü taraflara gönderilmez. Cookie, web storage, telemetri veya fare/klavye kaydı yoktur. Sunucu erişim logu tutmaz. Kullanıcının seçtiği kaynak dosya kendi diskinde kalır; sıfırlama fiziksel bellek silme garantisi değildir.

Bu bir üretim güvenlik sistemi değildir. Başarılı giriş sonucu, kaynak gruplaması ve cihaz yeniliğinin doğru türetilmesi müşteri IdP entegrasyonuna bağlıdır. CSV biçim kontrolü verinin gerçekten anonim/sentetik olduğunu kanıtlayamaz. Kalıcı cihaz izi, biyometri, sızdırılmış parola listeleri ve parola sızıntısı kontrolü MVP dışıdır. Sentetik çalışma sonuçları gerçek dünyada kanıtlanmış başarı olarak sunulamaz.

Lisans: [LICENSE](LICENSE).
