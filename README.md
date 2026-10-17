# Ephemeral Login Sentinel

Giriş olaylarından **oturum başına 0–100 risk puanı** üreten, yerelde çalışan bir MVP. **100 en yüksek risktir.** Yüksek risk MFA veya insan incelemesi önerir; otomatik hesap kilitleme ve gerçek MFA tetikleme yoktur.

Bu entegrasyon AI 1–4 teslimlerini bir araya getirir: mimari/demo, 10.000 olaylık sentetik veri, çalışan eğitim/değerlendirme komutları, dört model karşılaştırması ve güvenlik testleri. Hazır demo modeli sentetik veriden gerçekten eğitilmiştir. Sonuçlar gerçek müşteri performansı veya kalibre saldırı olasılığı değildir.

## Hızlı demo

**Python 3.10+ yeterlidir.** Demo için paket kurulumu, API anahtarı, Node.js veya internet bağlantısı gerekmez; eğitilmiş model JSON'u depoda bulunur.

```bash
python3 app/serve.py
```

Tarayıcıda **http://127.0.0.1:8000** adresini açın. Port doluysa `python3 app/serve.py --port 8001` kullanın. Windows'ta `py -3 app/serve.py` kullanılabilir. Durdurmak için `Ctrl+C`.

1. Açılıştaki dört kart **MOCK** arayüz örnekleridir. Ekrandaki yerel model durumunu kontrol edin.
2. **CSV içe aktar** ile `data/mvp_synthetic_logins.csv` dosyasını seçin.
3. Gerçek eğitilmiş model bu CSV'yi tarayıcı içinde puanlar; olaylar 4.036 oturumda gruplanır. Model sürümü, risk nedenleri ve önerilen aksiyon görünür.
4. Filtre, arama ve 50 satırlık sayfalama ile oturumları inceleyin. Herhangi bir olayı eksik/tanınmayan özellik yüzünden puanlanamayan oturum **puan bekliyor** kalır; düşük risk sayılmaz.
5. Bellekte tutma süresini 5/10/15 dakika seçin. **Mock görünüm** sıfırlaması veya süre dolması içe aktarımın uygulama referanslarını bırakır. Kaynak CSV diskten silinmez.

CSV **sunucuya yüklenmez**. Tarayıcı yalnızca aynı yerel sunucudan model JSON'unu alır. Sunucu depo/veri/manifest/model pickle dosyalarını paylaşmaz; sadece izinli web varlıkları ve doğrulanmış model JSON'u sunulur.

## Eğitim ve değerlendirmeyi tekrar çalıştırma

Tam geliştirme ortamı için **Python 3.13** kullanıldı. Proje kökünde:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-optional.txt
```

Windows etkinleştirme komutu `.venv\Scripts\activate` olur. `requirements-optional.txt` XGBoost içindir; kurulu değilse karşılaştırma bunu açıkça atlar. Üç temel yaklaşım kural referansı, Logistic Regression ve Random Forest'tır. Bu teslimde XGBoost da kurularak değerlendirilmiştir. SHAP zorunlu değildir; demo lojistik özellik katkılarını açıklar.

Veri zaten depodadır. Aynı sentetik teslimi yeniden üretmek isterseniz:

```bash
python src/data/generate_synthetic.py --rows 10000 --seed 42 --attack-rate 0.08
```

Bu komut CSV ve denetim manifestini birlikte yazar. Gerçek kimlik, parola, IP, kesin konum veya dış veri kullanmaz. Başka seed/oran kullanırsanız model ve sonuçlar eski veriyle eşleşmez; eğitimi ve değerlendirmeyi yeniden çalıştırın.

```bash
python -m src.models.train
python -m src.models.evaluate
```

Eğitim CSV/manifest yoksa, hash uyuşmuyorsa veya bölmeler sızıntı içeriyorsa başlamaz. Ayrımlar **6.000 fit / 2.000 validation / 2.000 test** şeklindedir; hesap, oturum, kaynak ve episode ortaklığı yoktur, zaman aralıkları ayrıdır. Ön işleme yalnız fit bölümünden öğrenilir; eşik yalnız validation bölümünden seçilir. `evaluate` kaydedilmiş karşılaştırma modellerini yeniden eğitim yapmadan değerlendirir.

Demo modeli **Logistic Regression**: küçük ve denetlenebilir JSON olarak tarayıcıda çalışabildiği için seçildi. RF/XGBoost daha iyi sentetik metrik verdiğinde bu raporda gizlenmez; demo modeli test sonuçlarına göre seçilmiş değildir. 30/70 arayüz politikası, validation'da seçilen değerlendirme eşiğinden ayrıdır.

## Sonuçlar ve sınırlamalar

[Model sonuçları](docs/model_results.md) PR-AUC/AP, ROC-AUC, precision, recall, confusion matrix, yanlış alarm, alt grup ve puanlama kapsamını içerir. [Güvenlik incelemesi](docs/security_review.md) kapatılan hataları ve kalan sınırları açıklar.

Eksik geçmişi olan olaylar puanlanmaz. Özellikle normal seyahat/yeni cihaz ve VPN bağlamlarında yanlış alarmlar hâlâ vardır. Sentetik başarı gerçek dünya etkinliği anlamına gelmez. Gerçek IdP entegrasyonu, üretim kimlik doğrulama/TTL servisi ve müşteri verisi üzerinde doğrulama bu yerel prototipin kapsamı dışındadır.

## Sabit CSV sözleşmesi

```csv
event_id,event_ts_utc,session_token,account_token,attempts_2m,attempts_1h,distinct_accounts_2m,failed_ratio_24h,hour_deviation,typical_weekday,geo_velocity_kmh,network_familiarity,asn_category,device_managed,device_new,is_suspicious,attack_type
```

17 alan ve sıraları değişmez. UTF-8, virgül ayırıcı, BOM ve CRLF desteklenir; demo sınırı 2 MiB / 10.000 olaydır. `network_familiarity` **familiar/unfamiliar** kategorisidir. Boolean alanlar 0/1, saat sapması 0–12 saat, başarısızlık oranı 0–1'dir. Boş özellik bilinmiyor olarak korunur.

Model yalnızca 11 özellik alır. Kimlikler, ham olay zamanı, hedef etiket, saldırı metaverisi ve manifest alanları modele girmez. Manifest, CSV şemasını değiştirmeden sentetik başarı sonucu ve bölme/episode denetimini sağlar. Ayrıntılar [mimaride](docs/architecture.md) ve [veri sözlüğünde](docs/synthetic_data.md).

## Testler

Python geliştirme ortamı etkin durumdayken:

```bash
python -m unittest discover -s tests -v
python -m unittest discover -s app/tests -p 'test_*.py' -v
```

Tam JavaScript/DOM kontrolleri için Node.js 24 ve pnpm 12.14.0:

```bash
npm install --global pnpm@12.14.0
pnpm --dir app install --frozen-lockfile
pnpm --dir app test
```

Node PATH'te değilse Python entegrasyon testleri JavaScript kısmını açıkça atlayabilir; tam kontrol için Node'u PATH'e ekleyin. LinkeDOM yalnız geliştirme/test bağımlılığıdır; gerçek tarayıcıdaki görsel kontrolün yerine geçmez. CI aynı Python ve JavaScript kontrollerini çalıştıracak şekilde tanımlıdır; bu teslimde uzak CI çalışması başlatılmamıştır.

## Teslim haritası

| Bölüm | Dosyalar |
| --- | --- |
| Ürün ve mimari | `docs/project_brief.md`, `docs/architecture.md`, `docs/retention_policy.md` |
| Demo | `app/` — yerel çıkarım, CSV okuyucusu, oturum görünümü, ömür kontrolü |
| Veri | `src/data/generate_synthetic.py`, `data/mvp_synthetic_logins.csv`, aynı dosyanın `.manifest.json` yan dosyası |
| Veri belgeleri | `docs/synthetic_data.md`, `docs/data_source_audit.md` |
| Modelleme | `src/models/train.py`, `src/models/evaluate.py`, `src/models/core.py`, yönlendirici notebook |
| Model artefaktları | `models/demo_model.json`, `models/comparison_models.joblib` |
| Değerlendirme | `docs/model_results.md`, `outputs/evaluation.json`, sentetik tahmin/parite dosyaları ve PR grafiği |
| Güvenlik | `docs/test_plan.md`, `docs/security_review.md`, `docs/reviews/` ilk denetim kaydı |
| Tekrar çalıştırma | `requirements*.txt`, `app/pnpm-lock.yaml`, `.github/workflows/tests.yml` |

## Gizlilik

Gerçek kullanıcı kayıtlarını, ham parolaları, ham IP'leri ve sızdırılmış dosyaları AI sohbetine yüklemeyin. Kalıcı cihaz izi, fare/klavye biyometrisi, parola sızıntısı kontrolü ve sızdırılmış listelerle eşleştirme yoktur. Kullanıcı adı yerine gerektiğinde müşteri ortamında opak hesap anahtarı kullanılmalıdır.

Demo cookie veya web storage oluşturmaz; erişim logu tutmaz. 120 saniyelik analiz penceresi ile dosyanın bellekte tutulma süresi farklıdır. Süre sonunda referans bırakma, fiziksel bellek silme garantisi değildir. Ayrıntılı uygulanan sınır: [veri yaşam döngüsü](docs/retention_policy.md).

Lisans: [LICENSE](LICENSE).
