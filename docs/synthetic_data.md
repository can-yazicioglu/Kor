# Sentetik giriş verisi — sürüm 2

`data/mvp_synthetic_logins.csv` ve `data/mvp_synthetic_logins.manifest.json` tamamen sentetik test dosyalarıdır. Gerçek müşteri kaydı, kullanıcı adı, parola, IP, kesin konum, cihaz parmak izi veya sızdırılmış liste kullanılmaz. Üretici dış kaynağa bağlanmaz. Bu veriden çıkan ölçümler gerçek dünya güvenlik başarısı veya kalibre edilmiş hesap ele geçirilme olasılığı değildir.

## Tekrar üretme

Depo kökünden:

```bash
python3 src/data/generate_synthetic.py \
  --rows 10000 --seed 42 --attack-rate 0.08 \
  --start-utc 2025-01-01T00:00:00Z \
  --output data/mvp_synthetic_logins.csv

python3 -m unittest discover -s tests -p 'test_data.py' -v
```

Üretici yalnızca Python standart kütüphanesine ihtiyaç duyar. Parametreler varsayılan değerlerle yukarıdaki gibidir; `--manifest-output` yan dosyanın konumunu değiştirebilir. Satır sayısı pozitif, saldırı oranı `[0,1]`, başlangıç zamanı saat dilimli olmalıdır. Etiketli saldırı sayısı `round(rows * attack_rate)` olarak belirlenir. Çok küçük dosyalar bütün senaryoları veya eğitim için yeterli iki sınıfı içeremeyebilir; üretilebilmeleri eğitime uygun olduklarını göstermez.

Teslim edilen 10.000 satırlık dosyanın SHA-256 değeri:

```text
41383a34524cefb434a66608c74a6554bada4377968298c6d7b7a43e4168b625
```

Aynı parametreler aynı CSV ve manifesti üretir. Seed'li token üretimi yalnızca sentetik test içindir; gerçek oturum çerezi üretmek için kullanılamaz. CSV değişirse manifest yeniden üretilmeli ve model yeniden doğrulanmalıdır; manifest CSV özetini `csv_sha256` alanında taşır.

## Veri sözleşmesi

Ortak **17 sütun ve sırası değiştirilmedi**:

```text
event_id,event_ts_utc,session_token,account_token,attempts_2m,attempts_1h,distinct_accounts_2m,failed_ratio_24h,hour_deviation,typical_weekday,geo_velocity_kmh,network_familiarity,asn_category,device_managed,device_new,is_suspicious,attack_type
```

Model girdileri yalnızca `attempts_2m` ile `device_new` arasındaki 11 özellik olabilir. Olay zamanı bölme ve sıralama içindir; kimlikler gruplama/eşleme içindir; `is_suspicious` hedeftir; `attack_type` değerlendirme metaverisidir. Bunların hiçbiri özellik matrisi veya risk gerekçesi üretmek için kullanılmamalıdır.

| Alan | Tür ve anlam |
| --- | --- |
| `attempts_2m` | Aynı hesaba ait, `(t−120 saniye, t]` içindeki görülmüş giriş denemesi sayısı; mevcut olay dâhil. Oturum/cookie değişse de hesap sayacı sürer. |
| `attempts_1h` | Aynı hesabın `(t−3600 saniye, t]` deneme sayısı; her zaman `attempts_2m` kadar veya daha büyük. |
| `distinct_accounts_2m` | Aynı **geçici kaynak anahtarı** üzerinden `(t−120 saniye, t]` içinde denenmiş ayrı hesap sayısı. Tek hesabın oturum sayısı değildir. |
| `failed_ratio_24h` | Mevcut sonuç hariç, daha önce bilinen sentetik sonuçların son 24 saatteki başarısızlık oranı `[0,1]`. Önceki sonuç yoksa boş. |
| `hour_deviation` | Sentetik tercih edilen saatten en kısa çembersel saat uzaklığı `[0,12]`; profil bilinmiyorsa boş. |
| `typical_weekday` | Sentetik olağan gün listesiyle eşleşme `0/1`; profil bilinmiyorsa boş. |
| `geo_velocity_kmh` | Koordinat üretmeden örneklenen sentetik bağlam; negatif olamaz, eksik olabilir. VPN kaynaklı büyük sıçrama fiziksel seyahat kanıtı değildir. |
| `network_familiarity` | `familiar` / `unfamiliar`; bilinmiyorsa boş. Sayısal 0–1 kodlama kullanılmaz. |
| `asn_category` | `residential`, `business`, `cloud`, `vpn`, `unknown`. `unknown` geçerli kategoridir; ASN numarası değildir. |
| `device_managed`, `device_new` | `0/1` veya boş; kalıcı cihaz kimliği içermez. |

Boş hücre **bilinmiyor** demektir; sıfıra veya “güvenli” sonucuna çevrilmez. Sabit şemaya eksik-değer sütunu eklenmez. Eksik özellik içeren 1.845 olay vardır; 8.155 olayda 11 özellik tamamdır. Tüketici bunları kapsam/çekimserlik hesabında göstermelidir.

Tüm hesap ve kaynak sayaçları sıralanmış **olaylardan gerçekten hesaplanır**. Önceki sürümün bağımsız örneklenen sayaçları kaldırılmıştır; gelecek olayların sayısı önceki satıra yazılmaz. Aynı zaman damgasındaki olaylarda CSV sırası nedensel alınış sırasıdır: henüz işlenmemiş eşzamanlı olay görünmez. `(t−120,t]` ifadesindeki sol sınır açıktır; tam 120 saniye önceki olay artık sayılmaz.

## Senaryolar ve zorlu normal kontroller

| `attack_type` | Satır | Hedef | Senaryo |
| --- | ---: | ---: | --- |
| `normal` | 3.955 | 0 | Olağan girişler, bazı meşru bağlam sapmaları. |
| `user_error` | 1.840 | 0 | Bir oturumda birkaç yanlış parola, sonrasında başarı; parola değeri hiç üretilmez. |
| `vpn_new_device` | 1.196 | 0 | VPN/yeni cihaz ve aynı geçici kaynaktan birden çok meşru hesap; yüksek sentetik konum sıçraması olabilir. |
| `travel_new_device` | 1.013 | 0 | Seyahat/yeni cihaz, tanıdık olmayan ağ ve yüksek konum/saat sapması birlikte görülebilir. |
| `night_shift` | 736 | 0 | Meşru gece çalışması; tek başına saat sapması saldırı değildir. |
| `cold_start` | 460 | 0 | Önceki kullanıcı profili yok; bağlam alanları açıkça eksik. |
| `brute_force` | 320 | 1 | Kısa sürede tek hesaba artan denemeler; bazı cookie yenilemeleri içerir. |
| `password_spraying` | 240 | 1 | Geçici ortak kaynaktan çok sayıda hesaba deneme. |
| `suspicious_success` | 240 | 1 | Yeni/olağan dışı bağlamla başarılı giriş; başarı yan dosyada bağımsız olarak doğrulanabilir. |

Bunlar satır sayılarıdır; saldırı episode'u veya oturum sayısı değildir. Toplam **4.036 oturum**, **573 hesap** vardır; birçok oturum birden fazla olay içerir. Her bölümde bütün senaryolar ve soğuk başlangıç dışındaki senaryoların tam özellikli örnekleri bulunur. Yüksek hız, yeni cihaz, VPN, gece ve düşük/yüksek başarısızlık oranları iki sınıfta da örtüşür. Ayrıca iki sınıfta yaklaşık %3 episode düzeyinde bağlam kaybı simüle edilir. Yine de kurallarla oluşturulmuş sentetik dağılımın kolay öğrenilmesi gerçek saldırı genellemesi değildir.

## Manifest ve sızıntısız bölme

Yan dosya ortak CSV şemasına ek sütun getirmez. Modelin gördüğü 11 özelliğe **asla birleştirilmez**. Yapısı:

```json
{
  "schema_version": 2,
  "synthetic": true,
  "csv_sha256": "<CSV SHA-256>",
  "split_order": ["fit", "validation", "test"],
  "events": {
    "evt_00000001": {
      "split": "fit",
      "scenario": "normal",
      "episode_id": "<sentetik episode anahtarı>",
      "source_token": "<sentetik geçici kaynak anahtarı>",
      "auth_success": true
    }
  },
  "warmup_events": [],
  "profiles": {},
  "semantics": {}
}
```

`events` bütün CSV olaylarını bire bir kapsar. `auth_success`, bağımsız senaryo doğrulaması ve önceki başarısızlık oranının denetimi içindir. Sabit CSV'nin başarı sütunu olmaması böylece değerlendirmede giderilir; model bu sonuca erişemez. `source_token`, spraying kapsamının denetlenmesini sağlar; ham IP veya kalıcı ağ/cihaz kimliği değildir.

| Bölüm | Olay | Gerçekleşen UTC aralığı | Tam özellikli olay |
| --- | ---: | --- | ---: |
| `fit` | 6.000 | 1 Ocak 2025 00:06:27 – 8 Ocak 2025 23:55:27 | 4.899 |
| `validation` | 2.000 | 11 Ocak 2025 00:13:35 – 18 Ocak 2025 22:26:25 | 1.625 |
| `test` | 2.000 | 21 Ocak 2025 00:13:17 – 28 Ocak 2025 23:54:11 | 1.631 |

Hesap, episode, oturum ve kaynak kümeleri bölümler arasında ayrı; zaman aralıkları sıralı ve aralarında iki dakikadan uzun boşluk vardır. Aynı saldırı episode'unun satırları iki bölüme dağılmaz. Rastgele satır bölmesi kullanılmaz. **Aynı senaryo türünün** her bölümde bulunması amaçlıdır; bu değerlendirme hiç görülmemiş saldırı türünü genelleme testi değildir. Eşik/hiperparametre yalnızca `fit` ve `validation` ile seçilmeli; `test` seçim için kullanılmamalıdır.

## Geçmiş, iki dakika ve silme sınırı

`profiles`, tercih edilen saat/gün parametrelerini **30 günlük geçmiş simülasyonu** olarak tanımlar. Gerçek bir hesaptan 30 gün veri görülmüş olduğu iddia edilmez; 30 günlük ham iz üretilmez. Profilin simülasyon kesim zamanı kendi bölümünün başlangıcından öncedir. `cold_start` profillerinde `history_days=0` bulunur.

`warmup_events`, bölüm başlamadan önceki 24 saatten 3.129 **sentetik** sonuç kaydı içerir. Bunlar yalnızca geçmiş başarısızlık oranının tekrar hesaplanmasını sağlar; bölüm başlangıcından en az 3.601 saniye önce oldukları için bir saatlik deneme penceresini etkilemez. Sonraki oranlar bilinen warmup sonuçları ve daha önceki CSV olaylarından hesaplanır; gelecek veya mevcut sonuç kullanılmaz. Bir hesapta son 24 saat içinde bilinen sonuç yoksa oran boştur.

Bir episode'un geçici kaynak anahtarı ve bir oturum anahtarı **120 saniyeden kısa** gözlem aralığında kullanılır. Gerçek sistemde kaynak korelasyonu müşteri ortamında geçici anahtarla sağlanmalı; kaynak eşlemesi ve iki dakikalık olay tamponu 120 saniye sonunda atılmalıdır. Bir saatlik ve 24 saatlik özellikler ayrı süreli özetler gerektirir; “bütün veri iki dakikada silinir” iddiası bu şemayla doğru değildir. Müşteri ortamındaki silme süresi açıkça tür bazında belirtilmelidir.

CSV ve manifest, kasıtlı olarak diskte tutulan **sentetik test fixture'larıdır**. Bu üretici canlı cookie/IdP sunucusu değildir; gerçek cookie güvenliği, bellekten fiziksel silme veya üretim yaşam döngüsü uyguladığı iddia edilmez. Sentetik fixture'lar ihtiyaç bitince CSV ve manifest birlikte silinerek kaldırılır; gerçek müşteri verisi bu fixture klasörüne veya AI sohbetine konulmamalıdır.

## Bağımsız veri kontrolleri

`tests/test_data.py`, sabit şema/sayıları, seed tekrarlanabilirliğini, aralıkları, senaryo desteğini, eksik bağlamı, 128 bit sentetik anahtar biçimlerini, çok olaylı oturumları, geçici kaynak/oturum ömürlerini ve dosya hash bağını kontrol eder. Kayan sayaçlar ve geçmiş başarısızlık oranı üreticinin kuyruk kodunu kullanmadan yeniden hesaplanır. Bölümler arasında hesap/episode/kaynak/oturum kesişimi ve zaman örtüşmesi aranır. Şüpheli başarılı girişlerin gerçek yan-dosya sonucu `true` olmalıdır.

Veri araştırması ve üçüncü taraf kaynakların neden alınmadığı [veri kaynağı denetiminde](data_source_audit.md) açıklanmıştır. Bu dosyaların hiçbiri dış veri setlerinden alınan kayıt içermez.
