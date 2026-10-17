# Sentetik giriş verisi

`data/mvp_synthetic_logins.csv`, MVP için tamamen sentetik bir olay örneklemidir. Gerçek müşteri kaydı, kullanıcı adı, parola, IP adresi, kesin konum, tarayıcı parmak izi veya sızdırılmış parola listesi kullanılmamıştır. Açık veri kaynakları incelenmiş, ancak hiçbir veri bu CSV'ye indirilmemiş veya eklenmemiştir.

## Üretim

Üretici Python standart kütüphanesiyle çalışır:

```bash
python src/data/generate_synthetic.py \
  --rows 10000 \
  --seed 20261017 \
  --attack-rate 0.08 \
  --output data/mvp_synthetic_logins.csv
```

Varsayılanlar 10.000 satır, seed `42`, `attack-rate` `0.08` ve `2025-01-01T00:00:00Z` başlangıçlı sentetik 30 günlük dönemdir. `--attack-rate`, `is_suspicious=1` hedef etiketli satırların tüm satırlara oranını belirler. Seed aynı parametrelerle tekrar üretilebilir sonuç verir. Başlangıç zamanı saat dilimi içeren ISO-8601 UTC değeri olmalıdır. Girdi sayısı en az 1, saldırı oranı 0 ile 1 arasında olmalıdır.

Üretilmiş örnekte 10.000 satırın 800'ü (%8) şüpheli etiketlidir. Senaryo dağılımı:

| `attack_type` | Satır | `is_suspicious` |
| --- | ---: | ---: |
| `normal` | 6.573 | 0 |
| `user_error` | 1.495 | 0 |
| `vpn_new_device` | 1.132 | 0 |
| `brute_force` | 320 | 1 |
| `password_spraying` | 240 | 1 |
| `suspicious_success` | 240 | 1 |

Bu oranlar üretici ayarlarıdır; gerçek saldırı sıklığı tahmini veya gerçek dünyada ölçülmüş başarı değildir.

## Senaryolar ve özelliklerin anlamı

- **Normal giriş:** Bir hesaba düşük giriş denemesi sayısı; sentetik olağan saat ve hafta içi profili.
- **Kullanıcı hatası:** Aynı hesapta kısa aralıkta birkaç ek deneme ve orta seviyede sentetik 24 saatlik başarısızlık oranı; pozitif saldırı etiketi verilmez.
- **VPN/yeni cihaz:** Tanıdık olmayan ağ, sentetik VPN/bulut ASN kategorisi veya yeni cihaz. Bu senaryo tek başına şüpheli sayılmaz; olağan dışı bağlamla birleşmeden yeniliğin otomatik suçlama olmadığını göstermek için negatif örnektir.
- **Brute force:** Kısa bir aralıkta aynı sentetik hesaba çok sayıda deneme; `attempts_2m` ve `attempts_1h` yüksek, `distinct_accounts_2m` düşük tutulur.
- **Password spraying:** İki dakikalık sentetik bir kümede birden çok sentetik hesaba az sayıda deneme; `distinct_accounts_2m` yüksek tutulur.
- **Şüpheli başarılı giriş:** Sentetik yeni cihaz/ağ, belirgin saat/hafta günü sapması ve yüksek sentetik ağ-hız değeriyle temsil edilir. Sabit şemada girişin başarılı olup olmadığını belirten ayrı bir sütun bulunmadığından `suspicious_success` değeri yalnızca `attack_type` değerlendirme metaverisinde yer alır; model özelliği olarak kullanılmamalıdır.

`event_id`, `session_token` ve `account_token` sentetik tanımlayıcı/gruplama değerleridir; model girdisi değildir. Her olay için bir sentetik oturum token'ı oluşturulur. CSV'deki token'lar örnek üretimini tekrarlanabilir kılmak için seed'e bağlıdır; gerçek oturum çerezi olarak kullanılmamalıdır. Gerçek sistemde oturum anahtarı rastgele ve kısa ömürlü olmalı, hareket/biyometri kaydetmemelidir.

`is_suspicious` hedef etikettir; `attack_type` değerlendirme metaverisidir ve model girdisi değildir. `typical_weekday`, `device_managed`, `device_new` ve `is_suspicious` sütunları `0/1` olarak yazılır. `event_ts_utc` zaman damgası UTC ISO-8601 biçimindedir.

`attempts_2m` iki dakikalık kayan pencere varsayımını; `attempts_1h`, `distinct_accounts_2m` ve `failed_ratio_24h` sentetik özet değerleri temsil eder. 30 günlük profil, tercih edilen saat/hafta günlerinden özellik üretmek için sentetik olarak simüle edilir; CSV'de her hesaba ait 30 günlük gerçek olay geçmişi yoktur. `failed_ratio_24h` gerçek önceki satırlardan hesaplanmaz. `geo_velocity_kmh` konum üretmeden örneklenen sentetik bir sayıdır; coğrafi koordinat veya gerçek seyahat bilgisi içermez. `asn_category` yalnızca genel sınıf etiketidir; ASN numarası yoktur.

## Sınırlamalar

- Bu CSV ile elde edilecek sonuçlar gerçek dünya başarısı, güvenlik etkinliği veya üretim modeli kalitesi kanıtı sayılamaz.
- Sınıf oranı ve senaryo özellikleri elle belirlenen üretici parametreleridir; oran ve örüntüler sentetik oldukları için model ölçümleri aldatıcı derecede kolay olabilir.
- Sabit şema başarılı/başarısız giriş sonucunu taşımıyor. Şüpheli başarılı giriş senaryosunun bağımsız bir sonuç alanı yoktur; bu sınırlama veri tüketicilerine açıkça bildirilmelidir.
- Kullanıcılar arası tekrar eden `account_token` değerleri yalnızca sentetik örnek içinde gruplama yapar. Gerçek kimlik veya kalıcı cihaz parmak izi değildir.
- Yüksek risk sonucu gerçek sistemde otomatik kilitleme anlamına gelmemeli; MFA veya inceleme önerisi olarak ele alınmalıdır.
