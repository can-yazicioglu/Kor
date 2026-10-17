# Ephemeral Login Sentinel — proje brief'i

## Problem ve amaç

Kısa sürede tek hesaba yoğunlaşan denemeler, çok hesaba yayılan denemeler ve alışılmadık bağlamdan başarılı giriş, tek olaydan anlaşılmayabilir. Amaç; ham parola, gerçek kullanıcı adı, ham IP veya kalıcı cihaz izi saklamadan giriş bağlamından **oturum başına 0–100 risk puanı** üreten yerel bir prototip geliştirmektir. **100 en yüksek risktir.**

Yüksek risk MFA veya insan incelemesi önerir. Puan kimlik doğrulama kararı, saldırı olasılığı veya güvenlik garantisi değildir. Otomatik hesap kilitleme uygulanmaz.

## MVP kapsamı

| Senaryo | Yaklaşım |
| --- | --- |
| Brute force | Aynı hesapta kayan 120 saniyelik deneme yoğunluğu ve önceki başarısızlık bağlamı |
| Password spraying | Geçici ortak kaynakta kayan 120 saniyede farklı hesap sayısı |
| Şüpheli başarılı giriş | Yeni cihaz/ağ ile zaman ve diğer bağlamların birlikte değerlendirilmesi; başarı bilgisi sentetik denetim manifestinde doğrulanır |

Normal yanlış parola, VPN, seyahat/yeni cihaz, gece çalışma ve eksik geçmiş karşı örnekleri de bulunur. CSV başarı sonucunu taşımadığı için gerçek IdP başarısı CSV'den tek başına kanıtlanamaz.

## Tamamlanan dört iş kolu

1. **AI 1 — mimari/demo:** Türkçe duyarlı ekran, açık mock modu, gerçek yerel model çıkarımı, CSV doğrulama, oturum risk/gerekçe/aksiyonları, arama/filtre/sayfalama ve bellek yaşam döngüsü.
2. **AI 2 — veri:** Seed/oranı ayarlanabilir sentetik üretici, 10.000 olaylık teslim, kaynak/episode/başarı/bölme denetim manifesti, nedensel sayaçlar, veri sözlüğü ve açık kaynak araştırma raporu.
3. **AI 3 — model:** Çalışan eğitim/değerlendirme CLI'ları; kural, Logistic Regression, Random Forest ve kurulu XGBoost karşılaştırması; açık özellik listesi; kullanıcı/zaman/episode ayrımı; taşınabilir demo modeli ve sonuç raporu.
4. **AI 4 — güvenlik:** Üç normal/üç şüpheli temel senaryo, gizlilik/sızıntı kontrolleri, çapraz bileşen testleri, ilk bulguların kapanış denetimi ve kalan sınırlamalar.

Başlangıçta ayrı branch teslimleri incelendi. Kullanıcının tüm eksikleri tamamlama talebiyle `integration/full-mvp` üzerinde ortak entegrasyon yapıldı; ilk denetim tarihsel olarak korundu. Bu aşamada yalnız tek AI'ın dosyalarıyla sınırlı çalışma yerine tüm bileşenlerin uyumu tamamlanmıştır.

## Gizlilik sınırları

- Müşteri giriş verileri müşteri ortamından çıkmaz. Demo CSV'yi tarayıcı belleğinde işler; yalnızca model JSON'u yerel sunucudan alınır.
- Gerçek kullanıcı kaydı, parola, IP veya sızdırılmış dosya AI sohbetine verilmez. Üretici dış müşteri veri kaynağı okumaz.
- Model 11 özellik alır; kimlikler, ham zaman, hedef etiket, saldırı metaverisi ve manifest alanları model girdisi değildir.
- Demo cookie kullanmaz. Canlı entegrasyonda cookie yalnız rastgele kısa ömürlü anahtar olabilir; kalıcı cihaz izi veya hareket/klavye biyometrisi oluşturulamaz.
- Gerçek 30 günlük geçmiş varsayılmaz. Sentetik profil açıkça simülasyondur; eksik özellik puansız kalır ve sıfır risk sayılmaz.
- Sentetik CSV/model/raporlar geliştirme artefaktlarıdır. Gerçek müşteri çıktısı bu depoya eklenmez.

## Kapsam dışı

Gerçek IdP ve MFA çağrıları, otomatik kilitleme, canlı üretim TTL/kimlik doğrulama servisi, kalıcı cihaz parmak izi, biyometri, parola sızıntısı kontrolü, sızdırılmış listeler ve üretim etkinliği iddiaları kapsam dışıdır. Yeni müşteri ortamına dağıtım ve gerçek veriyle doğrulama bu yerel MVP'nin tamamlanmasıyla otomatik olarak yapılmış sayılmaz.

## Kabul ölçütleri

- Sabit 17 sütun korunur; teslim edilmiş CSV demo tarafından okunur.
- Model gerçek sentetik teslim geldikten sonra eğitilir; mock sonuçlar eğitim metriği yapılmaz.
- Risk 0–100, gerekçeler modele verilen özelliklerle ilişkili, aksiyon MFA/incelemedir.
- Model dosyası yok/bozuk veya özellik eksikse puan üretilmez. Oturumun herhangi bir olayı puansızsa oturum tam değerlendirilmiş görünmez.
- Eğitim/validation/test arasında hesap, oturum, episode ve kaynak ortaklığı yoktur; zaman sırası ve pencere boşluğu denetlenir.
- Yanlış alarm ve çekimserlik açıkça raporlanır. Sentetik sonuçlar gerçek dünya başarısı olarak sunulmaz.
- Belgelenmiş kurulum, tekrar çalıştırma ve test komutları vardır. Test kapsamı ile doğrulanamayan üretim/görsel sınırlar ayrılır.

Güncel kanıtlar [güvenlik incelemesinde](security_review.md), model sonuçları [değerlendirme raporunda](model_results.md) bulunur.
