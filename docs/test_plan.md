# AI 4 — Bağımsız güvenlik ve doğrulama planı

Proje: **Ephemeral Login Sentinel**  
Plan tarihi: **17 Ekim 2026**  
Kapsam: Ortak brief'e karşı A1, a2 ve a3 teslimlerinin bağımsız denetimi.

Bu plan, veri satırları ve model sonuçları incelenmeden önce ortak brief üzerinden hazırlanmıştır. İlk AI 4 denetimi veri/model/dashboard üretmeden yapılmıştır. Kullanıcının daha sonraki bütün görevleri tamamlama talebiyle diğer üç rol düzeltme, üretim ve eğitimi tamamlamış; bu plan birleşik teslimde yeniden uygulanmıştır. Denetim testleri yeniden eğitim yapmaz. Sonuçlar ve kanıtlar [security_review.md](security_review.md) dosyasındadır. İşaretli kutular kontrolün yürütüldüğünü gösterir; her birinin kararı ve sınırı raporda ayrıca belirtilir.

## 1. Başarı ölçütü ve karar dili

- Oturum başına risk 0–100 aralığındadır; 100 en yüksek risktir. Puan saldırı olasılığı olarak sunulmaz.
- Yüksek risk MFA veya insan incelemesi önerir; otomatik hesap kilitleme yapılmaz.
- Kimlik, hedef etiket ve değerlendirme metaverisi model girdisinden ayrılır.
- Geçmiş veya model çıktısı yokluğu düşük risk sayılmaz. Gerçek 30 günlük geçmiş varsayılmaz.
- Sentetik sonuçlar yalnızca sentetik koşulları açıklar; gerçek dünya performansı iddia edilmez.
- Her kontrol **geçti**, **bulgu**, **doğrulanamadı** veya **uygulanamaz** olarak sınıflandırılır. Eksik çıktı başarı sayılmaz.

## 2. Altı bağımsız senaryo

Beklentiler belirli bir doğrulanmamış eşik veya uydurma model puanı içermez. Normal senaryolarda özellikle tek bir yeni bağlam sinyalinin gereksiz yüksek riske dönüşüp dönüşmediği incelenir. Şüpheli senaryolarda birden çok uyumlu sinyalin açıklanabilmesi ve uygun öneri verilmesi beklenir.

| Kimlik | Sınıf | Senaryo | Kontrol ve beklenen davranış |
| --- | --- | --- | --- |
| N1 | Normal | Kullanıcı parolasını bir veya iki kez yanlış girer, ardından olağan bağlamda başarılı olur. | Birkaç hata tek başına brute force kabul edilmemeli. Başarısızlık etiketi ile şüpheli etiketi karıştırılmamalı; açıklama gerçek mevcut sinyallere dayanmalı. |
| N2 | Normal | Yönetilen cihazda kurumsal VPN açılır; ağ/ASN ve görünen konum değişir, deneme yoğunluğu olağandır. | VPN veya yanıltıcı yüksek coğrafi hız tek başına saldırı kanıtı sayılmamalı. MFA gerekiyorsa bunun bağlam belirsizliği olduğu açıklanmalı; kilitleme olmamalı. |
| N3 | Normal | Kullanıcı seyahatte yeni bir cihazla giriş yapar; yeterli geçmiş yoktur ve deneme yoğunluğu olağandır. | Seyahat, yeni cihaz ve eksik geçmiş otomatik kötü niyete dönüşmemeli. Eksiklik sıfırla doldurulmamalı; ölçülü MFA önerisi ile kesin saldırı iddiası ayrılmalı. |
| S1 | Şüpheli | Aynı hesaba kayan 120 saniyede yoğun başarısız deneme gelir; yeni oturum anahtarları kullanılabilir. | Hesap düzeyindeki yoğunluk görünmeli; cookie yenilemek sayacı sıfırlamamalı. Yüksek riskte MFA/inceleme önerilmeli. |
| S2 | Şüpheli | Ortak kaynak bağlamı 120 saniyede çok sayıda hesaba az sayıda deneme yapar. | Hesaplar arası yayılım model öncesinde doğru hesaplanmalı. Salt oturum sayacı spraying tespiti sayılmamalı. NAT/VPN ortak kaynak yanılgısı ayrıca değerlendirilmelidir. |
| S3 | Şüpheli | Yoğun başarısızlık veya olağan dışı bağlam ardından yeni cihaz/ağ ile başarılı giriş olur. | Başarı yalnızca IdP sonucu/uygun metaveri ile doğrulanmalı; `is_suspicious` veya `attack_type` giriş başarısı veya model özelliği yapılmamalı. Bağlam gerekçesi ve MFA/inceleme önerisi görünmeli. |

## 3. Gizlilik ve veri sızıntısı kontrol listesi

### Ham hassas veri

- [x] CSV başlığı tam 17 alan mı; ek kullanıcı adı, e-posta, parola, IP, cookie içeriği, cihaz izi veya biyometri sütunu var mı?
- [x] Veri içerikleri, notebook hücreleri/çıktıları, uygulama kodu ve takip edilen dosyalarda ham kimlik, IP, parola veya sır örüntüsü var mı?
- [x] Opak anahtarlar kullanıcı adı/e-posta taşımadan üretilmiş mi; tokenlar açıkça sentetik mi? Örüntü kontrolü anonimlik kanıtı değildir.
- [x] Veri kaynağı ve üretim yolu açıklanmış mı? Sızdırılmış dosya/listelerle eşleştirme var mı?
- [x] Gerçek müşteri verisini dış API'ye, telemetriye, AI servisine veya uzaktaki depoya gönderen bir yol var mı?
- [x] Hatalar, notebook örnekleri ve loglar satır, dosya adı veya ham hassas değer yansıtıyor mu?
- [x] Cookie yalnızca geçici rastgele anahtar mı; kalıcı cihaz izi veya fare/klavye kaydı var mı?
- [x] Tarayıcı ve sunucu saklama/silme davranışı belgelenmiş ve uygulanan davranışla tutarlı mı?

### Model ve değerlendirme sızıntısı

- [x] `event_id`, `session_token`, `account_token`, `is_suspicious`, `attack_type` eğitim ve çıkarım özelliklerinden gerçekten çıkarılmış mı?
- [x] Ham zaman damgası veya saldırı sınıfını dolaylı kodlayan başka alan hedef sızıntısı yaratıyor mu?
- [x] Encoder/imputer/scaler ve özellik seçimi yalnızca eğitim verisine mi fit ediliyor?
- [x] Eğitim ve test aynı hesabı, oturumu, yinelenen olayı veya aynı saldırı zincirini paylaşıyor mu?
- [x] Rastgele satır ayrımı ile bağımsız kullanıcı/senaryo veya zaman ayrımı arasındaki fark raporlanmış mı?
- [x] Sentetik sınıflar kolay, ayrık kurallarla mı üretilmiş; normal davranış ile saldırı gerçekçi biçimde örtüşüyor mu?
- [x] Pencere özellikleri olaydan sonraki bilgiye veya etikete bakılarak türetilmiş mi?
- [x] Etiketler ve senaryo açıklamaları UI'da gerçek tahmin veya model gerekçesi gibi sunuluyor mu?

## 4. Pencere, silme ve puan sözleşmesi

- Ortak kısa pencere 2 dakika / 120 saniye olmalı. Sınırda `t−120`, pencere içi, `t`, yinelenen ve geç gelen olayların politikası belgelenmeli.
- `attempts_2m`, `attempts_1h` ve `distinct_accounts_2m` hesap/oturum/kaynak kapsamları uyumlu olmalı. Sayaçların yalnızca bağımsız rastgele değerler olması gerçek kayan pencere doğrulaması değildir.
- Kaynak anahtarı CSV'de yoksa spraying korelasyonunun müşteri içinde nasıl yapıldığı açıklanmalı.
- Cookie ömrü ile olay penceresi birbirine karıştırılmamalı. İki dakikalık korelasyon verisinin ve 1 saat/24 saat yardımcı sayaçlarının silme kuralları ayrı belirtilmeli.
- Bilinmeyen geçmiş ve model hatası görünür olmalı; puan 0'a çevrilmemeli. Kısmi puanlanan oturum tam değerlendirilmiş gibi görünmemeli.
- Puan çıktısı sonlu ve 0–100 olmalı. Eşikler, toplulaştırma ve gerekçeler belgelenmeli; otomatik kilitleme bulunmamalı.

## 5. İlk bağımsız denetimin yöntemi

1. Branch adları ve commit kimliklerini kaydet; ilgili teslimleri birbirinin üzerine yazmadan oku.
2. Bu planı oluştur. Mevcut veri/model çıktısını sonra incele.
3. CSV'yi yalnızca yerel kodla kontrol et; sohbete veya rapora ham satır, token veya hassas eşleşme koyma. Yalnızca sayım, alan adı, satır/hücre konumu ve bulgu gerekçesi raporla.
4. Notebook'u yürütmeden kod hücrelerini incele. Mevcut kaydedilmiş sonuçların gerçekten var olup olmadığını ayır. Eğitim hücrelerini çalıştırma.
5. Eğitim gerektirmeyen şema, kimlik örtüşmesi, bölme yapısı, dağılım, zaman/sayaç tutarlılığı, çıktı sözleşmesi ve mevcut A1 testlerini incele. Oluşturulmuş yeni test verisiyle metrik üretme.
6. N1–N3 ve S1–S3'ün mevcut teslimde temsil edilip edilmediğini kontrol et. Uygun etiket/çıkarım yoksa yanlış alarm veya yakalama oranı uydurma; doğrulanamadı yaz.
7. Bulguları önem derecesi, kanıt, etki ve dosya sahibine yönelik düzeltme önerisiyle raporla. Diğer AI'ların dosyalarını düzeltme veya modeli yeniden eğitme.

## 6. Öncelik ve demo geçiş ölçütleri

- **P0 / kritik:** Ham hassas veri dışarı çıkışı, gerçek parola/sır kaydı veya doğrudan yetkisiz dış işlem.
- **P1 / yüksek:** Hedef/kimlik sızıntısı, geçersiz bağımsız değerlendirme, çalışmayan temel sözleşme veya sonucu ciddi biçimde yanıltan çıktı.
- **P2 / orta:** Eksik tehdit kapsamı, yanlış alarmın değerlendirilememesi, pencere/silme/eksik değer tutarsızlığı.
- **P3 / düşük:** Belge, sunum veya izlenebilirlik eksikliği.

Demo, mock ve gerçek model sonucunu açıkça ayırmalı; mevcut olmayan modele/metriğe atıf yapmamalı. Hassas veri sızıntısı veya etiketten tahmin üretilmesi varsa gerçek veri/model demosu geçmez. Sadece mock gösterim, sınırlamaları açıkça ifade ederek ayrıca değerlendirilebilir. Rapor; tespit edilen durumları, kontrol edilemeyen alanları ve gerekli sonraki teslimleri birbirinden ayırır.

## 7. Birleşik teslimde yürütme kaydı

17 Ekim 2026 tarihinde ilk bulguların düzeltmeleri yeniden denetlendi. `integration/full-mvp` çalışma ağacında 12 veri, 22 model, 3 entegrasyon ve 11 HTTP olmak üzere **48 Python testi geçti**. Entegrasyon içinden 17 JavaScript sözleşme, 10 model/ömür ve 12 DOM kontrolü çalıştı. Gerçek teslimin 10.000 satırında Python–JavaScript puan/gerekçe eşliği doğrulandı.

N1–N3 ile S1–S3 mevcut sentetik veri ve manifestte temsil ediliyor. Alt grup yanlış alarmları ve çekimserlik ölçüldü; seyahat/VPN yanlış alarmları hâlâ açık bir üretim sınırlamasıdır. Altı gerçek sentetik demo oturumu ve beklenen sonuçlar güvenlik raporunda verilmiştir.

Kontrol listesinde ham hassas veri sızıntısı bulunmadı; gerçek müşteri kökeni üzerinde doğrulama yapılmadı. IdP/cookie/üretim TTL servisi bulunmadığından bunlara ilişkin uçtan uca test uygulanamaz. Yerel demo bellek süresi, reset, sayfadan ayrılma ve askı sonrası süre denetimi test edildi.

Canlı loopback HTTP smoke geçti. Gerçek tarayıcı yüzeyi bu ortamda erişilebilir olmadığı için görsel/erişilebilirlik QA **doğrulanamadı**; DOM testi bu kontrolün yerine sayılmaz. Uzak CI tanımlandı, çalıştırılmış gibi sunulmadı. İlk inceleme ile yeni durum birbirine karışmasın diye ilk güvenlik raporu `docs/reviews/` altında korundu.
