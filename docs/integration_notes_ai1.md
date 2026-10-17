# AI 1 — Entegrasyon kararları ve açık noktalar

Bu dosya ortak şemayı **değiştirmeyen ayrı rapordur**. Aşağıdaki maddeler AI 2/AI 3 ile uyum için hazırlanmıştır. Ortak şemaya alan eklenmemiştir; diğer AI'ların dosyalarına müdahale edilmemiştir.

| Konu | AI 1'de geçici yaklaşım | Sonraki teslimde netleştirilecek |
| --- | --- | --- |
| Pencere | `(t−120 sn, t]`, mevcut olay dâhil | AI 2 aynı sayaç anlamını belgelemeli; gecikme/tekilleştirme politikası ayrı olmalı. |
| Deneme kapsamı | `attempts_2m/1h` hesap bazında | Kaynak/hesap/oturum kapsamı eğitimde ve çıkarımda aynı olmalı. |
| Spraying | `distinct_accounts_2m` ortak geçici kaynak bağlamında | CSV'de kaynak anahtarı yok; model öncesi müşteri içi hesaplama gerekir. Oturum token'ı tek başına yeterli değil. Dağıtık saldırı kapsaması sınırlı. |
| Başarılı giriş | Mock kartta yalnızca senaryo anlatımı | Şemada `auth_result` yok. `is_suspicious` ve `attack_type` özellik yapılmadan, başarılı olayın IdP seviyesinde nasıl seçileceği belgelenmeli. CSV'den başarı kanıtı çıkarılmayacak. |
| `network_familiarity` | 0–1, 1 tanıdık | AI 2'nin kategori veya sayı kodlaması uyumlandırılmalı; otomatik tahmin edilmez. |
| `hour_deviation` | Negatif olmayan sayıyı kabul et | Birim saat mi, normalize değer mi? Çevrimsel saat uzaklığı seçilirse 0–12 sınırı ayrıca kesinleştirilmeli. |
| `typical_weekday` | Boolean, 1 olağan | Haftanın günü numarası olarak kullanılmamalı; AI 2 tanımı doğrulamalı. |
| `asn_category` | Kısa metin; sözlük zorlanmıyor | Eğitim sözlüğü, bilinmeyen kategori, imputation ve encoder AI 3 tarafından belgelenmeli. |
| Eksik geçmiş | Boş değer → `null` | Modelin desteklemediği eksik özellikler null sonuç vermeli. Boşluklar 0'a çevrilmemeli. |
| `device_new` | Güvenilir IdP sinyali veya bilinmiyor | Dönen cookie'den veya yeni parmak izi mekanizmasından türetilemez. |
| Hedef etiket | `is_suspicious`, UI puanı üretmez | Eğitim için etiketi olmayan satırların politikası AI 3'e ait. `attack_type` yalnızca değerlendirmede. |
| Model çıktısı | 0–100 tamsayı + nedenler + versiyon | Olasılıktan puana dönüşüm varsa AI 3 belgelemeli; kalibrasyon iddiası ayrıca kanıt gerektirir. |
| Oturum özeti | Tüm olaylar değerlendirildiyse maksimum; eşitlikte en son | Bu yöntem ve 30/70 eşikleri varsayım; değerlendirme tamamlanmadan gerçek dünya başarısı iddia edilmez. |

## AI 2 teslimi geldiğinde

1. CSV'yi yalnızca müşteri/yerel ortamda açın. AI sohbetine gerçek kayıt taşımayın.
2. Başlığın 17 alanı ve sırası aynen korunmalı. Biçim hataları değerleri yansıtmadan raporlanmalı.
3. Tip kodlamaları uyuşmuyorsa sütunları değiştirmeden veri sözlüğü üzerinde anlaşın; otomatik tahminle anlam dönüştürmeyin.
4. CSV geldikten sonra AI 3 eğitim/evaluasyon çalışmasına başlayabilir. Mock arayüz kartları eğitim verisi değildir.

## AI 3 teslimi geldiğinde

1. Modelin yalnızca 11 özellik kullandığı; kimlikler, ham zaman, etiket ve saldırı metaverisinin dışlandığı doğrulanmalı.
2. Eksik değer, kategori sözlüğü, versiyon ve puan dönüşümüyle birlikte müşteri içinde çalışabilecek çıkarım sınırı teslim edilmeli.
3. AI 1 `app/model-adapter.js` dosyasında bağlar. Diğer AI'ların model veya veri dosyaları üzerine yazılmaz.
4. Model hata durumları ve null çıktılar puanlanmamış oturum olarak kalmalı; heuristik veya etikete dayalı fallback eklenmemeli.
5. Entegrasyondan sonra mock etiketi yalnızca gerçek model çıktısının bulunduğu modda kaldırılabilir. Sentetik veriyle elde edilen sonuçlar yine gerçek dünyada kanıtlanmış başarı sayılmaz.
