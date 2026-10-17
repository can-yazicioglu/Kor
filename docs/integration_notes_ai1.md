# Entegrasyon kararları — kapanış

İlk AI 1 teslimindeki geçici kodlama varsayımları, tüm eksikleri tamamlama talebiyle ortaklaştırılmıştır. **CSV'ye sütun eklenmedi, çıkarılmadı veya yeniden ad verilmedi.** İlk hata kaydı [tarihsel denetimde](reviews/security_review_2026-10-17_initial.md), güncel doğrulama [son incelemede](security_review.md) bulunur.

| Konu | Son karar |
| --- | --- |
| Ağ aşinalığı | Sayı değil, `familiar/unfamiliar`; CSV okuyucu, Python ve JavaScript aynı sözlükte |
| Saat sapması | Çevrimsel saat uzaklığı, 0–12 saat |
| Kısa pencere | `(t−120 saniye,t]`; aynı zamanda önce gelen kayıt bilinir; gelecekteki olay kullanılmaz |
| Sayaç kapsamı | Denemeler hesap bazında; farklı hesap sayısı geçici ortak kaynak bazında |
| Başarı/kaynak/episode doğrulama | Sabit CSV dışında yalnız sentetik denetim manifesti; hiçbir alan model girdisi değil |
| Eksik geçmiş | CSV boş, uygulamada null; çıkarım puan üretmez, sıfır saymaz |
| Model girdisi | Kesin 11 özellik allowlist'i; kimlik/ham zaman/hedef/senaryo dışarıda |
| Model çıktısı | Gerçek eğitilmiş lojistik JSON; tamsayı risk, katkı gerekçeleri ve sürüm |
| Kimlik eşleme | Model dışında uygulama katmanında; oturumun tüm olayları puanlanırsa maksimum |
| Eşik | UI 30/70; validation benchmark eşiği ayrı ve uygunluk durumu açık |
| Kayıt ömrü | CSV tarayıcıda 5/10/15 dakika; kaynak dosya ve sentetik artefaktların politikası ayrı |
| Model bozulması | Sözleşme ve checksum denetimi; hata/null düşük risk değil |

Gerçek IdP başarısı, müşteri kaynak anahtarı, üretim cookie'si ve gerçek geçmiş entegrasyonu yerel prototipin kapsamı dışındadır. Model yanlış alarm üretebilir; özellikle normal seyahat ve yeni cihazlar için değerlendirme sınırları sonuç raporunda açıklanır.
