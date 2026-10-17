# Veri yaşam döngüsü ve silme sınırı

Bu politika yerel MVP'nin uygulanan davranışını açıklar. Ham parola, kullanıcı adı, IP, kesin konum veya kalıcı cihaz parmak izi hiçbir bileşene verilmez. Opak kimlikler de ilişkilendirilebilir veri kabul edilir. Gerçek müşteri kayıtları AI sohbetine yüklenmez.

| Veri | Nerede tutulur? | Ömür / bırakma davranışı |
| --- | --- | --- |
| İçe aktarılan CSV, olaylar ve oturum özetleri | Yalnızca tarayıcı belleği | Kullanıcının seçtiği 5, 10 veya 15 dakika. Süre dolması, sıfırlama, sayfadan ayrılma veya yeni başarılı içe aktarım eski referansları bırakır. |
| Model JSON'u | Yerel statik dosya; tarayıcı belleğinde çıkarım parametreleri | Model artefaktı sürümle tutulur; müşteri olayı içermez. HTTP yanıtı `no-store` kullanır. |
| CSV kaynak dosyası | Kullanıcının yerel diski | Tarayıcı bu dosyayı değiştirmez veya silmez. Kullanıcının dosya yaşam döngüsüne tabidir. |
| `data/` içindeki CSV ve denetim manifesti | Geliştirme deposu | Açıkça sentetik, yeniden üretilebilir test artefaktları olarak kalıcıdır. Gerçek müşteri verisi yerine kullanılamaz. |
| `models/` ve `outputs/` | Yerel geliştirme deposu | Yalnızca sentetik eğitimden model/özet/örnek çıktılar. Verinin hash'i ve model sürümüyle izlenir; müşteri çıktıları burada tutulmaz. |
| Erişim logları | Oluşturulmaz | Demo HTTP sunucusu adres, istek yolu veya CSV içeriği loglamaz. |
| Cookie / web storage / biyometri | Kullanılmaz | Demo cookie, localStorage, sessionStorage, IndexedDB veya fare/klavye davranış kaydı oluşturmaz. |

Uygulama zamanlayıcı yanında mutlak son kullanım zamanını kontrol eder; sekme görünürlüğü değişince ve kullanıcı veriyle etkileşime geçince süreyi yeniden denetler. Tarayıcı askıdayken JavaScript çalışamayabilir. Yeniden etkinleştiğinde süresi dolmuş veriye erişimden önce referanslar bırakılır. Bu davranış işletim sistemi belleğinin, swap'in, crash dump'ın veya tarayıcı iç kopyalarının fiziksel silindiği garantisi değildir.

## Pencere ve oturum süresi

**120 saniyelik analiz penceresi, dosyanın bellekte tutulma süresinden farklıdır.** Sentetik üretici hesap bazında `(t−120 saniye, t]` ve `(t−1 saat, t]` sayaçları, geçici ortak kaynak bazında farklı hesap sayısı üretir. Başarısızlık oranı mevcut olayın sonucunu kullanmadan önceki 24 saatlik sentetik sonuçlardan hesaplanır.

Sentetik manifestte kaynak ve oturum anahtarlarının ömrü en fazla 120 saniye olarak modellenir; aynı episode içindeki cookie dönüşümleri hesap/kaynak sayacını sıfırlamaz. Kaynak anahtarları ve gerçek giriş sonucu yalnızca denetim manifestinde bulunur; model özellikleri değildir. Manifestteki tokenlar gerçek cookie olarak kullanılmamalıdır.

Bu MVP bir canlı IdP veya sürekli olay toplama servisi içermez. Üretim bağlantısında rastgele, kısa ömürlü `Secure`/`HttpOnly` cookie, müşteri içi kaynak anahtarı ve gerçek TTL depolaması müşteri ortamında uygulanmalıdır. Canlı sayaçların süresi şu kapsamlarla ayrı yönetilmelidir:

- Kaynak korelasyonu: 120 saniye ve açıkça kararlaştırılmış geç olay toleransı.
- Hesap deneme sayacı: 1 saate kadar gerekli özet; daha uzun ham olay tutma zorunluluğu yoktur.
- Başarısızlık oranı: en fazla gerekli 24 saatlik sonuç özeti.
- Alışkanlık geçmişi: mevcut ve izin verilen veri varsa; 30 günlük gerçek geçmiş varmış gibi doldurulmaz.

## Ağ sınırı

Tarayıcı yalnızca aynı yerel sunucudaki model JSON'unu GET ile alır. CSV ve özellikler HTTP isteği oluşturmaz; çıkarım JavaScript ile tarayıcı içinde yapılır. Sunucu loopback'e bağlıdır, izinli dosya yolları dışını ve POST yüklemelerini reddeder. Model dosyasının dışarıdan alınması, uzak API kullanımı veya gerçek müşteri çıktılarının depoya eklenmesi mevcut MVP'nin desteklediği akış değildir.

## Doğrulama

`app/tests/` süre sınırı, sıfırlama, askı sonrası zaman kontrolü, sunucu dosya sınırı ve yükleme reddini; `tests/` sentetik kaynak/oturum ömrünü ve pencere sınırlarını sınar. Uygulama referansı bırakma ile fiziksel silme ayrı değerlendirilir. Gerçek IdP/TTL servisi olmadığı için bu belge onun güvenlik onayı değildir.
