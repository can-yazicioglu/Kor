# Ephemeral Login Sentinel: sıfırdan projenin tamamı

**Tek cümleyle:** Sentinel, bir girişin çevresindeki kısa ömürlü işaretleri inceleyip oturum riskini açıklayan, gerektiğinde ek doğrulama veya insan incelemesi öneren bir güvenlik prototipi.

Amacımız yalnızca “şifre doğru mu?” sorusunu cevaplamak değil. Doğru şifreyle yapılan bir girişin çevresinde şüpheli olaylar varsa bunları da görünür kılmak. Bunu yaparken kalıcı cihaz parmak izi, ham IP kaydı veya uzun süreli kullanıcı takibi oluşturmuyoruz.

## 1. Hangi problemi çözüyoruz?

Bir saldırgan aynı hesaba art arda şifre deneyebilir: **brute force**. Aynı kaynaktan çok sayıda hesaba az sayıda deneme yapabilir: **password spraying**. Birden fazla kaynakla aynı hesabı hedefleyebilir. Hatta doğru şifreyi bilip yeni cihaz ve alışılmadık bağlamla giriş yapabilir.

Sadece şifrenin doğru olması bu olayların tamamını açıklamaz. Sentinel, girişin öncesine ve bağlamına bakarak güvenlik ekibine ek kanıt sunmayı amaçlıyor. Otomatik hesap kilitlemiyor; önerisi MFA veya inceleme. Bu bir araştırma demosu: gerçek saldırılara karşı başarısı henüz kanıtlanmış değil.

## 2. Ekrandaki şirket ne?

**Vela**, projeyi anlatmak için oluşturulmuş hayali şirket. Çalışan giriş sayfasının yanında Sentinel risk monitörü var. Böylece şirket çalışanının gördüğü giriş akışıyla güvenlik ekibinin gördüğü kanıt aynı demoda izlenebiliyor.

Gerçek bir şirket hesabına bağlanmıyoruz. `demo / VelaDemo!42` ve `123456` herkese açık sunum değerleri. MFA ekranındaki kod gerçek bir ikinci faktör güvenliği sağlamıyor; akışı gösteriyor. Açılan çalışma alanı da tamamen kurgusal.

## 3. Bir giriş yaptığımda adım adım ne oluyor?

1. **Form yerel sunucuya gider.** Şifre ML modeline veya harici bir AI servisine gönderilmez. Tarayıcı alanları temizler; sunucu girilen değeri geçici olarak kontrol eder.
2. **Kimlik doğrulama yapılır.** Yayınlanmış demo şifresi, tuzlu `scrypt` doğrulayıcısıyla karşılaştırılır. Bu kontrol “şifre doğru mu?” sorusunu cevaplar.
3. **Parola referansı ayrı incelenir.** Değer, yerel yaygın-parola referansıyla karşılaştırılır. Tam veya sınırlı benzerlik eşleşmesi ayrı bir kanıttır; canlı akışta skora gelişigüzel +25/+10 eklenmez.
4. **Giriş olayı oluşturulur.** Ham kullanıcı adı yerine opak hesap/oturum anahtarları ve türetilmiş bağlam kullanılır.
5. **Son iki dakikaya bakılır.** Hesap denemeleri, hatalar, kaynaklar ve kaynak başına başarısız hesaplar sayılır. Pencere `(şimdi−120 saniye, şimdi]` biçimindedir.
6. **Model ve kurallar değerlendirilir.** Model bağlamdan sayısal bir tahmin üretir; ayrı kurallar tekrar eden hata veya spraying gibi örüntüleri açıklar.
7. **Sonuç gösterilir.** Güncel risk, eldeki oturum geçmişinin en yüksek puanı, veri kalitesi, nedenler ve MFA/inceleme önerisi görünür. Eksik geçmiş sıfır risk sayılmaz.
8. **Erişim ayrıca kontrol edilir.** Demo doğrulamasından sonra sunucu kısa süreli çalışan yetkisi verir. Her kaynak isteğinde yetki yeniden kontrol edilir; çalışan hesabı yönetici konsoluna giremez.

Birbirinden farklı üç karar var: **kimlik doğrulama** kim olduğunu kontrol eder; **risk analizi** girişin şüpheli bağlamını değerlendirir; **yetkilendirme** hangi kaynağa erişebileceğini belirler. Düşük risk puanı tek başına kapıyı açmaz.

## 4. Yapay zekâ nerede? ChatGPT mi kullanılıyor?

Canlı akışta bir dil modeli veya bulut AI çağrısı yok. Dahil edilen **11 özellikli lojistik model** yerel çıkarım yapıyor. Doğrulama verisiyle hazırlanmış ayrı bir kalibrasyon eşlemesi kullanılıyor.

Özellikler; deneme sayıları, hata oranı, saat/hafta günü bağlamı, coğrafi hız, ağ tanınırlığı, ASN kategorisi ve cihazın yeni/yönetilen olması gibi işaretlerden oluşuyor. Ham şifre, kimlik değerleri, `is_suspicious` hedef etiketi ve `attack_type` değerlendirme bilgisi model girdisi değil.

Ek eğitim çalışmaları farklı model/parametre adaylarını karşılaştırdı; bu bir LLM fine-tuning çalışması değil. Bazı adaylar sentetik veride daha iyi sıralama sağladı. Ancak son aday iki değerlendirme grubundaki şüpheli başarılı girişlerin **0/108 ve 0/115** tanesini yakaladı. Bu yüzden yayın kapısı adayı reddediyor ve canlı demoya geçmiyor.

Mevcut modelin de önemli sınırı var: hedeflenen yanlış alarm/yakalama dengesini sağlayan karar eşikleri bulunamadı. Bu nedenle tamamlanmış normal girişlerde bile inceleme öneriliyor. Yani “normal kullanıcıları sorunsuz geçirirken saldırıları kusursuz ayıran sistem” noktasında değiliz. **80 puan, gerçek dünyada %80 saldırı olasılığı demek değil.**

## 5. İki dakikalık sayaçlar veri tutmadan nasıl çalışıyor?

“Hiç veri tutmuyoruz” doğru bir tanım olmaz. **Az veri tutuyoruz ve süresini sınırlıyoruz.** Saymak için opak anahtarlar, türetilmiş olaylar, kararlar ve bazı kontrol bilgileri geçici RAM durumunda bulunuyor.

Demo başlarken sabit **beş dakikalık** ömür belirleniyor; sayfayı veya kanıtları yenilemek bunu uzatmıyor. Analiz son iki dakikayı kullanıyor. Kaynak yetkisi en fazla iki dakika, MFA sınaması da kendi kısa ömrüyle sınırlı. Sıfırlama veya süre dolması uygulamanın bu kayıtlara ve anahtarlara tuttuğu referansları kaldırıyor.

Bu, fiziksel RAM bitlerinin kesin biçimde silindiğini kanıtlamaz. Ayrıca sentetik CSV'ler, model dosyaları ve test sonuçları araştırma amacıyla repoda kalır. Gelecekte bağlanacak şirketin kimlik sağlayıcısının kendi kayıtlarına ayrı saklama politikası gerekir.

Uygulama kalıcı cihaz parmak izi, fare/klavye biyometrisi, ham IP günlüğü, çerez veya tarayıcı depolaması kullanmıyor. Demodaki “yeni cihaz”, “seyahat” ve geçmiş bağlamı sentetik; kullanıcıyı gerçekten 30 gündür izliyormuş gibi davranmıyoruz.

## 6. Yaygın şifre kontrolü internete ne gönderiyor?

Canlı kontrolde **hiçbir şey göndermiyor**. İki sabitlenmiş SecLists parola sözlüğünden hazırlanmış, 12.526 farklı girdilik yerel referans var. Tam eşleşmenin yanında normalleştirme, belirli son ekler ve sınırlı tek karakter değişiklikleri incelenebiliyor.

Kaynakların indirilmesi yalnızca açıkça çalıştırılan referans oluşturma adımında yapılır. Giriş sırasında liste çekilmez, HIBP sorgusu yapılmaz, şifre veya hash öneki başka servise gönderilmez. Referans hash'leri herkese açık kelimelerin indeksidir; gizli kullanıcı şifreleri değildir.

Eşleşme “bu hesabın şifresi sızdırılmıştır” anlamına gelmez. Eşleşmemesi de güvenli şifre garantisi vermez. Hatalı bir denemede kullanılan zayıf parola, hesabın gerçek parolasının zayıf olduğunu göstermez. [Tam kaynaklar ve sınırlar](password_sources.md).

## 7. Güvenlik tarafında neler var?

| Amaç | Demoda karşılığı |
|---|---|
| **Gizlilik — Confidentiality** | Türetilmiş veri, opak anahtarlar, sınırlı RAM ömrü; isteğe bağlı TLS 1.3. Varsayılan yerel HTTP şifreli değil. |
| **Bütünlük — Integrity** | İmzalı sağlayıcı mesajları, tekrar gönderim kontrolü ve HMAC karar makbuzu; dosyalar için SHA-256 karşılaştırması. |
| **Erişilebilirlik — Availability** | İstek/işçi/olay sınırları, işlem süreleri, pahalı parola kontrollerine eşzamanlılık sınırı. Bunlar tam DDoS koruması veya yüksek erişilebilirlik değil. |
| **Kimlik doğrulama** | Tuzlu scrypt demo doğrulayıcısı ve o girişe bağlı, süreli demo MFA kontrolü. |
| **Yetkilendirme** | Sunucunun verdiği sabit çalışan rolü; her istekte kontrol ve yönetici kaynağına ret. |

Hatalı etkileşimli şifreler beklemeyi **1, 2, 4, 8, 16, 32, 60 saniye** artırıyor; 60'da duruyor. Bu sınır demo oturumuna ait, reset ile kalkabilir. Gerçek sağlayıcıda ortak hesap sınırı gerekir.

Karar makbuzu, o demoya özel rastgele bir anahtarla HMAC kullanıyor. Puanı değiştirilmiş kopya doğrulanamıyor. Bu bir şifreleme yöntemi, kalıcı denetim günlüğü veya ele geçirilmiş sunucuya karşı garanti değil. Kod bu ayrımları arayüzde de açıklıyor.

## 8. Ne kadar özgün?

**Algoritma açısından özgünlük düşük; ürünün birleştirilmesi ve gösterimi açısından orta düzeyde.** Bu nitel bir değerlendirme, ölçülmüş puan değil. Risk temelli MFA ve cihaz/konum analizi zaten [Auth0](https://auth0.com/docs/secure/multi-factor-authentication/adaptive-mfa) ve [Microsoft Entra](https://learn.microsoft.com/en-us/entra/id-protection/concept-risk-detection-types) gibi ürünlerde var.

Bizim somut katkımız; kısa saklama süresini görünür kılan, 30/60/120 saniyelik kural kanıtlarını karşılaştıran, değiştirilen kararı sınatabilen ve model başarısızlığını açıkça sergileyen bütünlüklü bir uygulama. Bunların dünyada ilk kez bir araya geldiğini kanıtlamış değiliz.

Jüriye söylenebilecek dürüst cümle:

> Daha çok kişisel veri toplamak yerine, kısa ömürlü giriş kanıtından ne kadar faydalı risk bilgisi çıkarabileceğimizi araştırıyoruz. Kullanıcıya yalnızca puan değil, nedenlerini, saklama sınırını ve sistemin hangi durumda yetersiz kaldığını da gösteriyoruz.

[İngilizce özgünlük değerlendirmesi ve karşılaştırma](originality.md).

## 9. IBM Z ile ilişkisi ne?

Proje; güvenliği ve veri minimizasyonunu AI uygulamasının başından itibaren düşünme temasına uyuyor. Kriptografi envanteri, tehdit modeli, yerel işlem sınırı ve kontrollü entegrasyon arayüzü hazırlanmış durumda.

Ama şu anda **IBM Z üzerinde çalıştırılmış bir dağıtım yok**. Secure Execution, donanım anahtar koruması veya quantum-safe entegrasyon uygulanmış diye sunmamalıyız. Bunlar gelecekte gerçek altyapıyla doğrulanacak entegrasyon adımları. “IBM Z Datathon için hazırlanmış prototip” doğru ifade.

## 10. Nasıl çalıştırıp gösteriyoruz?

Repo klasöründe:

```bash
python3 scripts/preflight.py
python3 app/serve.py --port 8001
```

Tarayıcıdan `http://127.0.0.1:8001/company.html` adresini aç. Python 3.10+ yeterli; demo için API anahtarı veya ek paket gerekmez.

Sunumda şu sırayı kullan:

1. **Brute force:** 20 sahte hatanın sayaçlara ve gerekçelere yansımasını göster.
2. **Fill in → Sign in → 123456:** başarılı şifre ve demo MFA sonrasında önceki risk kanıtının kaybolmadığını anlat.
3. **Security lab → Test altered receipt:** orijinal kararın doğrulanıp değiştirilmiş kopyanın reddedildiğini göster.
4. **Employee resource → Try restricted console:** giriş yapmış olmanın her yere erişmek anlamına gelmediğini göster.
5. **Evidence & privacy → Reset demo:** geçici durumun kapsamını ve sıfırlamayı göster.
6. Son cümlede sentetik değerlendirme sınırını ve kapalı aday modeli açıkça söyle.

Yazılım için kayıtlı doğrulama kapsamı: **200 Python testi, 16 sunucu testi, 111 JavaScript kontrolü ve 8 masaüstü/mobil Chromium senaryosu**. Güncel çalışmanın sonucu GitHub CI rozetinde görünür. Testlerin geçmesi güvenlik açıklarının veya model hatalarının tamamen bittiği anlamına gelmez.

Bir sonraki büyük adım daha fazla özellik eklemekten önce, şüpheli başarılı girişleri normal seyahat/VPN kullanımından ayırabilmek; yeni ve önceden dondurulmuş değerlendirme gruplarıyla sınamak; seçilecek kimlik sağlayıcısıyla müşteri ortamında gözlem modunda çalışmak. Üretim güvenilirliği buradan kazanılacak.
