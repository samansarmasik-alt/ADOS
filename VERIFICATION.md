# Doğrulama kaydı — 29 Eylül 2026

Windows 11 x64 üzerinde Zig 0.15.2 ile yerel C derlemesi tamamlandı.
PowerShell sözdizimi, çalışma dosyalarının SHA256 değerleri, WinDivert
sürücüsünün `Valid` Authenticode imzası ve yapılandırma sınırları kontrol edildi.

`scripts/verify.ps1` IPv4/IPv6 UDP, TCP SYN/ACK, kaynak/port sınırları, gözlem
modu, yerel adres, bozuk paket, pencere yenileme, dolu sayaç tablosu ve sonlu
model skoru kontrollerini çalıştırır. Ayrı geçici kopyalarda değiştirilmiş DLL,
yinelenen manifest girdisi, kesirli hız sınırı, üst sınır aşımı ve yanlış
sertifika parmak izi reddedildi.

Çevrimdışı sayaç/karar-ağacı mikro ölçümü ağ paket/saniye kapasitesi değildir:
paket yakalama, sürücü, yeniden iletme veya saldırı trafiği içermez.

Kaggle CLI ile özel CPU eğitim işi tamamlandı. 19.968 sentetik pencere,
birbirinden ayrılmış eğitim/test senaryo grupları ve 4.992 test penceresi
kullanıldı. Kaggle/yerel çıktı karşılaştırması aynı sonucu verdi. 64 örnekte C
ile Python skorları arasındaki en yüksek mutlak fark 2,26e-8 oldu. Model
engellemesi kapalı; gerçek ağ doğruluğu belirlenmedi.

Önceki başlatıcının canlı kontrolünde açık WinDivert katmanı, artan paket
sayaçları ve yaklaşık 9 MB işlem çalışma kümesi gözlendi; sürücü belleği bu
ölçüme dahil değildir. Eski bağımsız işlem, yeni tek-pencere sürümüne geçiş
için kapsamlı stop komutuyla durduruldu ve mutex'in kalktığı doğrulandı.

Yeni sürüm dashboard ana işlemini takip eder ve Windows iş nesnesinin
`KILL_ON_JOB_CLOSE` özelliğini kullanır. İzole bir alt süreçle iş nesnesi
kapanınca alt sürecin de sona erdiği doğrulandı. Üç saniyelik canlı arayüz
kontrolü UAC isteği iptal edildiği için başlatılmadı. Paket içindeki `--check`
doğrulaması yönetici izni istemeden başarılı oldu; paylaşılan ZIP yalnızca
tek BAT ve kısa kullanım notu içeriyor. Kontrollü saldırı, hat doyumu, yayın
kalitesi ve yük altında CPU/gecikme testi yapılmadı.
