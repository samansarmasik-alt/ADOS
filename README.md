<div align="center">

# ADOS AI

### Windows için hafif, yerel gelen trafik koruması

Kişisel bilgisayarda yayın açarken ve çalışırken gelen paketleri izlemek için hazırlanmış küçük bir Windows prototipi.

![Windows 10/11 x64](https://img.shields.io/badge/Windows-10%20%2F%2011%20x64-0078D4?style=for-the-badge&logo=windows)
![C ve PowerShell](https://img.shields.io/badge/C%20%2B%20PowerShell-native-5C2D91?style=for-the-badge)
![MIT](https://img.shields.io/badge/lisans-MIT-2ea44f?style=for-the-badge)
![Durum](https://img.shields.io/badge/durum-prototip-orange?style=for-the-badge)

[Hızlı başlangıç](#hızlı-başlangıç) · [Kapsam](#ne-yapar) · [Sınırlar](#bilinmesi-gerekenler) · [Geliştirme](#geliştirme)

</div>

> **Erken aşama prototip:** Bu proje, internet servis sağlayıcısı veya ağ kenarı DDoS korumasının yerini tutmaz. Gerçek dünya saldırı doğruluğu ve paket/saniye performansı için ölçüm iddiası yoktur.

## Hızlı başlangıç

1. Windows x64 bilgisayarda [`ADOS.bat`](ADOS.bat) dosyasını indirip çift tıkla. Tek dosyalık paylaşım paketi [`final/ADOS-Windows.zip`](final/ADOS-Windows.zip) içinde de bulunur.
2. Gerçek filtreyi açmak için Windows yönetici iznini onayla. Canlı konsolda durum, görülen ve engellenen paket sayaçları ile son olaylar gösterilir.
3. Çıkmak için konsolda **Q**'ya bas veya pencereyi kapat. Uygulamanın koruma işlemi de kapanır.

Arayüzü güvenle görmek için komut satırında `ADOS.bat --demo` çalıştır. Demo sayaçları ve olayları **simüle eder**; ağa paket göndermez, sürücüyü açmaz ve yönetici izni istemez.

## Ne yapar

- Yerel Windows x64 üzerinde çalışan küçük bir C uygulamasıyla gelen trafiğin seçili bölümünü inceler.
- Kural tabanlı hız sınırları etkin engelleme katmanını oluşturur. Başlangıçtaki karar ağacı modeli trafik özetini değerlendirir; tek başına paket engellemez.
- Tek BAT dosyası gerekli bileşenleri kendi içine alır ve kullanıcı profilindeki `%LOCALAPPDATA%\ADOSAI` klasörüne açar. Çalıştırma sırasında internetten dosya indirmez.
- İmzalı WinDivert sürücüsünü kullanır; başlatıcı paket bütünlüğünü ve sürücü imzasını kontrol eder.
- GPU, Python veya derleyici gerektirmez. Yayın gönderimi gibi dışarı giden trafik incelenmez.

## Trafik kapsamı

| Trafik | Davranış |
| --- | --- |
| Genel IP adreslerinden gelen UDP | Hız sınırlarına göre incelenir |
| ACK içermeyen gelen TCP SYN | Hız sınırlarına göre incelenir |
| Dışarı giden trafik ve kurulmuş TCP bağlantılarının verisi | İnceleme dışı bırakılır |
| Özel/yerel adresler, parçalı veya desteklenmeyen paketler | Bu uygulama tarafından engellenmez |

Yayın ve kodlama yükünü korumak hedeflenmiştir; gelen UDP yanıtları yine de sınırlandırılabilir. İnternet bağlantısının kapasitesi uygulama çalışmadan önce dolarsa yerel filtre bunu geri getiremez.

## Bilinmesi gerekenler

- Hedef işletim sistemi Windows 10/11 x64'tür. ARM64 ve 32 bit Windows pakette desteklenmez.
- Gerçek koruma yönetici izni ister ve WinDivert sürücüsünü kullanır. Windows Güvenlik Duvarı kurallarını değiştirmez.
- Bu başlangıç modeli sentetik başlangıç verisiyle üretilmiştir; gerçek trafik doğruluğu kanıtı değildir. Model ve kurallar yanlış sınıflandırma yapabilir.
- Hız sınırları kişisel bilgisayar için başlangıç değerleridir. Yoğun sunucu trafiği veya yüksek hacimli UDP kullanımında uygun olduğu varsayılmamalıdır.
- Kontrollerin kapsamı ve bilinen ölçüm sınırları [`VERIFICATION.md`](VERIFICATION.md) dosyasındadır. WinDivert lisans bilgileri [`THIRD-PARTY.md`](THIRD-PARTY.md) içindedir.

## Geliştirme

Windows PowerShell ile yerel derleme:

```powershell
powershell -File scripts/build.ps1 -FetchCompiler
powershell -File scripts/package.ps1
```

İlk komut doğrulanmış geliştirici derleyicisini indirip yerel C çalışma zamanını oluşturur. Yeniden eğitim, veri şeması ve sentetik başlangıç modeli hakkında bilgi için [`training/README.md`](training/README.md) dosyasına bak.

Çalışma zamanı ve sürücü bileşenleri `vendor/windivert/` altındadır; lisans koşullarını dağıtımdan önce incele. Üretilen çalışma paketi karmaları `scripts/runtime-manifest.json` içinde tutulur. Bu karmalar dosya bütünlüğünü denetler; koruma başarısını ölçmez.

## Lisans

Proje MIT lisansı altındadır. Üçüncü taraf bileşenlerin kendi lisansları ayrıca geçerlidir; ayrıntılar için [`THIRD-PARTY.md`](THIRD-PARTY.md) dosyasına bak.