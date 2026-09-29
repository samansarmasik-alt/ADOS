# Gerçek CIC-IDS2017 verisiyle eğitim

Model, CIC-IDS2017 Cuma günündeki DDoS etiketleri ve bunlara denk gelen PCAP trafiğinden çıkarılan pencerelerle eğitildi. 8.839.309.056 baytlık tam PCAP indirilmez. İndirme betiği zaman damgalarından gerekli aralığı HTTP Range istekleriyle bulur ve yalnızca 18:51–19:21 UTC arasındaki 1.395.776.380 kaynak baytını (çıktı PCAPNG başlığıyla 1.395.776.472 bayt) alır. Yanındaki gerekli etiket Parquet dosyası 23.048.086 bayttır. İki dosya `training/downloads/` altında kalır ve Git'e eklenmez.

## Yerel CPU ile yeniden üretme

PowerShell'de proje kökünden çalıştır:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-training.txt
.\.venv\Scripts\python.exe training\download_cic_ddos_slice.py
.\.venv\Scripts\python.exe training\pcap_to_windows.py
.\.venv\Scripts\python.exe training\train_model.py --input training\downloads\cicids2017\windows.csv --seed 20260929 --test-size 0.25
```

İndirme betiği PCAP dilimini ve etiket dosyasını SHA-256 ile doğrular. Doğrulanmış yerel dosyaları tekrar kullanır. `--plan-only` yalnızca byte aralığını hesaplar; veri indirmez. Dönüştürücü hedef cihazı `192.168.10.50` olarak sabitler, karşılıklı IP/port/protokol akışlarıyla etiketleri eşler ve çalışma zamanının görebildiği gelen UDP ile ACK içermeyen TCP SYN paketlerinden 1 saniyelik pencereler çıkarır. Ham PCAP ve etiketler depoda tutulmaz.

Eğitici `models/model.json`, `models/model.h` ve `models/parity.json` dosyalarını üretir. `--input` verilmezse yalnızca geliştirme amaçlı sentetik başlangıç verisi kullanılır; bu seçenek gerçek modelin yeniden üretimi değildir. Kaggle CLI, yerel CPU eğitimi ve bu veri indirme akışı için gerekli değildir.

## Veri sınırları

Çıktı 650 pencereden oluşur: 411 normal, 239 DDoS. Kaynak etiket zamanları dakika hassasiyetindedir; dönüştürücü etiket çakışmalarını dışarıda bırakır ve her pencere için yeterli etiketli paket eşleşmesi arar. Ayrıntılı sayımlar `manifest.json` içinde yazılır.

DDoS örnekleri tek bir bağımsız saldırı grubunda toplandığı için veri sızıntısı olmadan iki sınıfı da içeren grup bazlı eğitim/test ayrımı kurulamıyor. Bu nedenle model tüm 650 pencereyle eğitilir; başarı metriği raporlanmaz (`metrics: null`). Model üretim doğrulamasından geçmemiştir, otomatik engelleme kapalıdır ve sonuç yalnızca tavsiye niteliğindedir. Kişisel bilgisayarda OBS ile YouTube yayını, kodlama yükü, yanlış pozitif oranı ve gerçek hat koşulları ayrıca ölçülmemiştir.

Özellik şeması her tamamlanmış 1 saniyelik pencere için `packet_rate`, `mean_packet_bytes`, `syn_ratio`, `udp_ratio`, `label`, `group_id` sütunlarını kullanır. `group_id` anonim oturum/grup tanımlayıcısıdır; IP adresi veya kişisel veri ekleme. Runtime kurulmuş TCP bağlantılarının verisini ve dışarı giden yayın trafiğini bu modele vermez.
