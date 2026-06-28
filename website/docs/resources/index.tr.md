# Projeler ve Ekosistem

## Tamamlayıcı Projeler

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Windows olay günlüklerini düzgün şekilde etkinleştirmek için belgeler ve betikler.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Hayabusa Rules deposuyla aynıdır, ancak kurallar ve yapılandırma dosyaları tek bir dosyada saklanır ve anti-virüs yazılımından kaynaklanan yanlış pozitifleri önlemek için XOR'lanır.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa tarafından kullanılan Hayabusa ve özenle seçilmiş Sigma tespit kuralları.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - `evtx` crate'inin daha iyi bakımı yapılan bir çatallaması (fork).
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - hayabusa/sigma tespit kurallarını test etmek için kullanılacak örnek evtx dosyaları.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Araçlarımız ve kaynaklarımız hakkında verdiğimiz konuşmalardan sunumlar.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Yukarı akış (upstream) Windows olay günlüğü tabanlı Sigma kurallarını daha kolay kullanılabilir bir biçime dönüştürür.
* [Takajo](https://github.com/Yamato-Security/takajo) - hayabusa sonuçları için bir analiz aracı.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - PowerShell ile yazılmış bir Windows olay günlüğü analiz aracı. (Kullanımdan kaldırıldı ve yerini Takajo aldı.)

## Hayabusa Kullanan Üçüncü Taraf Projeleri

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Plaso ve Hayabusa sonuçlarını Timesketch'e aktaran bir NodeRED iş akışı.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - İhtiyaçlarınıza uygun bulut tabanlı güvenlik araçları ve altyapısı sağlar. 
* [OpenRelik](https://openrelik.org/) - İşbirliğine dayalı dijital adli soruşturmaları kolaylaştırmak için tasarlanmış açık kaynaklı (Apache-2.0) bir platform.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Soruşturmalarınız sırasında günlükleri ve araç çıktılarını incelemek için Docker ile hızlıca bir splunk örneği başlatın.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Velociraptor Sorgu Dili (VQL) sorgularını kullanarak ana bilgisayar tabanlı durum bilgilerini toplamak için bir araç.

## Diğer Windows Olay Günlüğü Analiz Araçları ve İlgili Kaynaklar

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Python ile yazılmış saldırı tespit aracı.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Dijital Adli Bilişim ve Olay Müdahalesi için faydalı Event ID kaynaklarının bir koleksiyonu
* [Chainsaw](https://github.com/countercept/chainsaw) - Rust ile yazılmış başka bir sigma tabanlı saldırı tespit aracı.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - [Eric Conrad](https://twitter.com/eric_conrad) tarafından Powershell ile yazılmış saldırı tespit aracı.
* [Epagneul](https://github.com/jurelou/epagneul) - Windows olay günlükleri için grafik görselleştirme.
* [EventList](https://github.com/miriamxyra/EventList/) - [Miriam Wiesner](https://github.com/miriamxyra) tarafından güvenlik temel çizgisi (baseline) event ID'lerini MITRE ATT&CK ile eşleştirir.
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) tarafından
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) tarafından Evtx ayrıştırıcı.
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Tahsis edilmemiş alandan ve bellek görüntülerinden EVTX günlük dosyalarını kurtarın.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Evtx verilerini Elastic Stack'e gönderen Python aracı.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - [SBousseaden](https://twitter.com/SBousseaden) tarafından EVTX saldırı örneği olay günlüğü dosyaları.
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) tarafından ATT&CK ile eşleştirilmiş EVTX saldırı örneği olay günlüğü dosyaları
* [EVTX parser](https://github.com/omerbenamram/evtx) - [@OBenamram](https://twitter.com/obenamram) tarafından yazılmış, kullandığımız Rust evtx kütüphanesi.
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Sysmon ve PowerShell günlüğü görselleştiricisi.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - [JPCERTCC](https://twitter.com/jpcert_en) tarafından yanal hareketi tespit etmek için oturum açmaları görselleştiren grafiksel bir arayüz.
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - NSA'nın neyin izlenmesi gerektiğine dair rehberi.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Yamato Security tarafından DeepBlueCLI'nin Rust uyarlaması.
* [Sigma](https://github.com/SigmaHQ/sigma) - Topluluk tabanlı genel SIEM kuralları.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - [Phil Hagen](https://twitter.com/philhagen) tarafından DFIR analizi için veri içe aktarmaya yönelik Elastic Stack ile önceden paketlenmiş bir VM
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - evtx dosyalarını Security Onion'a aktarın.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Sysmon için yapılandırma ve çevrimdışı günlük görselleştirme aracı.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - [Eric Zimmerman](https://twitter.com/ericrzimmerman) tarafından en iyi CSV zaman çizelgesi analiz aracı.
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - Forward Defense'ten Steve Anson tarafından.
* [Zircolite](https://github.com/wagga40/Zircolite) - Python ile yazılmış Sigma tabanlı saldırı tespit aracı.
