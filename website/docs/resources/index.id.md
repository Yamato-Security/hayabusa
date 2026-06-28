# Proyek & Ekosistem

## Proyek Pendamping

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - Dokumentasi dan skrip untuk mengaktifkan log peristiwa Windows dengan benar.
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - Sama seperti repositori Hayabusa Rules tetapi aturan dan file konfigurasi disimpan dalam satu file dan di-XOR untuk mencegah positif palsu dari anti-virus.
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Aturan deteksi Hayabusa dan Sigma terkurasi yang digunakan oleh Hayabusa.
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - Fork dari crate `evtx` yang lebih terpelihara.
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - File evtx sampel untuk digunakan menguji aturan deteksi hayabusa/sigma.
* [Presentations](https://github.com/Yamato-Security/Presentations) - Presentasi dari ceramah yang telah kami berikan tentang alat dan sumber daya kami.
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - Mengkurasi aturan Sigma berbasis log peristiwa Windows hulu menjadi bentuk yang lebih mudah digunakan.
* [Takajo](https://github.com/Yamato-Security/takajo) - Penganalisis untuk hasil hayabusa.
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - Penganalisis untuk log peristiwa Windows yang ditulis dalam PowerShell. (Tidak digunakan lagi dan digantikan oleh Takajo.)

## Proyek Pihak Ketiga Yang Menggunakan Hayabusa

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - Alur kerja NodeRED yang mengimpor hasil Plaso dan Hayabusa ke dalam Timesketch.
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - Menyediakan alat dan infrastruktur keamanan berbasis cloud yang sesuai dengan kebutuhan Anda. 
* [OpenRelik](https://openrelik.org/) - Platform sumber terbuka (Apache-2.0) yang dirancang untuk menyederhanakan investigasi forensik digital kolaboratif.
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - Dengan cepat menjalankan instance splunk dengan Docker untuk menjelajahi log dan keluaran alat selama investigasi Anda.
* [Velociraptor](https://github.com/Velocidex/velociraptor) - Alat untuk mengumpulkan informasi status berbasis host menggunakan kueri The Velociraptor Query Language (VQL).

## Penganalisis Log Peristiwa Windows Lainnya dan Sumber Daya Terkait

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - Alat deteksi serangan yang ditulis dalam Python.
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  Koleksi sumber daya Event ID yang berguna untuk Forensik Digital dan Tanggap Insiden
* [Chainsaw](https://github.com/countercept/chainsaw) - Alat deteksi serangan berbasis sigma lainnya yang ditulis dalam Rust.
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - Alat deteksi serangan yang ditulis dalam Powershell oleh [Eric Conrad](https://twitter.com/eric_conrad).
* [Epagneul](https://github.com/jurelou/epagneul) - Visualisasi grafik untuk log peristiwa Windows.
* [EventList](https://github.com/miriamxyra/EventList/) - Memetakan ID peristiwa baseline keamanan ke MITRE ATT&CK oleh [Miriam Wiesner](https://github.com/miriamxyra).
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - oleh [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - Pengurai Evtx oleh [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Memulihkan file log EVTX dari ruang yang tidak teralokasi dan citra memori.
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - Alat Python untuk mengirim data Evtx ke Elastic Stack.
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - File log peristiwa sampel serangan EVTX oleh [SBousseaden](https://twitter.com/SBousseaden).
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - File log peristiwa sampel serangan EVTX yang dipetakan ke ATT&CK oleh [Michel de CREVOISIER](https://twitter.com/mdecrevoisier)
* [EVTX parser](https://github.com/omerbenamram/evtx) - pustaka evtx Rust yang kami gunakan ditulis oleh [@OBenamram](https://twitter.com/obenamram).
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Visualisasi log Sysmon dan PowerShell.
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Antarmuka grafis untuk memvisualisasikan logon guna mendeteksi pergerakan lateral oleh [JPCERTCC](https://twitter.com/jpcert_en).
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - Panduan NSA tentang apa yang harus dipantau.
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - Port Rust dari DeepBlueCLI oleh Yamato Security.
* [Sigma](https://github.com/SigmaHQ/sigma) - Aturan SIEM generik berbasis komunitas.
* [SOF-ELK](https://github.com/philhagen/sof-elk) - VM yang sudah dikemas dengan Elastic Stack untuk mengimpor data bagi analisis DFIR oleh [Phil Hagen](https://twitter.com/philhagen)
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - Mengimpor file evtx ke dalam Security Onion.
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Alat konfigurasi dan visualisasi log offline untuk Sysmon.
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - Penganalisis timeline CSV terbaik oleh [Eric Zimmerman](https://twitter.com/ericrzimmerman).
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - oleh Steve Anson dari Forward Defense.
* [Zircolite](https://github.com/wagga40/Zircolite) - Alat deteksi serangan berbasis Sigma yang ditulis dalam Python.
