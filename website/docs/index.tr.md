---
hide:
  - navigation
  - toc
---

<div class="hb-hero" markdown>

<img class="hb-logo" alt="Hayabusa" src="assets/logo.png" />

<p class="hb-tagline">
<strong>Hayabusa</strong>, <a href="https://yamatosecurity.connpass.com/">Yamato Security</a> tarafından oluşturulmuş bir Windows olay günlüğü <strong>hızlı adli zaman çizelgesi oluşturucu</strong>
ve <strong>tehdit avlama aracıdır</strong>.
Bellek güvenli Rust ile yazılmış, hız için çok iş parçacıklı ve Sigma spesifikasyonunu — v2 korelasyon kuralları dahil —
tam olarak destekleyen tek açık kaynaklı araçtır.
</p>

<div class="hb-cta" markdown>
[Başlayın :material-rocket-launch:](getting-started/index.md){ .md-button .md-button--primary }
[Komut Referansı :material-console:](commands/index.md){ .md-button }
[GitHub'da Görüntüle :fontawesome-brands-github:](https://github.com/Yamato-Security/hayabusa){ .md-button }
</div>

<p class="hb-badges">
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/v/release/Yamato-Security/hayabusa?color=blue&label=Stable%20Version&style=flat"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/releases"><img src="https://img.shields.io/github/downloads/Yamato-Security/hayabusa/total?style=flat&label=GitHub%F0%9F%A6%85Downloads&color=blue"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/stargazers"><img src="https://img.shields.io/github/stars/Yamato-Security/hayabusa?style=flat&label=GitHub%F0%9F%A6%85Stars"/></a>
<a href="https://github.com/Yamato-Security/hayabusa/graphs/contributors"><img src="https://img.shields.io/github/contributors/Yamato-Security/hayabusa?label=Contributors&color=blue&style=flat"/></a>
</p>

</div>

---

## Neden Hayabusa?

<div class="grid cards" markdown>

-   :material-flash:{ .lg .middle } __Yıldırım hızında__

    ---

    Dağ kadar `.evtx` dosyasını ayrıştırmak ve mümkün olduğunca hızlı bir şekilde tek bir zaman çizelgesi üretmek için
    tam çok iş parçacıklı, bellek güvenli **Rust** ile yazılmıştır.

-   :material-shield-search:{ .lg .middle } __Tam Sigma desteği__

    ---

    4.000'den fazla özenle seçilmiş tespit kuralıyla desteklenen, **v2 korelasyon kuralları** dahil olmak üzere
    Sigma spesifikasyonunu tam olarak destekleyen tek açık kaynaklı araç.

-   :material-timeline-clock:{ .lg .middle } __DFIR zaman çizelgeleri__

    ---

    Bir ana bilgisayardan veya binlercesinden gelen olayları, analize hazır tek bir **CSV / JSON / JSONL**
    adli zaman çizelgesinde birleştirir.

-   :material-server-network:{ .lg .middle } __Kurumsal çapta avlanma__

    ---

    Tek bir sistemde canlı çalıştırın, çevrimdışı analiz için günlükler toplayın veya **Velociraptor** Hayabusa
    artefaktı ile kurum genelinde avlanın.

-   :material-chart-box:{ .lg .middle } __Zengin analiz çıktısı__

    ---

    Önemli olanı hızlıca öne çıkarmak için metrikler, oturum açma özetleri, anahtar kelime yönlendirmesi, HTML raporları ve bir tespit
    sıklığı zaman çizelgesi.

-   :material-import:{ .lg .middle } __Diğerleriyle iyi çalışır__

    ---

    Sonuçları doğrudan **Elastic Stack**, **Timesketch**, **Timeline
    Explorer**'a aktarın veya JSON'u **jq** ile dilimleyin.

</div>

## İş başında görün

![Hayabusa DFIR zaman çizelgesi oluşturma](assets/doc/DFIR-TimelineCreation-EN.png)

Terminal çıktısı, HTML sonuç özeti ve LibreOffice, Timeline Explorer ve Timesketch'teki analiz için
[Ekran Görüntüleri](overview/screenshots.md) galerisine göz atın.

## Hızlı bağlantılar

<div class="grid cards" markdown>

-   __:material-book-open-variant: Buraya yeni mi geldiniz?__

    [Genel Bakış](overview/index.md) ile başlayın, ardından Hayabusa'yı indirip çalıştırmak için
    [Başlangıç](getting-started/index.md) bölümüne geçin.

-   __:material-console-line: CLI ile mi çalışıyorsunuz?__

    [Komut Listesi](commands/index.md) ve [Analiz](commands/analysis.md), [Config](commands/config.md) ve
    [DFIR Zaman Çizelgesi](commands/dfir-timeline.md) komutları için komut başına referansa
    geçin.

-   __:material-tune: Çıktıyı mı ayarlıyorsunuz?__

    [Çıktı Profilleri](output/index.md), [Kısaltmalar](output/abbreviations.md)
    ve [Görüntüleme ve Özet](output/display.md) seçeneklerine bakın.

-   __:material-puzzle: Daha ileri mi gidiyorsunuz?__

    [Kuralları](rules/index.md), [proje ekosistemini](resources/index.md)
    ve nasıl [katkıda bulunulacağını](resources/contributing.md) keşfedin.

</div>
