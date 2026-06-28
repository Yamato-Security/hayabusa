# Yapılandırma Komutları

## `config-critical-systems` komutu

Bu komut, etki alanı denetleyicileri ve dosya sunucuları gibi kritik sistemleri otomatik olarak bulmaya çalışır ve bunları `./config/critical_systems.txt` yapılandırma dosyasına ekler; böylece tüm uyarılar bir seviye artırılır.
Bir etki alanı denetleyicisi olup olmadığını belirlemek için Security 4768 (Kerberos TGT istendi) olaylarını arar.
Bir dosya sunucusu olup olmadığını belirlemek için Security 5145 (Ağ Paylaşımı Dosya Erişimi) olaylarını arar.
`critical_systems.txt` dosyasına eklenen tüm ana bilgisayar adlarında, düşük seviyenin üzerindeki tüm uyarılar bir seviye artırılır ve en fazla `emergency` seviyesine çıkar.

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  Directory of multiple .evtx files
  -f, --file <FILE>      File path to one .evtx file

Display Settings:
  -K, --no-color  Disable color output
  -q, --quiet     Quiet mode: do not display the launch banner

General Options:
  -h, --help  Show the help menu
```

### `config-critical-systems` komut örnekleri

* `../hayabusa-sample-evtx` dizininde etki alanı denetleyicileri ve dosya sunucuları arayın:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
