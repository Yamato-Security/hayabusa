# Perintah Config

## Perintah `config-critical-systems`

Perintah ini akan secara otomatis mencoba menemukan sistem-sistem kritis seperti domain controller dan file server lalu menambahkannya ke file konfigurasi `./config/critical_systems.txt` sehingga semua alert akan dinaikkan satu tingkat.
Perintah ini akan mencari event Security 4768 (Kerberos TGT requested) untuk menentukan apakah sebuah host adalah domain controller.
Perintah ini akan mencari event Security 5145 (Network Share File Access) untuk menentukan apakah sebuah host adalah file server.
Setiap hostname yang ditambahkan ke file `critical_systems.txt` akan memiliki semua alert di atas low dinaikkan satu tingkat dengan tingkat maksimum `emergency`.

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

### Contoh perintah `config-critical-systems`

* Mencari domain controller dan file server di direktori `../hayabusa-sample-evtx`:

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
