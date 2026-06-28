# Git Cloning

Anda dapat melakukan `git clone` terhadap repositori dengan perintah berikut dan mengompilasi biner dari kode sumber:

**Peringatan:** Branch main dari repositori ini ditujukan untuk keperluan pengembangan sehingga Anda mungkin dapat mengakses fitur-fitur baru yang belum dirilis secara resmi, namun, mungkin terdapat bug sehingga anggaplah branch ini tidak stabil.

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **Catatan:** Jika Anda lupa menggunakan opsi --recursive, folder `rules`, yang dikelola sebagai git submodule, tidak akan ikut di-clone.

Anda dapat menyinkronkan folder `rules` dan mendapatkan aturan Hayabusa terbaru dengan `git pull --recurse-submodules` atau gunakan perintah berikut:

```bash
hayabusa.exe update-rules
```

Jika pembaruan gagal, Anda mungkin perlu mengganti nama folder `rules` dan mencoba lagi.

>> Perhatian: Saat memperbarui, file aturan dan file konfigurasi di dalam folder `rules` akan digantikan dengan file aturan dan file konfigurasi terbaru dari repositori [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).
>> Setiap perubahan yang Anda buat pada file yang sudah ada akan ditimpa, jadi kami menyarankan agar Anda membuat cadangan dari file apa pun yang Anda edit sebelum memperbarui.
>> Jika Anda melakukan penyetelan level dengan `level-tuning`, harap setel ulang file aturan Anda setelah setiap pembaruan.
>> Jika Anda menambahkan aturan **baru** di dalam folder `rules`, aturan tersebut **tidak** akan ditimpa atau dihapus saat memperbarui.
