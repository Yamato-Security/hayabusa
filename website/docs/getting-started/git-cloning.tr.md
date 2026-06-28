# Git ile Klonlama

Depoyu aşağıdaki komutla `git clone` ile klonlayabilir ve ikili dosyayı kaynak koddan derleyebilirsiniz:

**Uyarı:** Deponun ana dalı (main branch) geliştirme amaçlıdır; bu nedenle henüz resmi olarak yayınlanmamış yeni özelliklere erişebilirsiniz, ancak hatalar olabilir, dolayısıyla kararsız olarak değerlendirin.

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **Not:** --recursive seçeneğini kullanmayı unutursanız, git alt modülü (submodule) olarak yönetilen `rules` klasörü klonlanmayacaktır.

`rules` klasörünü `git pull --recurse-submodules` ile senkronize edebilir ve en son Hayabusa kurallarını alabilir veya aşağıdaki komutu kullanabilirsiniz:

```bash
hayabusa.exe update-rules
```

Güncelleme başarısız olursa, `rules` klasörünü yeniden adlandırıp tekrar denemeniz gerekebilir.

>> Dikkat: Güncelleme sırasında, `rules` klasöründeki kurallar ve yapılandırma dosyaları, [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) deposundaki en son kurallar ve yapılandırma dosyalarıyla değiştirilir.
>> Mevcut dosyalarda yaptığınız değişikliklerin üzerine yazılacağından, güncellemeden önce düzenlediğiniz dosyaların yedeğini almanızı öneririz.
>> `level-tuning` ile seviye ayarı (level tuning) yapıyorsanız, lütfen her güncellemeden sonra kural dosyalarınızı yeniden ayarlayın.
>> `rules` klasörünün içine **yeni** kurallar eklerseniz, güncelleme sırasında bunların üzerine **yazılmaz** veya silinmez.
