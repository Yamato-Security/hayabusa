# Git Cloning

你可以使用下列指令以 `git clone` 複製此儲存庫，並從原始碼編譯出二進位檔：

**警告：** 此儲存庫的 main 分支是用於開發目的，因此你可能可以存取尚未正式發布的新功能，然而其中可能含有錯誤，請將其視為不穩定版本。

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **注意：** 如果你忘記使用 --recursive 選項，以 git submodule 形式管理的 `rules` 資料夾將不會被複製。

你可以使用 `git pull --recurse-submodules` 同步 `rules` 資料夾並取得最新的 Hayabusa 規則，或使用下列指令：

```bash
hayabusa.exe update-rules
```

如果更新失敗，你可能需要將 `rules` 資料夾重新命名後再試一次。

>> 注意：更新時，`rules` 資料夾中的規則與設定檔會被替換為 [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) 儲存庫中最新的規則與設定檔。
>> 你對現有檔案所做的任何變更都會被覆寫，因此我們建議你在更新前先備份任何你編輯過的檔案。
>> 如果你正在使用 `level-tuning` 進行等級調校，請在每次更新後重新調校你的規則檔案。
>> 如果你在 `rules` 資料夾中新增**新的**規則，更新時這些規則**不會**被覆寫或刪除。
