# 下載

請從 [Releases](https://github.com/Yamato-Security/hayabusa/releases) 頁面下載已編譯為二進位檔的最新穩定版 Hayabusa，或自行編譯原始碼。

我們提供下列架構的二進位檔：

- Linux ARM 64 位元 GNU（`hayabusa-x.x.x-lin-aarch64-gnu`）
- Linux ARM 64 位元 MUSL（`hayabusa-x.x.x-lin-aarch64-musl`）
- Linux Intel 64 位元 GNU（`hayabusa-x.x.x-lin-x64-gnu`）
- Linux Intel 64 位元 MUSL（`hayabusa-x.x.x-lin-x64-musl`）
- macOS ARM 64 位元（`hayabusa-x.x.x-mac-aarch64`）
- macOS Intel 64 位元（`hayabusa-x.x.x-mac-x64`）
- Windows ARM 64 位元（`hayabusa-x.x.x-win-aarch64.exe`）
- Windows Intel 64 位元（`hayabusa-x.x.x-win-x64.exe`）
- Windows Intel 32 位元（`hayabusa-x.x.x-win-x86.exe`）

## Windows 即時回應套件

自 v2.18.0 起，我們提供特殊的 Windows 套件，這些套件使用以單一檔案提供的 XOR 編碼規則，並將所有設定檔合併為單一檔案（託管於 [hayabusa-encoded-rules 儲存庫](https://github.com/Yamato-Security/hayabusa-encoded-rules)）。
只需下載名稱中含有 `live-response` 的 zip 套件即可。
這些 zip 檔僅包含三個檔案：Hayabusa 二進位檔、XOR 編碼規則檔以及設定檔。
這些即時回應套件的目的，是當在用戶端端點上執行 Hayabusa 時，我們希望確保像 Windows Defender 這類防毒掃描程式不會對 `.yml` 規則檔產生誤報。
此外，我們希望盡量減少寫入系統的檔案數量，以免像 USN Journal 這類鑑識軌跡被覆寫。
