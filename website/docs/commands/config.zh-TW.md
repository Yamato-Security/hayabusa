# 設定指令

## `config-critical-systems` 指令

此指令會自動嘗試尋找關鍵系統，例如網域控制站與檔案伺服器，並將它們加入 `./config/critical_systems.txt` 設定檔中，使所有警示提升一個等級。
它會搜尋 Security 4768（要求 Kerberos TGT）事件，以判斷是否為網域控制站。
它會搜尋 Security 5145（網路共用檔案存取）事件，以判斷是否為檔案伺服器。
任何加入 `critical_systems.txt` 檔案的主機名稱，其所有高於 low 的警示都會提升一個等級，最高為 `emergency` 等級。

```
Usage: hayabusa.exe config-critical-systems <INPUT> [OPTIONS]

Input:
  -d, --directory <DIR>  包含多個 .evtx 檔案的目錄
  -f, --file <FILE>      單一 .evtx 檔案的檔案路徑

Display Settings:
  -K, --no-color  停用彩色輸出
  -q, --quiet     安靜模式：不顯示啟動橫幅

General Options:
  -h, --help  顯示說明選單
```

### `config-critical-systems` 指令範例

* 在 `../hayabusa-sample-evtx` 目錄中搜尋網域控制站與檔案伺服器：

```
hayabusa.exe config-critical-systems -d ../hayabusa-sample-evtx"
```
