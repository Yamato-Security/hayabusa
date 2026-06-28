# 專案與生態系

## 相關專案

* [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) - 用於正確啟用 Windows 事件日誌的文件與腳本。
* [Hayabusa Encoded Rules](https://github.com/Yamato-Security/hayabusa-encoded-rules) - 與 Hayabusa Rules 儲存庫相同，但規則與設定檔被儲存於單一檔案中並經過 XOR 處理，以防止防毒軟體誤報。
* [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules) - Hayabusa 所使用的 Hayabusa 與精選 Sigma 偵測規則。
* [Hayabusa EVTX](https://github.com/Yamato-Security/hayabusa-evtx) - 維護更完善的 `evtx` crate 分支。
* [Hayabusa Sample EVTXs](https://github.com/Yamato-Security/hayabusa-sample-evtx) - 用於測試 hayabusa/sigma 偵測規則的範例 evtx 檔案。
* [Presentations](https://github.com/Yamato-Security/Presentations) - 我們針對自家工具與資源所進行演講的簡報。
* [Sigma to Hayabusa Converter](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) - 將上游基於 Windows 事件日誌的 Sigma 規則整理成更易於使用的形式。
* [Takajo](https://github.com/Yamato-Security/takajo) - hayabusa 結果的分析工具。
* [WELA (Windows Event Log Analyzer)](https://github.com/Yamato-Security/WELA) - 以 PowerShell 撰寫的 Windows 事件日誌分析工具。（已棄用，並由 Takajo 取代。）

## 使用 Hayabusa 的第三方專案

* [AllthingsTimesketch](https://github.com/blueteam0ps/AllthingsTimesketch) - 一個將 Plaso 與 Hayabusa 結果匯入 Timesketch 的 NodeRED 工作流程。
* [LimaCharlie](https://docs.limacharlie.io/docs/extensions-third-party-extensions-hayabusa) - 提供雲端式安全工具與基礎架構以滿足您的需求。 
* [OpenRelik](https://openrelik.org/) - 一個開放原始碼（Apache-2.0）平台，旨在簡化協作式數位鑑識調查。
* [Splunk4DFIR](https://github.com/mf1d3l/Splunk4DFIR) - 使用 Docker 快速啟動一個 splunk 執行個體，以在調查期間瀏覽日誌與工具輸出。
* [Velociraptor](https://github.com/Velocidex/velociraptor) - 一個使用 The Velociraptor Query Language (VQL) 查詢來收集主機端狀態資訊的工具。

## 其他 Windows 事件日誌分析工具與相關資源

* [APT-Hunter](https://github.com/ahmedkhlief/APT-Hunter) - 以 Python 撰寫的攻擊偵測工具。
* [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids) -  對數位鑑識與事件應變有用的 Event ID 資源彙整
* [Chainsaw](https://github.com/countercept/chainsaw) - 另一個以 Rust 撰寫、基於 sigma 的攻擊偵測工具。
* [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - 由 [Eric Conrad](https://twitter.com/eric_conrad) 以 Powershell 撰寫的攻擊偵測工具。
* [Epagneul](https://github.com/jurelou/epagneul) - Windows 事件日誌的圖形視覺化工具。
* [EventList](https://github.com/miriamxyra/EventList/) - 由 [Miriam Wiesner](https://github.com/miriamxyra) 製作，將安全基準事件 ID 對應至 MITRE ATT&CK。
* [Mapping MITRE ATT&CK with Window Event Log IDs](https://www.socinvestigation.com/mapping-mitre-attck-with-window-event-log-ids/) - 由 [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) 製作
* [EvtxECmd](https://github.com/EricZimmerman/evtx) - 由 [Eric Zimmerman](https://twitter.com/ericrzimmerman) 製作的 Evtx 剖析器。
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - 從未配置空間與記憶體映像中復原 EVTX 日誌檔案。
* [EvtxToElk](https://www.dragos.com/blog/industry-news/evtxtoelk-a-python-module-to-load-windows-event-logs-into-elasticsearch/) - 將 Evtx 資料傳送至 Elastic Stack 的 Python 工具。
* [EVTX ATTACK Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - 由 [SBousseaden](https://twitter.com/SBousseaden) 製作的 EVTX 攻擊範例事件日誌檔案。
* [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - 由 [Michel de CREVOISIER](https://twitter.com/mdecrevoisier) 製作、對應至 ATT&CK 的 EVTX 攻擊範例事件日誌檔案
* [EVTX parser](https://github.com/omerbenamram/evtx) - 我們所使用、由 [@OBenamram](https://twitter.com/obenamram) 撰寫的 Rust evtx 函式庫。
* [Grafiki](https://github.com/lucky-luk3/Grafiki) - Sysmon 與 PowerShell 日誌視覺化工具。
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - 由 [JPCERTCC](https://twitter.com/jpcert_en) 製作，用於視覺化登入以偵測橫向移動的圖形化介面。
* [NSA Windows Event Monitoring Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events) - NSA 關於應監控項目的指南。
* [RustyBlue](https://github.com/Yamato-Security/RustyBlue) - 由 Yamato Security 製作的 DeepBlueCLI Rust 移植版本。
* [Sigma](https://github.com/SigmaHQ/sigma) - 社群為基礎的通用 SIEM 規則。
* [SOF-ELK](https://github.com/philhagen/sof-elk) - 由 [Phil Hagen](https://twitter.com/philhagen) 製作、預先封裝並搭載 Elastic Stack 以匯入資料進行 DFIR 分析的 VM
* [so-import-evtx](https://docs.securityonion.net/en/2.3/so-import-evtx.html) - 將 evtx 檔案匯入 Security Onion。
* [SysmonTools](https://github.com/nshalabi/SysmonTools) - Sysmon 的設定與離線日誌視覺化工具。
* [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) - 由 [Eric Zimmerman](https://twitter.com/ericrzimmerman) 製作、最佳的 CSV 時間軸分析工具。
* [Windows Event Log Analysis - Analyst Reference](https://www.forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf) - 由 Forward Defense 的 Steve Anson 製作。
* [Zircolite](https://github.com/wagga40/Zircolite) - 以 Python 撰寫、基於 Sigma 的攻擊偵測工具。
