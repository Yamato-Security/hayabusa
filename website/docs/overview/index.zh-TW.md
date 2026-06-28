# 關於 Hayabusa

Hayabusa 是由日本的 [Yamato Security](https://yamatosecurity.connpass.com/) 團隊所開發的 **Windows 事件記錄快速鑑識時間軸產生器** 與 **威脅獵捕工具**。
Hayabusa 在日文中意指 ["遊隼"](https://en.wikipedia.org/wiki/Peregrine_falcon)，之所以選用此名，是因為遊隼是世界上速度最快的動物，擅長獵捕且高度可訓練。
它以記憶體安全的 [Rust](https://www.rust-lang.org/) 撰寫，支援多執行緒以追求最快速度，並且是唯一完整支援 Sigma 規格（包含 v2 關聯規則）的開源工具。
Hayabusa 能夠處理解析 [上游 Sigma](https://github.com/SigmaHQ/sigma) 規則，不過，我們在 [hayabusa-rules 儲存庫](https://github.com/Yamato-Security/hayabusa-rules) 中所使用與託管的 Sigma 規則經過一些轉換，以便讓規則載入更具彈性並減少誤報。
您可以在 [sigma-to-hayabusa-converter 儲存庫](https://github.com/Yamato-Security/sigma-to-hayabusa-converter) 的 README 檔案中閱讀相關細節。
Hayabusa 可以在單一執行中的系統上進行即時分析，也可以透過從單一或多個系統收集記錄以進行離線分析，或是透過 [Velociraptor](https://docs.velociraptor.app/) 執行 [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) 來進行全企業範圍的威脅獵捕與事件應變。
輸出結果會彙整為單一的 CSV/JSON/JSONL 時間軸，方便在 [LibreOffice](https://www.libreoffice.org/)、[Timeline Explorer](https://ericzimmerman.github.io/#!index.md)、[Elastic Stack](../importing/elastic-stack.md)、[Timesketch](https://timesketch.org/) 等工具中輕鬆分析…
