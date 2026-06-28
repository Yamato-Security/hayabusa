# 主要目標

## 威脅狩獵與企業範圍的 DFIR

Hayabusa 目前擁有超過 4000 條 Sigma 規則以及超過 170 條 Hayabusa 內建偵測規則，並且持續定期新增更多規則。
它可以搭配 [Velociraptor](https://docs.velociraptor.app/) 的 [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/)，免費用於企業範圍的主動威脅狩獵以及 DFIR（數位鑑識與事件回應）。
透過結合這兩款開源工具，當環境中沒有建置 SIEM 時，你基本上可以回溯性地重現一套 SIEM。
你可以觀看 [Eric Capuano](https://twitter.com/eric_capuano) 的 Velociraptor 逐步教學影片[在此](https://www.youtube.com/watch?v=Q1IoGX--814)來了解如何進行。

## 快速產生鑑識時間軸

Windows 事件日誌分析傳統上一直是一個非常冗長且繁瑣的過程，因為 Windows 事件日誌 1) 採用難以分析的資料格式，且 2) 大部分資料都是雜訊，對調查並無用處。
Hayabusa 的目標是只擷取出有用的資料，並以盡可能簡潔、易於閱讀的格式呈現，不僅讓受過專業訓練的分析師可以使用，任何 Windows 系統管理員也能使用。
Hayabusa 希望能讓分析師相較於傳統的 Windows 事件日誌分析，用 20% 的時間完成 80% 的工作。

![DFIR 時間軸](../assets/doc/DFIR-TimelineCreation-EN.png)
