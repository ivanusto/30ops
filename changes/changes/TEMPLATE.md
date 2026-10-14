---
id: CR-YYYY-NNNN
title: 一句話，動詞開頭，說改什麼
status: draft
type: standard
risk: low
requester: 
implementer: 
approver: 
agent: 
assets:
  - <asset>/<component>
window_start: 
window_end: 
silence: 
tags: 
---

## 目的

為什麼要改。引用觸發它的東西：哪一條告警、哪一列 `eol/assets.tsv`、哪一篇的待辦。

## 影響

`agent:` 有寫的話（例如 `agent:ops`），那個代理程式在這張單的窗內可以透過 onprem-agent-gate 碰 `assets` 列的資產，唯讀的隨時可以，可逆的要窗內且 begin 之後，不可逆的還要人核准。沒寫就是沒有任何代理程式可以。這一段要寫代理程式預期做什麼、不能做什麼。

改的期間誰會感覺到什麼。哪些告警預期會響（寫進上面的 `silence`），哪些服務會停多久，單點失效的窗在哪裡。

## 步驟

逐條，可以照著敲。每一條寫在哪台機器上執行。第一條與最後一條是 `change-mark.sh begin` 與 `end`。

## 驗證

改完怎麼知道成功。命令與預期輸出，與 Day 19 到 25 的哪個指標或查詢對得起來。

## 回退

出錯時怎麼回到改之前。要能在窗內做完。沒有回退方法的變更要在這裡寫「無，原因是…」，並把 `risk` 設成 `high`。

回退若會讓某個資料流中斷（日誌、指標、備份、同步），寫出中斷的邊界怎麼找、缺的資料怎麼補。例如 CR-2026-0011 回退收集端時 515 關了 10 分鐘，邊界是比對 60F 記憶體日誌與收集端，缺的那一筆以 `fortigate-export-load.py --source backfill` 補回。

## 紀錄

執行時填。

- begin: 
- end: 
- result: 
- evidence: 
- followups: 
