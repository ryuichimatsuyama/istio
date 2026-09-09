# Postmortem: PaymentService Availability Degradation

- 発生日: 2026-09-10
- 対象サービス: paymentservice
- 環境: Amazon EKS / Online Boutique
- 種別: Chaos Engineering
- 重大度: Page
- ステータス: Resolved

---

## 1. 概要

Chaos Meshを使用して、`checkoutservice → paymentservice` 間に
意図的なネットワーク遅延を注入した。

この影響によりPaymentServiceのAvailability SLOが悪化し、
Slothによって生成されたError Budget Burn Rate Alertが発火した。

AlertmanagerからPagerDutyへ通知され、
PagerDuty Incidentに設定されたRunbookを起点として障害調査を実施した。

調査の結果、paymentservice Podおよび依存先Redisに異常はなく、
分散トレースから `checkoutservice → paymentservice` 間の通信経路で
タイムアウトが発生していることを特定した。

また、調査過程でJaegerがインメモリストレージを使用していたため、
Jaeger再起動時に過去のTraceが消失するObservability上の問題も発見した。

---

## 2. 影響

障害発生中、PaymentServiceへの一部のgRPCリクエストが失敗した。

Grafanaでは以下の影響を確認した。

- PaymentService Availabilityの低下
- gRPC Error Ratioの上昇
- p95 Latencyの上昇
- Request Rateは継続しており、完全停止ではなかった

そのため、本障害はPaymentService全体の停止ではなく、
一部リクエストのタイムアウトによる可用性低下と判断した。

---

## 3. 検知

障害はSlothによって生成された
PaymentService Availability SLOのMulti-Window Burn Rate Alertによって
自動検知された。

検知フロー:

Prometheus
→ Sloth SLO / Burn Rate Alert
→ Alertmanager
→ PagerDuty
→ Runbook

PagerDutyでは以下のAlertを受信した。

- Alert: `PaymentserviceAvailability`
- Severity: `page`
- Category: `availability`

PagerDuty IncidentにはRunbookへのリンクが付与されており、
RunbookからGrafanaを使用して調査を開始した。

---

## 4. 調査

### 4.1 SLO / SLI

GrafanaのSLO Dashboardから以下を確認した。

- Availability低下
- gRPC Error Ratio上昇
- p95 Latency上昇

これにより、実際にユーザーリクエストへ影響が発生していることを確認した。

### 4.2 Workload Health

PaymentServiceのWorkload Healthを確認した。

- Ready Replicas: 100%
- Pod Restarts: 0
- CPU: 異常な上昇なし
- Memory: 異常な上昇なし

PaymentService Pod自体は正常に稼働していた。

このため、Pod Crash、CPU Saturation、Memory Exhaustionなどの
リソース起因の障害である可能性を除外した。

### 4.3 Dependency Health

PaymentServiceが依存するRedisを確認した。

- Redis Ready Replicas: 100%
- Redis Restarts: 0

Redis Podの停止や再起動は発生していなかった。

この時点で、PaymentServiceおよびRedisのPod障害ではない可能性が高いと判断した。

### 4.4 Distributed Trace

Jaegerで障害発生時間帯のTraceを調査した。

`checkoutservice` 側のPaymentService client span:

- Operation: `hipstershop.PaymentService/Charge`
- Duration: `163.71 ms`
- Status: `ERROR`
- gRPC Status: `UNAVAILABLE`
- Status Description: `upstream request timeout`
- Start: `07:59:30.192`

一方、`paymentservice` 側のserver span:

- Operation: `grpc.hipstershop.PaymentService/Charge`
- Duration: `6.73 ms`
- gRPC Status: `0 (OK)`
- Start: `07:59:31.194`

PaymentService内部の処理時間は6.73msと短く、
処理自体も正常終了していた。

一方でcheckoutservice側ではPaymentServiceへのリクエストが
`upstream request timeout` / `UNAVAILABLE` となっていた。

このため、PaymentServiceアプリケーション内部ではなく、
`checkoutservice → paymentservice` 間の通信経路で
障害が発生している可能性が高いと判断した。

---

## 5. Clock Skew Warningの分析

Jaegerでは以下のWarningが表示された。

`clock skew adjustment disabled; not applying calculated delta of -922.655012ms`

しかし、checkoutserviceとpaymentserviceのPod配置を確認したところ、
両サービスは同一Node上で稼働していた。

Node:

`i-035c2941ef68692c2`

また、client spanとserver spanの開始時刻の差は以下だった。

- Client Start: `07:59:30.192`
- Server Start: `07:59:31.194`
- Difference: 約 `1.002秒`

Chaos Meshで設定したNetwork Delayは `1秒` だったため、
観測された約1秒の差は注入したNetworkChaosと整合する。

したがって、このWarningは実際のNode間Clock Skewではなく、
ネットワーク遅延によってserver spanがclient timeout後に記録された結果、
JaegerがClock Skewの可能性を検出したものと判断した。

---

## 6. 根本原因

根本原因はChaos Meshによって意図的に注入した
`checkoutservice → paymentservice` 間のネットワーク遅延だった。

NetworkChaos:

- Source: `checkoutservice`
- Target: `paymentservice`
- Action: `delay`
- Latency: `1s`
- Correlation: `100%`
- Duration: `300s`
- Target Mode: `one`

ネットワーク遅延によってcheckoutservice側のリクエストが
upstream timeoutとなり、gRPC `UNAVAILABLE` が発生した。

その結果PaymentService Availabilityが低下し、
SLO Error Budgetの消費速度が閾値を超え、
Burn Rate Alertが発火した。

---

## 7. 復旧

NetworkChaosの終了後、サービス状態をGrafanaで確認した。

復旧判定ではPodがRunningであることだけではなく、
以下のSLI/SLOの回復を確認する。

- Availabilityの正常化
- gRPC Error Ratioの正常化
- p95 Latencyの正常化
- Error Budget Burn Rateの低下
- PagerDuty AlertのResolve

これらが正常化した時点でサービス復旧と判断する。

---

## 8. 調査中に発見したObservability Gap

今回のIncident Response中に、
障害発生時間帯のTraceがJaegerから取得できない問題が発生した。

調査したところJaeger Containerが障害発生後に再起動していた。

当時のJaegerはインメモリストレージを使用していたため、
プロセス再起動によって保存されていたTraceが消失していた。

これはアプリケーション障害とは別の、
Incident Investigationを妨げるObservability上の問題だった。

### 改善

JaegerのTrace Storageを以下の構成へ変更した。

Jaeger
→ Badger
→ PersistentVolumeClaim
→ EKS Auto Mode StorageClass
→ Amazon EBS gp3

構成:

- Storage Backend: Badger
- Persistent Volume: EBS gp3
- Capacity: 10Gi
- Access Mode: ReadWriteOnce
- StorageClass Provisioner: `ebs.csi.eks.amazonaws.com`
- Retention: 168h（7日）

これによりJaeger Pod/Containerが再起動しても、
過去のTraceを保持できる構成とした。

### 永続化の検証

Jaegerの永続化対応後、再起動前に生成されたTrace IDを記録し、
Jaeger Deploymentを再起動した。

再起動後に同一Trace IDを検索したところ、
再起動前のTraceを正常に取得できることを確認した。

これにより、Jaeger Pod/Containerの再起動後も
Badger + EBS上にTrace Dataが保持されることを検証した。

---

## 9. Action Items

| Action | Status |
|---|---|
| JaegerをIn-Memory StorageからBadgerへ変更 | Completed |
| BadgerをEBS gp3 PVCへ永続化 | Completed |
| Jaeger再起動後のTrace Persistence Test | Completed |
| PaymentService Availability Runbook整備 | Completed |
| PagerDutyからRunbookへのリンク設定 | Completed |
| Metrics → Trace → Logsの調査フロー検証 | Completed |
| Chaos Experiment再実行によるEnd-to-End検証 | Completed |

---

## 10. Lessons Learned

### SLOベースの検知が有効だった

PodのReady状態やCPU/Memoryだけでは今回の障害を検知できなかった。

PaymentService Podは正常に稼働していたにもかかわらず、
ユーザーリクエストではタイムアウトが発生していた。

Availability SLOとBurn Rate Alertを使用することで、
インフラリソースの状態ではなくサービスへの実際の影響を検知できた。

### Metricsだけでは根本原因を特定できなかった

Grafana Metricsから可用性低下、Error Ratio上昇、Latency上昇を確認できたが、
それだけではPaymentService内部の問題なのか、
サービス間通信の問題なのか判断できなかった。

Distributed Traceを確認することで、

checkoutservice:
`ERROR / UNAVAILABLE / upstream request timeout`

paymentservice:
`OK / 6.73ms`

という違いを確認でき、
障害箇所をサービス間通信経路まで絞り込むことができた。

### Observability Infrastructure自身にも信頼性が必要

Incident ResponseではTraceが重要な証拠になる。

しかしJaegerがインメモリストレージを使用していたため、
Jaeger自身の再起動によってIncident発生時のTraceが失われた。

Observability Stackも障害調査に必要なProduction Infrastructureの一部として扱い、
必要なTelemetry Dataを障害後も保持できるようにする必要がある。

---

## 11. 結論

今回のChaos Engineeringでは、
単にネットワーク障害を発生させるだけでなく、

Chaos Injection
→ SLOによる検知
→ PagerDuty Alert
→ Runbook
→ Metrics
→ Workload / Dependency Health
→ Distributed Trace
→ Root Cause Identification
→ Recovery Verification
→ Postmortem

というIncident Responseの一連のプロセスを検証した。

また、Incident Investigation中にJaegerのTrace Persistenceという
Observability上の弱点を発見し、Badger + EBSによる永続化へ改善した。

この実験により、障害を検知する仕組みだけでなく、
障害発生後に原因を調査し、復旧を確認し、
さらにObservability Platform自体を改善するところまで検証した。
