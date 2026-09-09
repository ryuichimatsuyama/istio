# Runbook: Paymentservice Availability SLO

## 概要

このRunbookは、`paymentservice` の Availability SLO に対する
Error Budget Burn Rate Alert が発生した際の調査・復旧手順です。

一次調査はGrafanaを使用し、Metrics・Traces・Logsを相関させて原因を切り分けます。

---

## 対象アラート

- Alert: `PaymentserviceAvailability`
- Service: `paymentservice`
- SLO: `availability`
- Protocol: gRPC
- Page通知: PagerDuty
- Ticket通知: Slack

---

## 想定される影響

`paymentservice` のgRPCリクエスト失敗率が上昇し、
Checkout処理中の決済が失敗する可能性があります。

主な依存関係:

```text
checkoutservice
      ↓
paymentservice
      ↓
redis-payment
```

---

# 調査手順

## 1. Grafana SLO Dashboardを確認

PagerDuty IncidentからRunbookを開き、
Grafanaの `Online Boutique SLO` Dashboardを確認します。

Service:

```text
paymentservice
```

Dashboard:

```text
<GRAFANA_BASE_URL>/d/47085a4c-f58b-41c5-8bf5-556ec126baab/online-boutique-slo?var-service=paymentservice
```

最初に以下を確認します。

- Availability
- Error Budget Remaining
- Burn Rate

Error Budget Remaining:

```promql
slo:period_error_budget_remaining:ratio{
  sloth_service="paymentservice",
  sloth_slo="availability"
}
```

Error Budgetが急速に消費されている場合は、
ユーザー影響が継続している可能性があります。

---

## 2. Investigationを確認

Grafana Dashboardの `Investigation` Rowを確認します。

確認項目:

- Request Rate
- gRPC Error Ratio
- p95 Latency

### Request Rate

Alert発生時刻付近でリクエスト量が急増・急減していないか確認します。

### gRPC Error Ratio

gRPCエラー率が上昇していないか確認します。

参考PromQL:

```promql
sum(rate(istio_requests_total{
  reporter="source",
  destination_workload="paymentservice",
  request_protocol="grpc",
  grpc_response_status!="0"
}[5m]))
/
sum(rate(istio_requests_total{
  reporter="source",
  destination_workload="paymentservice",
  request_protocol="grpc"
}[5m]))
```

### p95 Latency

Alert発生時刻付近でレイテンシが悪化していないか確認します。

### 切り分けの目安

| 状態 | 疑う対象 |
|---|---|
| Error Ratioのみ上昇 | Application Error / Dependency |
| Latencyのみ上昇 | High Load / Dependency / Network |
| Request Rate急増 + Latency上昇 | Overload |
| Error Ratio + Latency上昇 | paymentservice / Dependency |
| Request Rate急減 | Upstream |

---

## 3. Workload Healthを確認

Grafana Dashboardの `Workload Health` Rowを確認します。

確認項目:

- Ready Replicas
- Pod Restarts (1h)
- CPU Usage
- Memory Usage

### Ready Replicas

正常:

```text
100%
```

100%未満の場合は、`paymentservice` Workloadの異常を疑います。

### Pod Restarts (1h)

正常:

```text
0
```

Alert発生時刻付近でRestartが発生している場合は、
Application Crash、OOM、Probe Failureなどの可能性があります。

### CPU Usage

Alert発生時刻付近でCPU Usageが急増していないか確認します。

### Memory Usage

Alert発生時刻付近でMemory Usageが急増または継続的に増加していないか確認します。

Workload Healthに異常がある場合は、
`paymentservice` 自体の問題を優先して調査します。

---

## 4. Dependency Healthを確認

Grafana Dashboardの `Dependency Health` Rowを確認します。

`paymentservice` の依存先:

```text
redis-payment
```

確認項目:

- Redis Ready
- Redis Restarts (1h)

### Redis Ready

正常:

```text
100%
```

100%未満の場合は、`redis-payment` の障害を疑います。

### Redis Restarts (1h)

正常:

```text
0
```

Restartが発生している場合は、
PagerDuty Alert発生時刻との相関を確認します。

`paymentservice` が正常で `redis-payment` に異常がある場合は、
Dependency障害としてRedis側を優先して調査します。

---

## 5. Traceを確認

Metricsだけで原因を特定できない場合はTraceを確認します。

GrafanaからAlert発生時刻付近のTraceを調査します。

主な確認項目:

- `PaymentService/Charge`
- Span Status
- Span Duration
- Upstream Service
- Downstream Service
- Error発生箇所
- Trace ID

特定リクエストのみの障害なのか、
`paymentservice` 全体の障害なのかを切り分けます。

---

## 6. Logsを確認

Traceに関連するLogsをLokiで確認します。

主な確認項目:

- gRPC Error
- Timeout
- Redis Connection Error
- Lock Acquisition Failure
- Idempotency Error
- Application Exception

Trace IDが取得できる場合は、
同一Trace IDのLogsを優先して確認します。

基本的な調査フロー:

```text
SLO Alert
   ↓
Metrics
   ↓
Trace
   ↓
Logs
```

---

# Recent Changeの確認

Alert発生直前に変更が行われていないか、
Argo CD / GitHubのDeployment履歴を確認します。

主な確認対象:

- Application Image
- Kubernetes Manifest
- Helm values
- Application Configuration
- Istio Configuration
- Redis Configuration

Alert発生時刻とDeployment時刻に相関がある場合は、
直近変更によるRegressionを疑います。

---

# Mitigation / Recovery

原因が直近のリリースにある場合は、
GitOpsの手順に従って正常なVersionへRollbackします。

GitをSource of Truthとして復旧し、
Desired Stateと実環境の整合性を維持します。

Dependency障害の場合は、
該当Dependencyの復旧手順またはRunbookに従います。

Platform障害が疑われる場合は、
Platform担当へエスカレーションします。

---

# 復旧確認

Mitigation実施後、Grafana SLO DashboardでSLIの回復を確認します。

確認項目:

- gRPC Error Ratioが正常値へ戻った
- Availabilityが回復した
- p95 Latencyが正常化した
- Ready Replicasが100%
- Pod Restartが継続していない
- redis-paymentがReady
- Error Budgetの急速な消費が停止した
- Sloth Burn Rate Alertが解消した

Workloadが正常に見えるだけではIncidentをCloseしません。

**SLIが回復し、ユーザー影響が解消したことを確認してからIncidentをCloseします。**

---

# エスカレーション条件

以下の場合はエスカレーションします。

- Error Budgetの急速な消費が継続している
- PagerDuty Alertが解消しない
- Rollback後もSLIが回復しない
- redis-paymentが回復しない
- 複数Serviceで同時にSLO違反が発生している
- Istio / EKS / NetworkなどPlatform側の障害が疑われる
- GrafanaのMetrics / Traces / Logsだけでは原因を特定できない

---

# Incident後

重大なIncidentの場合はPostmortemを作成します。

記録項目:

- Incident開始時刻
- Incident終了時刻
- 影響Service / SLO
- ユーザー影響
- Error Budget消費量
- Root Cause
- Mitigation
- Permanent Fix
- Follow-up Action
- Owner

---

# Incident Response Flow

```text
PagerDuty
    ↓
Runbook
    ↓
Grafana SLO Dashboard
    ↓
┌─────────────────────┐
│ SLO Overview        │
│ Investigation       │
│ Workload Health     │
│ Dependency Health   │
└─────────────────────┘
    ↓
Metrics
    ↓
Trace
    ↓
Logs
    ↓
Root Cause
    ↓
GitOps / Rollback / Escalation
    ↓
GrafanaでSLI回復確認
    ↓
Incident Close
