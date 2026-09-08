
# Runbook: Paymentservice Availability SLO

## 概要

このRunbookは、`paymentservice` の Availability SLO に対する
Error Budget Burn Rate Alert が発生した際の調査・復旧手順です。

原則として、一次調査はGrafanaで実施します。

Grafanaでは以下を確認できます。

- SLO / Error Budget
- Request Rate / Error Ratio / Latency
- paymentserviceのWorkload Health
- redis-paymentのDependency Health
- Trace
- Logs

Grafanaだけでは原因を特定できない場合に、`kubectl` などを使用して
追加調査を実施します。

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

`paymentservice` のgRPCリクエスト失敗率が上昇している状態です。

Checkout処理から決済処理を実行できず、
注文処理が失敗する可能性があります。

主な依存関係:

```text
checkoutservice
      ↓
paymentservice
      ↓
redis-payment
````

---

# 調査手順

## 1. Grafana SLO Dashboardを確認

PagerDuty AlertからGrafanaの `availability` Dashboardを開き、
Serviceを `paymentservice` に設定します。

Dashboard:

```text
<GRAFANA_BASE_URL>/d/47085a4c-f58b-41c5-8bf5-556ec126baab/online-boutique-slo?var-service=paymentservice
```

最初に以下を確認します。

### Availability

AvailabilityがSLO Objectiveを下回っていないか確認します。

### Error Budget Remaining

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

### Request Rate

リクエスト量が通常時と比較して急増・急減していないか確認します。

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

エラー率だけでなく、レイテンシが同時に悪化していないか確認します。

判断例:

| 状態                         | 疑う対象                    |
| -------------------------- | ----------------------- |
| Error Ratioのみ上昇            | アプリケーションエラー、依存サービス      |
| Latencyのみ上昇                | 高負荷、依存サービス、ネットワーク       |
| Request Rate急増 + Latency上昇 | 過負荷                     |
| Error Ratio + Latency上昇    | paymentserviceまたは依存サービス |
| Request Rate急減             | upstream側の障害も確認         |

---

## 3. Workload Healthを確認

Grafana Dashboardの `Workload Health` Rowを確認します。

### Ready Replicas

`100%` になっていることを確認します。

100%未満の場合は、paymentservice Podが正常にReadyになっていない可能性があります。

### Pod Restarts (1h)

直近1時間にPod Restartが発生していないか確認します。

通常:

```text
0
```

Restartが発生している場合は、Crash / OOM / Probe Failureなどを疑います。

### CPU Usage

Alert発生時刻付近でCPU Usageが急増していないか確認します。

### Memory Usage

Alert発生時刻付近でMemory Usageが継続的に増加していないか確認します。

Workload Healthに異常がある場合は、paymentservice自体の問題を優先して調査します。

---

## 4. Dependency Healthを確認

Grafana Dashboardの `Dependency Health` Rowを確認します。

paymentserviceは以下のRedisを利用します。

```text
redis-payment
```

### Redis Ready

正常:

```text
100%
```

100%未満の場合は、redis-paymentの障害を疑います。

### Redis Restarts (1h)

正常:

```text
0
```

Restartが発生している場合は、Alert発生時刻との相関を確認します。

paymentserviceが正常でもredis-paymentに異常がある場合は、
依存サービス障害としてRedis側を優先して調査します。

---

## 5. Traceを確認

Metricsだけでは原因を特定できない場合はTraceを確認します。

GrafanaのTrace ExemplarsまたはJaegerから、
Alert発生時刻付近のTraceを調査します。

主に以下を確認します。

* `PaymentService/Charge`
* Span Status
* Span Duration
* upstream service
* downstream service
* Error発生箇所
* Trace ID

特定のリクエストだけが失敗しているのか、
paymentservice全体で問題が発生しているのかを切り分けます。

---

## 6. Logsを確認

Traceから関連するLogsへ遷移し、Lokiで調査します。

主に以下を確認します。

* gRPC error
* timeout
* Redis connection error
* lock acquisition failure
* idempotency error
* exception

Trace IDが取得できている場合は、
同一Trace IDのLogsを優先して確認します。

理想的な調査フロー:

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

# 追加調査

## Grafanaで原因を特定できない場合

Grafanaで原因を特定できない場合のみ、
Kubernetesを直接確認します。

### Pod詳細

```bash
kubectl get pods -n microservices-demo -l app=paymentservice -o wide
```

```bash
kubectl describe pod -n microservices-demo <POD_NAME>
```

確認項目:

* CrashLoopBackOff
* OOMKilled
* Probe Failure
* Scheduling Failure
* Image Pull Failure

### Kubernetes Events

```bash
kubectl get events -n microservices-demo \
  --sort-by='.lastTimestamp' | tail -50
```

### Redis接続確認

```bash
POD=$(kubectl get pod -n microservices-demo \
  -l app=paymentservice \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n microservices-demo "$POD" -- \
  node -e "
const net=require('net');
const s=net.connect(6379,'redis-payment',()=>{
  console.log('CONNECTED');
  s.end();
});
s.on('error',e=>{
  console.error(e);
  process.exit(1);
});
"
```

正常:

```text
CONNECTED
```

---

# Recent Changeの確認

Alert発生直前にDeploymentや設定変更が行われていないか確認します。

確認対象:

* Application Image
* Kubernetes Manifest
* Helm values
* ConfigMap / Secret
* Istio Configuration
* Redis Configuration

必要に応じてArgo CD / GitHubのDeployment履歴と
Alert発生時刻を比較します。

---

# Mitigation / Recovery

原因が直近のリリースにある場合は、
GitOpsの手順に従って正常なVersionへRollbackします。

原則として、本番Manifestを恒久的に

```bash
kubectl edit
```

で変更しません。

GitをSource of Truthとして復旧します。

緊急対応としてKubernetesを直接操作した場合は、
復旧後にGit上のDesired Stateとの整合性を確認します。

---

# 復旧確認

Mitigation実施後、Grafana SLO Dashboardで以下を確認します。

* gRPC Error Ratioが正常値へ戻った
* Availabilityが回復した
* p95 Latencyが正常化した
* Ready Replicasが100%
* Pod Restartが継続していない
* redis-paymentがReady
* Error Budgetの急速な消費が停止した
* Sloth Burn Rate Alertが解消した

Podが `Running` になっただけではIncidentをCloseしません。

**SLIが回復していることを確認してからIncidentをCloseします。**

---

# エスカレーション条件

以下の場合は追加のエスカレーションを検討します。

* Error Budgetの急速な消費が継続
* PagerDuty Alertが解消しない
* Rollback後もSLIが回復しない
* redis-paymentが回復しない
* 複数Serviceで同時にSLO違反が発生
* Istio / EKS / NetworkなどPlatform側の障害が疑われる

---

# Incident後

重大なIncidentの場合はPostmortemを作成します。

最低限、以下を記録します。

* Incident開始時刻
* Incident終了時刻
* 影響Service / SLO
* ユーザー影響
* Error Budget消費量
* Root Cause
* Mitigation
* Permanent Fix
* Follow-up Action
* Owner
