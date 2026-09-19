# MikroTik Exporter Deployment

This guide describes the current source tree. Review the [breaking migrations](CHANGELOG.md)
before upgrading a published deployment. Configure RouterOS API-SSL with a dedicated `read,api`
user and source restrictions as shown in [README.md](README.md#routeros-requirements).

## Docker

Build the current checkout locally:

```bash
bash build-docker.sh mikrotik-exporter:local
```

The script only builds an image; it does not start containers, contact routers, or publish images.
For production, choose a tested released image. Use an exact version or digest when an automated
patch update is not acceptable; `:0.5` is the convenient default for routine patch updates.

Published GHCR tags have different stability guarantees:

| Tag | Meaning | Recommended use |
| --- | --- | --- |
| `:0.5.0` | Exact release | Reproducible deployments without a digest |
| `:0.5` | Newest patch in the 0.5 line | Recommended default for routine updates |
| `:latest` | Newest stable release (moved only by a release) | Local evaluation, not production |
| `@sha256:...` | Exact published image manifest | Highest reproducibility and rollback safety |
| `sha-<full-sha>` | Immutable validated `main` commit image | Pinning a specific verified build |
| `:main` | Current checked `main` build | Development only |

Release tags (`:0.5.0`, `:0.5`) and `:latest` are promoted from the verified `main` image; they are
never rebuilt during a release. `:latest` is re-pointed only when a stable release is published, so
it never tracks an unreleased `main` commit.

Create a private `exporter.env` containing `SERVER_ADDR=0.0.0.0:9090`, the router JSON, and any
other settings from [.env.example](.env.example). Docker `--env-file` expects the JSON value
without the outer single quotes used by dotenv/shell examples. Mount a private CA bundle at the
path specified in `tls.ca_file` if needed:

```bash
docker run -d --name mikrotik-exporter --restart=unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:9090:9090 \
  --env-file ./exporter.env \
  --mount type=bind,src=/absolute/path/router-ca.pem,dst=/etc/mikrotik-exporter/router-ca.pem,readonly \
  mikrotik-exporter:local
```

Omit the CA mount and `ca_file` when using system roots. Keep environment files out of source
control; container administrators can inspect container environment variables. Restrict access to
the container runtime as well as the files.

## Kubernetes

### Deploy the Manifests

The repository provides plain manifests in `k8s/`, not a Helm chart. The Kustomize bundle includes
a ServiceMonitor and therefore requires the Prometheus Operator CRD. The base bundle intentionally
does not include a Secret; create it from a private secret manager or with `kubectl create secret`.
The image is pinned to the current release and should be overridden with an exact release or digest
in a private overlay when required.

For a deployment without the sample secret, create a private `routers.json` containing the JSON
array documented in the README, then:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl create secret generic mikrotik-exporter-secret \
  --from-file=ROUTERS_CONFIG=./routers.json -n monitoring
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

With Prometheus Operator installed, also apply:

```bash
kubectl apply -f k8s/servicemonitor.yaml
```

For an already customized private overlay, `kubectl apply -k /path/to/overlay` applies the complete
configuration. The supplied Deployment imports `SERVER_ADDR` from the ConfigMap and
`ROUTERS_CONFIG` from the Secret; add explicit `env` entries in your overlay for collection interval,
startup, or other settings. Merely adding those keys to the ConfigMap does not inject them.

If `tls.ca_file` is configured, add a read-only ConfigMap/Secret volume to your overlay and mount
the PEM bundle at that path. The supplied Deployment does not mount custom trust files. Ensure
UID 1000 can read them. `tls: {}` uses container system roots without a custom mount.

Use one replica per configured router set. Additional replicas independently poll every router
and expose separate counters; plan sharding or Prometheus deduplication before scaling out.

### Probes and Lifecycle

The Deployment uses `/live` for startup/liveness and `/ready` for readiness on the named
`metrics` port. `/ready` stays false during optional startup checks and becomes false during
shutdown. `/health` is a diagnostic endpoint for router freshness and can return 503 during router
outages while the exporter is correctly serving its failure metrics. Do not use it as a process probe.

```bash
kubectl rollout status deployment/mikrotik-exporter -n monitoring
kubectl logs -n monitoring -l app=mikrotik-exporter
kubectl port-forward -n monitoring svc/mikrotik-exporter 9090:9090
```

From another terminal:

```bash
curl --fail http://localhost:9090/live
curl --fail http://localhost:9090/ready
curl http://localhost:9090/health
curl --fail http://localhost:9090/metrics
```

Configuration is loaded at startup. After updating the Secret, environment, or CA mount:

```bash
kubectl rollout restart deployment/mikrotik-exporter -n monitoring
kubectl rollout status deployment/mikrotik-exporter -n monitoring
```

Update image digests through your overlay/deployment pipeline. Check the rollout and freshness
metrics after each update. Keep the previous compatible image/configuration available for rollback.

## Prometheus

### ServiceMonitor

The endpoint port must match **the Service port name `metrics`**. Match the ServiceMonitor's
labels and namespace to your Prometheus resource's selection policy:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mikrotik-exporter
  namespace: monitoring
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: mikrotik-exporter
  endpoints:
    - port: metrics
      interval: 30s
      scrapeTimeout: 10s
      path: /metrics
```

### Static Configuration

```yaml
scrape_configs:
  - job_name: mikrotik-exporter
    static_configs:
      - targets: ["mikrotik-exporter.monitoring.svc.cluster.local:9090"]
    scrape_interval: 30s
    scrape_timeout: 10s
```

### Alerts

Use freshness timestamps, including their zero/never-success state, rather than testing a lifetime
success counter for zero. The example uses a 120-second freshness threshold for the default
30-second collection interval; adjust it for your interval and expected router latency. The
`for` duration is additional to that threshold. Match the PrometheusRule's labels to your operator
selection policy; the `job` label below assumes the static configuration above (adapt for discovery).

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: mikrotik-exporter-alerts
  namespace: monitoring
spec:
  groups:
    - name: mikrotik-exporter
      rules:
        - alert: MikroTikExporterDown
          expr: up{job="mikrotik-exporter"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "MikroTik exporter is unavailable"
        - alert: MikroTikRouterCollectionStale
          expr: >-
            (mikrotik_scrape_last_success_timestamp_seconds == 0)
            or (time() - mikrotik_scrape_last_success_timestamp_seconds > 120)
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "No recent complete collection from {{ $labels.router }}"
        - alert: MikroTikGroupCollectionStale
          expr: >-
            (mikrotik_group_last_success_timestamp_seconds == 0)
            or (time() - mikrotik_group_last_success_timestamp_seconds > 120)
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Group {{ $labels.group }} is stale on {{ $labels.router }}"
        - alert: MikroTikConntrackSeriesOmitted
          expr: mikrotik_conntrack_dropped_series > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Conntrack series cap reached on {{ $labels.router }}"
        - alert: MikroTikHighCPU
          expr: mikrotik_system_cpu_load_ratio > 0.8
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High CPU load on {{ $labels.router }}"
            description: "CPU utilization ratio is {{ $value }} (0–1)."
        - alert: MikroTikLowMemory
          expr: mikrotik_system_free_memory_bytes / mikrotik_system_total_memory_bytes < 0.1
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Less than 10% memory free on {{ $labels.router }}"
```

Freshness alerts detect router/group collection problems; `up` detects scrape failures. If a target
is removed from discovery entirely, an inventory-based absent-target alert is also needed.
Resource values can remain stale during failures; interpret resource alerts together with freshness.

## Grafana

Import `grafana/dashboard.json` from the same revision as the exporter and select your Prometheus
datasource. For unreleased versions, use this file rather than assuming the
[catalog dashboard 24875](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)
already has the new metric names and units. CPU is a ratio, durations are seconds, and metadata
joins should select current info (`== 1`).

For a Grafana dashboard sidecar configured to watch `grafana_dashboard=1` in `monitoring`:

```bash
kubectl create configmap mikrotik-dashboard \
  --from-file=dashboard.json=grafana/dashboard.json -n monitoring
kubectl label configmap mikrotik-dashboard grafana_dashboard=1 -n monitoring
```

## Security

- Use verified RouterOS TLS, a dedicated `read,api` user, and an exporter source `/32` restriction
  on both the user/service and router firewall. Plaintext API exposes credentials.
- Keep `/metrics`, `/health`, `/live`, and `/ready` on a private network. Use an authenticated TLS
  reverse proxy when access crosses a trust boundary; the exporter has no HTTP auth or TLS listener.
- Use a secret manager or protected configuration files. Do not paste secrets in shell commands,
  issue reports, or Git. Review metric labels and logs for private topology before sharing.
- Run non-root with a read-only root filesystem and dropped capabilities, as the Deployment does.

Example NetworkPolicy for one TLS router at `192.0.2.1` (replace addresses and selectors). Your CNI
must enforce NetworkPolicy; confirm source NAT, DNS, and monitoring namespace behavior in your cluster:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mikrotik-exporter
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: mikrotik-exporter
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - protocol: TCP
          port: 9090
  egress:
    - to:
        - ipBlock:
            cidr: 192.0.2.1/32
      ports:
        - protocol: TCP
          port: 8729
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

Node-local DNS may require a different DNS egress rule. Prefer a Prometheus pod selector as well as
the namespace selector when its labels are known. See [SECURITY.md](SECURITY.md) for reporting.

## Troubleshooting

- **Startup exits:** validate JSON, duplicate names, integer ranges, IP bind address, and strict-mode
  requirements. Invalid configuration is an error, not a fallback to another router.
- **TLS connection fails:** verify the configured `tls` object, certificate identity, chain, clock,
  CA mount path/permissions, and API-SSL certificate. Do not disable verification to work around it.
- **Ready but degraded:** inspect group success/completeness and freshness, RouterOS permissions,
  feature availability, and logs. `/health` does not actively probe the router.
- **Unexpected stale/zero values:** required malformed numeric fields fail the fetch; inspect debug
  logs and group status. Review logs for sensitive topology before sharing them.
- **Prometheus has no target:** check ServiceMonitor selection, the `metrics` Service port name,
  Endpoints/EndpointSlices, NetworkPolicy, and Prometheus Targets.
- **Grafana has no data:** check datasource, router selection, metric migration, and matching dashboard
  revision. WireGuard bytes are gauges and conntrack may be capped.

Use `kubectl describe pod` and `kubectl logs --previous` for startup failures. Ordinary local tests
use loopback fixtures; contact real routers only with the explicit ignored-test command in
[CONTRIBUTING.md](CONTRIBUTING.md#testing).
