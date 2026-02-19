# MikroTik Exporter - Deployment

Technical documentation for deploying in production environments.

## Table of Contents

- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Prometheus](#prometheus)
- [Grafana](#grafana)
- [Security](#security)

---

## Docker

### Building the Image

```bash
# Multi-stage build (optimized size)
docker build -t mikrotik-exporter:latest .

# With version tag
docker build -t mikrotik-exporter:0.1.0 .
```

### Publishing to Registry

#### GitHub Container Registry

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
docker tag mikrotik-exporter:latest ghcr.io/jesof/mikrotik-exporter:latest
docker push ghcr.io/jesof/mikrotik-exporter:latest
```

#### Docker Hub

```bash
docker login
docker tag mikrotik-exporter:latest username/mikrotik-exporter:latest
docker push username/mikrotik-exporter:latest
```

### Running the Container

```bash
docker run -d \
  --name mikrotik-exporter \
  --restart=unless-stopped \
  -p 9090:9090 \
  -e ROUTERS_CONFIG='[{"name":"router1","address":"192.168.88.1:8728","username":"admin","password":"pass"}]' \
  -e COLLECTION_INTERVAL_SECONDS=30 \
  -e RUST_LOG=info \
  ghcr.io/jesof/mikrotik-exporter:latest
```

If `ROUTERS_CONFIG` is not set, you can use the legacy configuration
`ROUTEROS_ADDRESS/ROUTEROS_USERNAME/ROUTEROS_PASSWORD` (router name will be `default`).

---

## Kubernetes

### Quick Start

```bash
# Apply all manifests
kubectl apply -k k8s/

# Check status
kubectl get pods -n monitoring -l app=mikrotik-exporter
kubectl logs -n monitoring -l app=mikrotik-exporter -f
```

### Step-by-Step Deployment

#### 1. Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

#### 2. Secret (router configuration)

Edit `k8s/secret.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mikrotik-exporter-secret
  namespace: monitoring
type: Opaque
stringData:
  ROUTERS_CONFIG: |
    [
      {
        "name": "main-router",
        "address": "192.168.88.1:8728",
        "username": "admin",
        "password": "secure-password"
      }
    ]
```

```bash
kubectl apply -f k8s/secret.yaml
```

#### 3. ConfigMap (server settings)

```bash
kubectl apply -f k8s/configmap.yaml
```

#### 4. Deployment

```bash
kubectl apply -f k8s/deployment.yaml
```

#### 5. Service

```bash
kubectl apply -f k8s/service.yaml
```

#### 6. ServiceMonitor (for Prometheus Operator)

```bash
kubectl apply -f k8s/servicemonitor.yaml
```

### Verify Deployment

```bash
# Port-forward for testing
kubectl port-forward -n monitoring svc/mikrotik-exporter 9090:9090

# Check endpoints
curl http://localhost:9090/health
curl http://localhost:9090/metrics | grep mikrotik_system_info
```

### Update Configuration

```bash
# Edit Secret
kubectl edit secret mikrotik-exporter-secret -n monitoring

# Or apply modified file
kubectl apply -f k8s/secret.yaml

# Restart to apply changes
kubectl rollout restart deployment/mikrotik-exporter -n monitoring
kubectl rollout status deployment/mikrotik-exporter -n monitoring
```

### Update Image

```bash
# Rolling update to new version
kubectl set image deployment/mikrotik-exporter \
  mikrotik-exporter=ghcr.io/jesof/mikrotik-exporter:v0.2.1 \
  -n monitoring

# Check status
kubectl rollout status deployment/mikrotik-exporter -n monitoring

# Rollback if issues occur
kubectl rollout undo deployment/mikrotik-exporter -n monitoring
```

### Helm Chart (optional)

Create a basic chart:

```bash
mkdir -p helm/mikrotik-exporter
cd helm/mikrotik-exporter

cat > Chart.yaml <<EOF
apiVersion: v2
name: mikrotik-exporter
version: 0.1.0
appVersion: "0.1.0"
description: MikroTik Prometheus Exporter
type: application
EOF

cat > values.yaml <<EOF
image:
  repository: ghcr.io/jesof/mikrotik-exporter
  tag: latest
  pullPolicy: Always

resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 200m
    memory: 256Mi

routers:
  - name: main-router
    address: "192.168.88.1:8728"
    username: admin
    password: changeme

collectionInterval: 30
EOF

# Install
helm install mikrotik-exporter . -n monitoring --create-namespace
```

### Uninstall

```bash
# Via kubectl
kubectl delete -k k8s/

# Via Helm
helm uninstall mikrotik-exporter -n monitoring
```

---

## Prometheus

### Prometheus Operator (recommended)

ServiceMonitor automatically discovers the exporter:

```yaml
# k8s/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mikrotik-exporter
  namespace: monitoring
  labels:
    release: prometheus # Must match the label selector in Prometheus
spec:
  selector:
    matchLabels:
      app: mikrotik-exporter
  endpoints:
    - port: http
      interval: 30s
      path: /metrics
```

Verify:

```bash
kubectl get servicemonitor -n monitoring mikrotik-exporter
```

### Static Configuration

For standard Prometheus, add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "mikrotik-exporter"
    static_configs:
      - targets: ["mikrotik-exporter.monitoring.svc.cluster.local:9090"]
    scrape_interval: 30s
    scrape_timeout: 10s
    honor_labels: true
```

### Verify in Prometheus UI

```promql
# Check availability
up{job="mikrotik-exporter"}

# Check metrics
mikrotik_system_info
mikrotik_system_cpu_load
rate(mikrotik_interface_rx_bytes_total[5m])
```

### Alerts

```yaml
# PrometheusRule for alerts
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: mikrotik-exporter-alerts
  namespace: monitoring
spec:
  groups:
    - name: mikrotik-exporter
      interval: 30s
      rules:
        - alert: MikroTikExporterDown
          expr: up{job="mikrotik-exporter"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "MikroTik Exporter is unavailable"
            description: "Exporter has not responded for more than 5 minutes"

        - alert: MikroTikRouterDown
          expr: mikrotik_scrape_success_total == 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Router {{ $labels.router }} is unavailable"
            description: "Metrics collection from router {{ $labels.router }} has failed for more than 5 minutes"

        - alert: MikroTikHighCPU
          expr: mikrotik_system_cpu_load > 80
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High CPU usage on {{ $labels.router }}"
            description: "CPU load = {{ $value }}% on router {{ $labels.router }}"

        - alert: MikroTikLowMemory
          expr: (mikrotik_system_free_memory_bytes / mikrotik_system_total_memory_bytes) * 100 < 10
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Low memory on {{ $labels.router }}"
            description: "Less than 10% memory available on router {{ $labels.router }}"
```

---

## Grafana

### Official Dashboard

The dashboard is available in the official Grafana catalog:
- **ID:** `24875`
- **URL:** [https://grafana.com/grafana/dashboards/24875](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)

### Import Dashboard

#### Via UI

1. Grafana → Dashboards → Import
2. Upload `grafana/dashboard.json`
3. Select Prometheus datasource
4. Import

#### Via ConfigMap (Kubernetes)

```bash
# Create ConfigMap
kubectl create configmap mikrotik-dashboard \
  --from-file=dashboard.json=grafana/dashboard.json \
  -n monitoring

# Add label for auto-discovery
kubectl label configmap mikrotik-dashboard \
  grafana_dashboard=1 \
  -n monitoring
```

Grafana Helm chart configuration:

```yaml
# values.yaml
sidecar:
  dashboards:
    enabled: true
    label: grafana_dashboard
    labelValue: "1"
    folder: /tmp/dashboards
    searchNamespace: monitoring
```

#### Via Grafana API

```bash
GRAFANA_URL="http://grafana.monitoring.svc.cluster.local"
API_KEY="your-api-key"

curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d @grafana/dashboard.json \
  "${GRAFANA_URL}/api/dashboards/db"
```

### Dashboard Includes

- **System Info**: RouterOS version, device model, uptime
- **Resource Usage**: CPU load, memory usage
- **Network Traffic**: RX/TX per interface
- **Metrics Health**: Scrape duration, success rate, connection errors
- **Interface Status**: Table with status of all interfaces

---

## Security

### RouterOS User with Minimal Permissions

```bash
# On MikroTik router
/user group add name=monitoring policy=api,read
/user add name=prometheus group=monitoring password=secure-random-password
```

### Kubernetes Secret

```bash
# Create Secret from command line
kubectl create secret generic mikrotik-exporter-secret \
  --from-literal=ROUTERS_CONFIG='[{...}]' \
  -n monitoring

# Or from file
kubectl create secret generic mikrotik-exporter-secret \
  --from-file=ROUTERS_CONFIG=routers.json \
  -n monitoring
```

### Network Policies

Restrict network access:

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
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 9090
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 8728 # RouterOS API
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 53 # DNS
        - protocol: UDP
          port: 53
```

### TLS for RouterOS API (port 8729)

> ⚠️ Not yet implemented in the project (in roadmap)

---

## Troubleshooting

### Pod Won't Start

```bash
kubectl describe pod -n monitoring -l app=mikrotik-exporter
kubectl logs -n monitoring -l app=mikrotik-exporter --previous
```

### No Metrics in Prometheus

```bash
# Check ServiceMonitor
kubectl get servicemonitor -n monitoring -o yaml

# Check endpoints
kubectl get endpoints -n monitoring mikrotik-exporter

# Check in Prometheus UI: Status → Targets
```

### Router Connection Errors

```bash
# Logs with details
kubectl logs -n monitoring -l app=mikrotik-exporter -f

# Check network connectivity from pod
kubectl exec -it -n monitoring deployment/mikrotik-exporter -- sh
# In container only busybox (wget available, curl/jq not) — for curl/jq use sidecar
```

### Dashboard Shows No Data

1. Check that Prometheus datasource is configured
2. Check metrics in Prometheus UI
3. Check dashboard variables (Settings → Variables)
4. Make sure the correct router is selected in dropdown

---

## Additional Configuration

### Ingress for External Access

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mikrotik-exporter
  namespace: monitoring
spec:
  ingressClassName: nginx
  rules:
    - host: mikrotik-exporter.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: mikrotik-exporter
                port:
                  number: 9090
```

### HPA (Horizontal Pod Autoscaler)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mikrotik-exporter
  namespace: monitoring
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mikrotik-exporter
  minReplicas: 1
  maxReplicas: 3
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```
