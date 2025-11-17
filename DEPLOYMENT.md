# MikroTik Exporter - Развертывание

Техническая документация по развертыванию в production-окружениях.

## Содержание

- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Prometheus](#prometheus)
- [Grafana](#grafana)
- [Безопасность](#безопасность)

---

## Docker

### Сборка образа

```bash
# Multi-stage build (оптимизированный размер)
docker build -t mikrotik-exporter:latest .

# С указанием версии
docker build -t mikrotik-exporter:0.1.0 .
```

### Публикация в Registry

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

### Запуск контейнера

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

---

## Kubernetes

### Быстрый старт

```bash
# Применить все манифесты
kubectl apply -k k8s/

# Проверка статуса
kubectl get pods -n monitoring -l app=mikrotik-exporter
kubectl logs -n monitoring -l app=mikrotik-exporter -f
```

### Пошаговое развертывание

#### 1. Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

#### 2. Secret (конфигурация роутеров)

Отредактируйте `k8s/secret.yaml`:

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

#### 3. ConfigMap (настройки сервера)

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

#### 6. ServiceMonitor (для Prometheus Operator)

```bash
kubectl apply -f k8s/servicemonitor.yaml
```

### Проверка развертывания

```bash
# Port-forward для тестирования
kubectl port-forward -n monitoring svc/mikrotik-exporter 9090:9090

# Проверка endpoints
curl http://localhost:9090/health
curl http://localhost:9090/metrics | grep mikrotik_system_info
```

### Обновление конфигурации

```bash
# Редактирование Secret
kubectl edit secret mikrotik-exporter-secret -n monitoring

# Или применение измененного файла
kubectl apply -f k8s/secret.yaml

# Перезапуск для применения изменений
kubectl rollout restart deployment/mikrotik-exporter -n monitoring
kubectl rollout status deployment/mikrotik-exporter -n monitoring
```

### Обновление образа

```bash
# Rolling update на новую версию
kubectl set image deployment/mikrotik-exporter \
  mikrotik-exporter=ghcr.io/jesof/mikrotik-exporter:v0.2.0 \
  -n monitoring

# Проверка статуса
kubectl rollout status deployment/mikrotik-exporter -n monitoring

# Откат при проблемах
kubectl rollout undo deployment/mikrotik-exporter -n monitoring
```

### Helm Chart (опционально)

Создание базового chart:

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

# Установка
helm install mikrotik-exporter . -n monitoring --create-namespace
```

### Удаление

```bash
# Через kubectl
kubectl delete -k k8s/

# Через Helm
helm uninstall mikrotik-exporter -n monitoring
```

---

## Prometheus

### Prometheus Operator (рекомендуется)

ServiceMonitor автоматически обнаруживает exporter:

```yaml
# k8s/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mikrotik-exporter
  namespace: monitoring
  labels:
    release: prometheus # Должен совпадать с label selector в Prometheus
spec:
  selector:
    matchLabels:
      app: mikrotik-exporter
  endpoints:
    - port: http
      interval: 30s
      path: /metrics
```

Проверка:

```bash
kubectl get servicemonitor -n monitoring mikrotik-exporter
```

### Статическая конфигурация

Для обычного Prometheus добавьте в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "mikrotik-exporter"
    static_configs:
      - targets: ["mikrotik-exporter.monitoring.svc.cluster.local:9090"]
    scrape_interval: 30s
    scrape_timeout: 10s
    honor_labels: true
```

### Проверка в Prometheus UI

```promql
# Проверка доступности
up{job="mikrotik-exporter"}

# Проверка метрик
mikrotik_system_info
mikrotik_system_cpu_load
rate(mikrotik_interface_rx_bytes[5m])
```

### Алерты

```yaml
# PrometheusRule для алертов
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
            summary: "MikroTik Exporter недоступен"
            description: "Exporter не отвечает более 5 минут"

        - alert: MikroTikRouterDown
          expr: mikrotik_scrape_success == 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Роутер {{ $labels.router }} недоступен"
            description: "Сбор метрик с роутера {{ $labels.router }} не производится более 5 минут"

        - alert: MikroTikHighCPU
          expr: mikrotik_system_cpu_load > 80
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Высокая загрузка CPU на {{ $labels.router }}"
            description: "CPU load = {{ $value }}% на роутере {{ $labels.router }}"

        - alert: MikroTikLowMemory
          expr: (mikrotik_system_free_memory_bytes / mikrotik_system_total_memory_bytes) * 100 < 10
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Мало свободной памяти на {{ $labels.router }}"
            description: "Свободно менее 10% памяти на роутере {{ $labels.router }}"
```

---

## Grafana

### Импорт Dashboard

#### Через UI

1. Grafana → Dashboards → Import
2. Upload `grafana/dashboard.json`
3. Выберите Prometheus datasource
4. Import

#### Через ConfigMap (Kubernetes)

```bash
# Создание ConfigMap
kubectl create configmap mikrotik-dashboard \
  --from-file=dashboard.json=grafana/dashboard.json \
  -n monitoring

# Добавление label для автообнаружения
kubectl label configmap mikrotik-dashboard \
  grafana_dashboard=1 \
  -n monitoring
```

Конфигурация Grafana Helm chart:

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

#### Через Grafana API

```bash
GRAFANA_URL="http://grafana.monitoring.svc.cluster.local"
API_KEY="your-api-key"

curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d @grafana/dashboard.json \
  "${GRAFANA_URL}/api/dashboards/db"
```

### Dashboard включает

- **System Info**: Версия RouterOS, модель устройства, uptime
- **Resource Usage**: CPU load, memory usage
- **Network Traffic**: RX/TX по интерфейсам
- **Metrics Health**: Scrape duration, success rate, ошибки подключения
- **Interface Status**: Таблица со статусами всех интерфейсов

---

## Безопасность

### RouterOS пользователь с минимальными правами

```bash
# На MikroTik роутере
/user group add name=monitoring policy=api,read
/user add name=prometheus group=monitoring password=secure-random-password
```

### Kubernetes Secret

```bash
# Создание Secret из командной строки
kubectl create secret generic mikrotik-exporter-secret \
  --from-literal=ROUTERS_CONFIG='[{...}]' \
  -n monitoring

# Или из файла
kubectl create secret generic mikrotik-exporter-secret \
  --from-file=ROUTERS_CONFIG=routers.json \
  -n monitoring
```

### Network Policies

Ограничение сетевого доступа:

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

### TLS для RouterOS API (порт 8729)

> ⚠️ Пока не реализовано в проекте (в roadmap)

---

## Troubleshooting

### Pod не запускается

```bash
kubectl describe pod -n monitoring -l app=mikrotik-exporter
kubectl logs -n monitoring -l app=mikrotik-exporter --previous
```

### Нет метрик в Prometheus

```bash
# Проверка ServiceMonitor
kubectl get servicemonitor -n monitoring -o yaml

# Проверка endpoints
kubectl get endpoints -n monitoring mikrotik-exporter

# Проверка в Prometheus UI: Status → Targets
```

### Ошибки подключения к роутерам

```bash
# Логи с подробностями
kubectl logs -n monitoring -l app=mikrotik-exporter -f

# Проверка сетевой доступности из pod
kubectl exec -it -n monitoring deployment/mikrotik-exporter -- sh
# В контейнере нет дополнительных утилит, используйте busybox sidecar
```

### Dashboard не показывает данные

1. Проверьте, что Prometheus datasource настроен
2. Проверьте наличие метрик в Prometheus UI
3. Проверьте переменные dashboard (Settings → Variables)
4. Убедитесь, что выбран правильный роутер в dropdown

---

## Дополнительные настройки

### Ingress для внешнего доступа

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
