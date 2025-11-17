# MikroTik Exporter - Примеры использования

Практические примеры развертывания для различных сценариев.

## Содержание

- [Docker Compose - Production Stack](#docker-compose---production-stack)
- [Docker - Standalone](#docker---standalone)
- [Kubernetes - Multi-Router](#kubernetes---multi-router)
- [Prometheus Queries](#prometheus-queries)

---

## Docker Compose - Production Stack

Полный стек мониторинга с Prometheus, Grafana и Alertmanager.

### docker-compose.yml

```yaml
version: "3.8"

services:
  mikrotik-exporter:
    image: ghcr.io/jesof/mikrotik-exporter:latest
    container_name: mikrotik-exporter
    restart: unless-stopped
    ports:
      - "9090:9090"
    environment:
      - SERVER_ADDR=0.0.0.0:9090
      - COLLECTION_INTERVAL_SECONDS=30
      - RUST_LOG=info
      - ROUTERS_CONFIG=[
        {"name":"office-main","address":"192.168.88.1:8728","username":"prometheus","password":"secure-pass-1"},
        {"name":"office-backup","address":"192.168.88.2:8728","username":"prometheus","password":"secure-pass-2"},
        {"name":"warehouse","address":"192.168.89.1:8728","username":"prometheus","password":"secure-pass-3"}
        ]
    networks:
      - monitoring
    healthcheck:
      test:
        [
          "CMD",
          "wget",
          "--quiet",
          "--tries=1",
          "--spider",
          "http://localhost:9090/health",
        ]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=30d"
      - "--web.console.libraries=/etc/prometheus/console_libraries"
      - "--web.console.templates=/etc/prometheus/consoles"
      - "--web.enable-lifecycle"
    networks:
      - monitoring
    depends_on:
      - mikrotik-exporter

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboard.json:/var/lib/grafana/dashboards/mikrotik.json:ro
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=
    networks:
      - monitoring
    depends_on:
      - prometheus

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    restart: unless-stopped
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager/config.yml:/etc/alertmanager/config.yml:ro
      - alertmanager-data:/alertmanager
    command:
      - "--config.file=/etc/alertmanager/config.yml"
      - "--storage.path=/alertmanager"
    networks:
      - monitoring

volumes:
  prometheus-data:
  grafana-data:
  alertmanager-data:

networks:
  monitoring:
    driver: bridge
```

### prometheus/prometheus.yml

```yaml
global:
  scrape_interval: 30s
  evaluation_interval: 30s
  external_labels:
    cluster: "production"
    environment: "prod"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093

rule_files:
  - "/etc/prometheus/alerts.yml"

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "mikrotik-exporter"
    static_configs:
      - targets: ["mikrotik-exporter:9090"]
    scrape_interval: 30s
    scrape_timeout: 10s
    honor_labels: true
```

### prometheus/alerts.yml

```yaml
groups:
  - name: mikrotik
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
          description: "Не удается собрать метрики с {{ $labels.router }}"

      - alert: MikroTikHighCPU
        expr: mikrotik_system_cpu_load > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Высокая загрузка CPU на {{ $labels.router }}"
          description: "CPU load = {{ $value }}%"

      - alert: MikroTikLowMemory
        expr: (mikrotik_system_free_memory_bytes / mikrotik_system_total_memory_bytes) * 100 < 10
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Мало памяти на {{ $labels.router }}"
          description: "Свободно {{ $value | humanizePercentage }} памяти"

      - alert: MikroTikInterfaceDown
        expr: mikrotik_interface_running == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Интерфейс {{ $labels.interface }} на {{ $labels.router }} не работает"
          description: "Интерфейс {{ $labels.interface }} в состоянии down"
```

### grafana/provisioning/datasources/prometheus.yml

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
```

### grafana/provisioning/dashboards/mikrotik.yml

```yaml
apiVersion: 1

providers:
  - name: "MikroTik"
    orgId: 1
    folder: ""
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
```

### alertmanager/config.yml

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ["alertname", "cluster", "service"]
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: "default"

receivers:
  - name: "default"
    email_configs:
      - to: "alerts@example.com"
        from: "alertmanager@example.com"
        smarthost: "smtp.example.com:587"
        auth_username: "alertmanager@example.com"
        auth_password: "password"

inhibit_rules:
  - source_match:
      severity: "critical"
    target_match:
      severity: "warning"
    equal: ["alertname", "cluster", "service"]
```

### Запуск

```bash
# Создать структуру директорий
mkdir -p prometheus grafana/provisioning/{datasources,dashboards} alertmanager

# Скопировать dashboard
cp grafana/dashboard.json ./grafana/

# Запустить стек
docker-compose up -d

# Проверка логов
docker-compose logs -f mikrotik-exporter

# Остановка
docker-compose down

# Удаление с данными
docker-compose down -v
```

### Доступ

- **MikroTik Exporter**: http://localhost:9090/metrics
- **Prometheus**: http://localhost:9091
- **Grafana**: http://localhost:3000 (admin/admin)
- **Alertmanager**: http://localhost:9093

---

## Docker - Standalone

### Простой запуск (один роутер)

```bash
docker run -d \
  --name mikrotik-exporter \
  --restart=unless-stopped \
  -p 9090:9090 \
  -e SERVER_ADDR=0.0.0.0:9090 \
  -e ROUTERS_CONFIG='[{"name":"main","address":"192.168.88.1:8728","username":"admin","password":"admin"}]' \
  -e COLLECTION_INTERVAL_SECONDS=30 \
  -e RUST_LOG=info \
  ghcr.io/jesof/mikrotik-exporter:latest
```

### С конфигурацией из файла

```bash
# Создать routers.json
cat > routers.json <<EOF
[
  {
    "name": "office-main",
    "address": "192.168.88.1:8728",
    "username": "prometheus",
    "password": "secure-password-1"
  },
  {
    "name": "office-backup",
    "address": "192.168.88.2:8728",
    "username": "prometheus",
    "password": "secure-password-2"
  }
]
EOF

# Запустить с конфигурацией
docker run -d \
  --name mikrotik-exporter \
  --restart=unless-stopped \
  -p 9090:9090 \
  -e SERVER_ADDR=0.0.0.0:9090 \
  -e ROUTERS_CONFIG="$(cat routers.json)" \
  -e RUST_LOG=info \
  ghcr.io/jesof/mikrotik-exporter:latest
```

### С healthcheck

```bash
docker run -d \
  --name mikrotik-exporter \
  --restart=unless-stopped \
  -p 9090:9090 \
  -e ROUTERS_CONFIG='[{"name":"router1","address":"192.168.88.1:8728","username":"admin","password":"pass"}]' \
  --health-cmd='wget --quiet --tries=1 --spider http://localhost:9090/health || exit 1' \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  --health-start-period=10s \
  ghcr.io/jesof/mikrotik-exporter:latest
```

---

## Kubernetes - Multi-Router

### Конфигурация для нескольких роутеров

```yaml
# routers-secret.yaml
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
        "name": "office-main",
        "address": "192.168.88.1:8728",
        "username": "prometheus",
        "password": "secure-pass-1"
      },
      {
        "name": "office-backup",
        "address": "192.168.88.2:8728",
        "username": "prometheus",
        "password": "secure-pass-2"
      },
      {
        "name": "warehouse",
        "address": "192.168.89.1:8728",
        "username": "prometheus",
        "password": "secure-pass-3"
      },
      {
        "name": "branch-office",
        "address": "10.0.10.1:8728",
        "username": "prometheus",
        "password": "secure-pass-4"
      }
    ]
```

### Deployment с resource limits

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mikrotik-exporter
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mikrotik-exporter
  template:
    metadata:
      labels:
        app: mikrotik-exporter
    spec:
      containers:
        - name: mikrotik-exporter
          image: ghcr.io/jesof/mikrotik-exporter:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 9090
              name: http
          env:
            - name: SERVER_ADDR
              value: "0.0.0.0:9090"
            - name: COLLECTION_INTERVAL_SECONDS
              value: "30"
            - name: RUST_LOG
              value: "info"
            - name: ROUTERS_CONFIG
              valueFrom:
                secretKeyRef:
                  name: mikrotik-exporter-secret
                  key: ROUTERS_CONFIG
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 256Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 10
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
```

---

## Prometheus Queries

### Системные метрики

```promql
# CPU load по роутерам
mikrotik_system_cpu_load

# Использование памяти (%)
100 - (mikrotik_system_free_memory_bytes / mikrotik_system_total_memory_bytes * 100)

# Uptime в днях
mikrotik_system_uptime_seconds / 86400

# Роутеры с загрузкой CPU > 70%
mikrotik_system_cpu_load > 70
```

### Сетевой трафик

```promql
# RX rate (bits/s) за последние 5 минут
rate(mikrotik_interface_rx_bytes[5m]) * 8

# TX rate (bits/s)
rate(mikrotik_interface_tx_bytes[5m]) * 8

# Общий трафик RX+TX (Mbps)
(rate(mikrotik_interface_rx_bytes[5m]) + rate(mikrotik_interface_tx_bytes[5m])) * 8 / 1000000

# Топ-5 интерфейсов по RX
topk(5, rate(mikrotik_interface_rx_bytes[5m]))

# Суммарный трафик по роутеру
sum by (router) (rate(mikrotik_interface_rx_bytes[5m]))
```

### Ошибки и пакеты

```promql
# Rate ошибок RX
rate(mikrotik_interface_rx_errors[5m])

# Rate ошибок TX
rate(mikrotik_interface_tx_errors[5m])

# Packets per second (RX)
rate(mikrotik_interface_rx_packets[5m])

# Интерфейсы с ошибками
mikrotik_interface_rx_errors > 0 or mikrotik_interface_tx_errors > 0
```

### Мониторинг health

```promql
# Success rate сбора метрик (%)
rate(mikrotik_scrape_success[5m]) / (rate(mikrotik_scrape_success[5m]) + rate(mikrotik_scrape_errors[5m])) * 100

# Длительность сбора метрик (ms)
mikrotik_scrape_duration_milliseconds

# Время с последнего успешного сбора (минуты)
(time() - mikrotik_scrape_last_success_timestamp_seconds) / 60

# Роутеры с ошибками подключения
mikrotik_connection_consecutive_errors > 0

# Использование пула соединений (%)
mikrotik_connection_pool_active / mikrotik_connection_pool_size * 100
```

### Алерты

```promql
# Exporter недоступен
up{job="mikrotik-exporter"} == 0

# Роутер недоступен
mikrotik_scrape_success == 0

# Высокая загрузка CPU
mikrotik_system_cpu_load > 80

# Мало памяти (<10%)
(mikrotik_system_free_memory_bytes / mikrotik_system_total_memory_bytes) * 100 < 10

# Интерфейс down
mikrotik_interface_running == 0

# Много ошибок на интерфейсе
rate(mikrotik_interface_rx_errors[5m]) > 10 or rate(mikrotik_interface_tx_errors[5m]) > 10
```

---

## Полезные команды

### Docker

```bash
# Логи exporter
docker logs -f mikrotik-exporter

# Статистика контейнера
docker stats mikrotik-exporter

# Выполнить команду внутри
docker exec -it mikrotik-exporter sh

# Проверка health
docker exec mikrotik-exporter wget -qO- http://localhost:9090/health | jq

# Перезапуск
docker restart mikrotik-exporter
```

### Kubernetes

```bash
# Логи pod
kubectl logs -n monitoring -l app=mikrotik-exporter -f

# Проверка метрик из pod
kubectl exec -n monitoring deployment/mikrotik-exporter -- \
  wget -qO- http://localhost:9090/metrics | grep mikrotik_system_info

# Port-forward для локального доступа
kubectl port-forward -n monitoring svc/mikrotik-exporter 9090:9090

# Масштабирование (не рекомендуется для exporter с state)
kubectl scale deployment/mikrotik-exporter --replicas=2 -n monitoring

# Проверка ресурсов
kubectl top pod -n monitoring -l app=mikrotik-exporter
```
