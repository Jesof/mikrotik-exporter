# Деплой в Kubernetes

Эта документация описывает процесс развертывания MikroTik Exporter в Kubernetes кластере.

## Содержание

- [Предварительные требования](#предварительные-требования)
- [Сборка Docker образа](#сборка-docker-образа)
- [Развертывание в Kubernetes](#развертывание-в-kubernetes)
- [Настройка Prometheus](#настройка-prometheus)
- [Импорт dashboard в Grafana](#импорт-dashboard-в-grafana)
- [Troubleshooting](#troubleshooting)

## Предварительные требования

- Kubernetes кластер (v1.20+)
- `kubectl` установлен и настроен
- Docker для сборки образа
- (Опционально) Prometheus Operator установлен в кластере
- (Опционально) Grafana установлена в кластере

## Сборка Docker образа

### 1. Локальная сборка

```bash
# Сборка образа
docker build -t mikrotik-exporter:latest .

# Тестирование образа локально
docker run -p 9090:9090 \
  -e ROUTERS_CONFIG='[{"name":"test","address":"192.168.88.1:8728","username":"admin","password":"admin"}]' \
  mikrotik-exporter:latest
```

### 2. Публикация в Container Registry

#### GitHub Container Registry (GHCR)

```bash
# Авторизация в GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Тег образа
docker tag mikrotik-exporter:latest ghcr.io/jesof/mikrotik-exporter:latest
docker tag mikrotik-exporter:latest ghcr.io/jesof/mikrotik-exporter:v0.1.0

# Публикация
docker push ghcr.io/jesof/mikrotik-exporter:latest
docker push ghcr.io/jesof/mikrotik-exporter:v0.1.0
```

#### Docker Hub

```bash
# Авторизация в Docker Hub
docker login

# Тег образа
docker tag mikrotik-exporter:latest username/mikrotik-exporter:latest
docker tag mikrotik-exporter:latest username/mikrotik-exporter:v0.1.0

# Публикация
docker push username/mikrotik-exporter:latest
docker push username/mikrotik-exporter:v0.1.0
```

## Развертывание в Kubernetes

### Вариант 1: Используя kubectl напрямую

#### 1. Создание namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

#### 2. Настройка конфигурации

Отредактируйте `k8s/secret.yaml` и добавьте ваши роутеры с реальными учетными данными:

```yaml
stringData:
  ROUTERS_CONFIG: |
    [
      {
        "name": "main-router",
        "address": "192.168.88.1:8728",
        "username": "admin",
        "password": "your-secure-password"
      }
    ]
```

**Важно:** Конфигурация роутеров хранится только в Secret, так как содержит чувствительные данные (логины и пароли). ConfigMap используется только для SERVER_ADDR.

#### 3. Применение манифестов

```bash
# Применить конфигурацию
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml

# Деплой приложения
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# (Опционально) Для Prometheus Operator
kubectl apply -f k8s/servicemonitor.yaml
```

#### 4. Проверка деплоя

```bash
# Проверка статуса pod
kubectl get pods -n monitoring

# Проверка логов
kubectl logs -n monitoring -l app=mikrotik-exporter -f

# Проверка сервиса
kubectl get svc -n monitoring mikrotik-exporter

# Тестирование endpoint
kubectl port-forward -n monitoring svc/mikrotik-exporter 9090:9090
# Открыть в браузере: http://localhost:9090/metrics
```

### Вариант 2: Используя Kustomize

```bash
# Применить все манифесты через kustomize
kubectl apply -k k8s/

# Или с указанием namespace
kubectl apply -k k8s/ -n monitoring
```

### Вариант 3: Используя Helm (пример создания chart)

Создайте простой Helm chart:

```bash
# Создание структуры
mkdir -p helm/mikrotik-exporter
cd helm/mikrotik-exporter

# Создание Chart.yaml
cat > Chart.yaml <<EOF
apiVersion: v2
name: mikrotik-exporter
description: MikroTik Prometheus Exporter
type: application
version: 0.1.0
appVersion: "0.1.0"
EOF

# Создание values.yaml
cat > values.yaml <<EOF
image:
  repository: ghcr.io/jesof/mikrotik-exporter
  tag: latest
  pullPolicy: Always

service:
  type: ClusterIP
  port: 9090

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
    password: admin

prometheusOperator:
  enabled: true
EOF

# Установка через Helm
helm install mikrotik-exporter . -n monitoring --create-namespace
```

## Настройка Prometheus

### Для Prometheus Operator

ServiceMonitor уже создан в `k8s/servicemonitor.yaml`. Убедитесь, что label selector в вашем Prometheus соответствует:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata:
  name: prometheus
spec:
  serviceMonitorSelector:
    matchLabels:
      release: prometheus # Должен совпадать с label в ServiceMonitor
```

### Для ванильного Prometheus

Добавьте job в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "mikrotik-exporter"
    static_configs:
      - targets: ["mikrotik-exporter.monitoring.svc.cluster.local:9090"]
    scrape_interval: 30s
    scrape_timeout: 10s
```

## Импорт dashboard в Grafana

### Через UI

1. Откройте Grafana
2. Перейдите в **Dashboards** → **Import**
3. Загрузите файл `grafana/dashboard.json`
4. Выберите Prometheus datasource
5. Нажмите **Import**

### Через ConfigMap (для Grafana в Kubernetes)

```bash
# Создание ConfigMap с dashboard
kubectl create configmap mikrotik-dashboard \
  --from-file=grafana/dashboard.json \
  -n monitoring

# Добавление label для автоматического обнаружения
kubectl label configmap mikrotik-dashboard \
  grafana_dashboard=1 \
  -n monitoring
```

Пример sidecar конфигурации для Grafana Helm chart:

```yaml
# values.yaml для Grafana
sidecar:
  dashboards:
    enabled: true
    label: grafana_dashboard
    labelValue: "1"
    folder: /tmp/dashboards
    searchNamespace: monitoring
```

### Через Grafana API

```bash
# Получение API ключа из Grafana UI (Configuration → API Keys)
GRAFANA_URL="http://grafana.monitoring.svc.cluster.local"
API_KEY="your-api-key"

# Импорт dashboard
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d @grafana/dashboard.json \
  "${GRAFANA_URL}/api/dashboards/db"
```

## Проверка работы

### 1. Проверка метрик

```bash
# Port-forward для доступа к метрикам
kubectl port-forward -n monitoring svc/mikrotik-exporter 9090:9090

# Проверка health endpoint
curl http://localhost:9090/health

# Проверка метрик
curl http://localhost:9090/metrics | grep mikrotik
```

### 2. Проверка в Prometheus

Откройте Prometheus UI и выполните запрос:

```promql
up{job="mikrotik-exporter"}
```

Или проверьте конкретные метрики:

```promql
mikrotik_system_info
mikrotik_system_cpu_load
mikrotik_interface_rx_bytes
```

### 3. Проверка dashboard в Grafana

Откройте импортированный dashboard "MikroTik Router Monitoring" и выберите роутер из выпадающего списка.

## Troubleshooting

### Pod не запускается

```bash
# Проверка событий
kubectl describe pod -n monitoring -l app=mikrotik-exporter

# Проверка логов
kubectl logs -n monitoring -l app=mikrotik-exporter --previous

# Проверка конфигурации
kubectl get configmap -n monitoring mikrotik-exporter-config -o yaml
kubectl get secret -n monitoring mikrotik-exporter-secret -o yaml
```

### Нет метрик в Prometheus

```bash
# Проверка ServiceMonitor
kubectl get servicemonitor -n monitoring mikrotik-exporter -o yaml

# Проверка endpoints
kubectl get endpoints -n monitoring mikrotik-exporter

# Проверка Prometheus targets
# Откройте Prometheus UI → Status → Targets
```

### Ошибки подключения к роутерам

```bash
# Проверка логов
kubectl logs -n monitoring -l app=mikrotik-exporter -f

# Проверка сетевой доступности из pod
kubectl exec -it -n monitoring deployment/mikrotik-exporter -- sh
# Внутри pod (если есть nc/telnet):
# nc -zv 192.168.88.1 8728
```

### Dashboard не отображает данные

1. Проверьте, что Prometheus datasource настроен корректно
2. Проверьте, что в Prometheus есть метрики (см. раздел "Проверка в Prometheus")
3. Проверьте переменные dashboard (Settings → Variables)
4. Убедитесь, что выбран правильный роутер в dropdown

## Обновление

### Обновление образа

```bash
# Пересобрать и загрузить новый образ
docker build -t ghcr.io/jesof/mikrotik-exporter:v0.2.0 .
docker push ghcr.io/jesof/mikrotik-exporter:v0.2.0

# Обновить deployment
kubectl set image deployment/mikrotik-exporter \
  mikrotik-exporter=ghcr.io/jesof/mikrotik-exporter:v0.2.0 \
  -n monitoring

# Или через patch
kubectl patch deployment mikrotik-exporter \
  -n monitoring \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"mikrotik-exporter","image":"ghcr.io/jesof/mikrotik-exporter:v0.2.0"}]}}}}'

# Проверка статуса rollout
kubectl rollout status deployment/mikrotik-exporter -n monitoring
```

### Обновление конфигурации

```bash
# Редактирование secret
kubectl edit secret mikrotik-exporter-secret -n monitoring

# Или применение обновленного файла
kubectl apply -f k8s/secret.yaml

# Рестарт deployment для применения изменений
kubectl rollout restart deployment/mikrotik-exporter -n monitoring
```

## Удаление

```bash
# Удаление всех ресурсов
kubectl delete -f k8s/servicemonitor.yaml
kubectl delete -f k8s/service.yaml
kubectl delete -f k8s/deployment.yaml
kubectl delete -f k8s/configmap.yaml
kubectl delete -f k8s/secret.yaml

# Или через kustomize
kubectl delete -k k8s/

# Удаление namespace (если больше не нужен)
kubectl delete namespace monitoring
```

## Дополнительные настройки

### Ingress для внешнего доступа

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mikrotik-exporter
  namespace: monitoring
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
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

### Horizontal Pod Autoscaling

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

### Мониторинг самого exporter'а

Добавьте PrometheusRule для алертов:

```yaml
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
            summary: "MikroTik Exporter is down"
            description: "MikroTik Exporter has been down for more than 5 minutes."

        - alert: MikroTikScrapeErrors
          expr: rate(mikrotik_scrape_errors[5m]) > 0
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "MikroTik scrape errors detected"
            description: "Router {{ $labels.router }} is experiencing scrape errors."
```
