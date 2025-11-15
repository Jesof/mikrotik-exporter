# MikroTik Exporter - Примеры использования

## Быстрый старт с Docker Compose

```yaml
version: "3.8"

services:
  mikrotik-exporter:
    image: ghcr.io/jesof/mikrotik-exporter:latest
    ports:
      - "9090:9090"
    environment:
      - SERVER_ADDR=0.0.0.0:9090
      - ROUTERS_CONFIG=[{"name":"main-router","address":"192.168.88.1:8728","username":"admin","password":"admin"}]
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboard.json:/etc/grafana/provisioning/dashboards/mikrotik.json
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    restart: unless-stopped

volumes:
  prometheus-data:
  grafana-data:
```

Создайте `prometheus.yml`:

```yaml
global:
  scrape_interval: 30s
  evaluation_interval: 30s

scrape_configs:
  - job_name: "mikrotik-exporter"
    static_configs:
      - targets: ["mikrotik-exporter:9090"]
```

Запуск:

```bash
docker-compose up -d
```

Доступ:

- Метрики: http://localhost:9090/metrics
- Prometheus: http://localhost:9091
- Grafana: http://localhost:3000 (admin/admin)
