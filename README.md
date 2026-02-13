# MikroTik Prometheus Exporter

Prometheus exporter для MikroTik RouterOS API с поддержкой множественных роутеров и асинхронной архитектурой.

## Quick Start

```bash
# Docker
docker run -p 9090:9090 \
  -e ROUTERS_CONFIG='[{"name":"router1","address":"192.168.88.1:8728","username":"admin","password":"pass"}]' \
  ghcr.io/jesof/mikrotik-exporter:latest

# Binary
ROUTERS_CONFIG='[...]' ./mikrotik-exporter

# Kubernetes
kubectl apply -k k8s/
```

## Метрики

| Метрика                                 | Тип     | Описание               |
| --------------------------------------- | ------- | ---------------------- |
| `mikrotik_interface_rx_bytes`           | counter | Полученные байты       |
| `mikrotik_interface_tx_bytes`           | counter | Отправленные байты     |
| `mikrotik_system_cpu_load`              | gauge   | Загрузка CPU (%)       |
| `mikrotik_system_free_memory_bytes`     | gauge   | Свободная память       |
| `mikrotik_scrape_duration_milliseconds` | gauge   | Длительность сбора     |
| `mikrotik_connection_pool_size`         | gauge   | Размер пула соединений |
| `mikrotik_connection_tracking_count`    | gauge   | Connection tracking    |
| `mikrotik_wireguard_peer_rx_bytes`      | gauge   | WireGuard RX bytes     |
| `mikrotik_wireguard_peer_tx_bytes`      | gauge   | WireGuard TX bytes     |

[Полный список метрик →](#полный-список-метрик)

## Конфигурация

### Переменные окружения

```bash
SERVER_ADDR=0.0.0.0:9090                    # HTTP server bind address
ROUTERS_CONFIG=[{...}]                      # JSON массив роутеров (рекомендуется)
COLLECTION_INTERVAL_SECONDS=30              # Интервал сбора метрик
RUST_LOG=info                               # Уровень логирования
ROUTEROS_ADDRESS=192.168.88.1:8728          # Legacy: адрес RouterOS API (один роутер)
ROUTEROS_USERNAME=admin                     # Legacy: пользователь (default: admin)
ROUTEROS_PASSWORD=                          # Legacy: пароль (default: пусто)
```

Если `ROUTERS_CONFIG` не задан, используется legacy-конфигурация
`ROUTEROS_ADDRESS/ROUTEROS_USERNAME/ROUTEROS_PASSWORD` с именем роутера `default`.

### Формат ROUTERS_CONFIG

```json
[
  {
    "name": "router-name", // Имя роутера (используется в метках)
    "address": "192.168.88.1:8728", // Адрес RouterOS API
    "username": "admin", // Имя пользователя
    "password": "password" // Пароль
  }
]
```

## Endpoints

| Path       | Описание                         | Код ответа |
| ---------- | -------------------------------- | ---------- |
| `/metrics` | Prometheus метрики               | 200        |
| `/health`  | Health check с статусом роутеров | 200/503    |

## Развертывание

- [Kubernetes](DEPLOYMENT.md#kubernetes)
- [Docker & Docker Compose](EXAMPLES.md#docker-compose---production-stack)
- [Prometheus интеграция](DEPLOYMENT.md#prometheus)
- [Grafana dashboard](DEPLOYMENT.md#grafana)

## Требования к RouterOS

```bash
# Включить API
/ip service set api address=0.0.0.0/0 disabled=no port=8728

# Создать пользователя
/user group add name=monitoring policy=api,read
/user add name=prometheus group=monitoring password=secure-password
```

## Разработка

```bash
# Запуск
cargo run

# Тесты
cargo test

# Сборка
cargo build --release
```

[Архитектура и API →](#архитектура-проекта)

## Лицензия

MIT - см. [LICENSE](LICENSE)

---

## Полный список метрик

### Интерфейсы (Labels: router, interface)

| Метрика                         | Тип     | Описание                          |
| ------------------------------- | ------- | --------------------------------- |
| `mikrotik_interface_rx_bytes`   | counter | Полученные байты                  |
| `mikrotik_interface_tx_bytes`   | counter | Отправленные байты                |
| `mikrotik_interface_rx_packets` | counter | Полученные пакеты                 |
| `mikrotik_interface_tx_packets` | counter | Отправленные пакеты               |
| `mikrotik_interface_rx_errors`  | counter | Ошибки приёма                     |
| `mikrotik_interface_tx_errors`  | counter | Ошибки передачи                   |
| `mikrotik_interface_running`    | gauge   | Статус (1=работает, 0=остановлен) |

### Система (Labels: router)

| Метрика                              | Тип   | Описание                                      |
| ------------------------------------ | ----- | --------------------------------------------- |
| `mikrotik_system_cpu_load`           | gauge | Загрузка CPU (%)                              |
| `mikrotik_system_free_memory_bytes`  | gauge | Свободная память                              |
| `mikrotik_system_total_memory_bytes` | gauge | Общая память                                  |
| `mikrotik_system_uptime_seconds`     | gauge | Uptime системы                                |
| `mikrotik_system_info`               | gauge | Информация о системе (labels: version, board) |

### Сервисные метрики (Labels: router)

| Метрика                                          | Тип     | Описание                                  |
| ------------------------------------------------ | ------- | ----------------------------------------- |
| `mikrotik_scrape_success`                        | counter | Успешные сборы                            |
| `mikrotik_scrape_errors`                         | counter | Ошибки сбора                              |
| `mikrotik_scrape_duration_milliseconds`          | gauge   | Длительность последнего сбора             |
| `mikrotik_scrape_last_success_timestamp_seconds` | gauge   | Unix timestamp последнего успешного сбора |
| `mikrotik_connection_consecutive_errors`         | gauge   | Последовательные ошибки подключения       |
| `mikrotik_collection_cycle_duration_milliseconds`| gauge   | Длительность полного цикла сбора          |
| `mikrotik_connection_pool_size`                  | gauge   | Размер пула соединений                    |
| `mikrotik_connection_pool_active`                | gauge   | Активные соединения в пуле                |

### Connection tracking (Labels: router, src_address, protocol, ip_version)

| Метрика                                | Тип   | Описание                                   |
| -------------------------------------- | ----- | ------------------------------------------ |
| `mikrotik_connection_tracking_count`   | gauge | Количество соединений по src/protocol/ip   |

### WireGuard Interfaces (Labels: router, interface)

Статус интерфейсов WireGuard доступен через стандартную метрику `mikrotik_interface_running`.

### WireGuard Peers (Labels: router, interface, name, allowed_address, endpoint)

| Метрика                              | Тип   | Описание                                    |
| ------------------------------------ | ----- | ------------------------------------------- |
| `mikrotik_wireguard_peer_rx_bytes`   | gauge | Полученные байты от пира                    |
| `mikrotik_wireguard_peer_tx_bytes`   | gauge | Отправленные байты пиру                     |
| `mikrotik_wireguard_peer_latest_handshake` | gauge | Unix timestamp последнего хендшейка |

## Архитектура проекта

```tree
src/
├── lib.rs                  # Публичная библиотека
├── main.rs                 # Точка входа
├── prelude.rs              # Re-exports
├── api/                    # HTTP handlers
├── collector/              # Background metrics collection
│   ├── cache.rs            # System info cache
│   └── router_task.rs      # Per-router collection task
├── config/                 # Configuration loading
├── metrics/                # Prometheus metrics
│   └── registry/           # init/update/cleanup/scrape split
└── mikrotik/               # RouterOS API client
    └── connection/         # auth/protocol/parse split
```

### Использование как библиотеки

```rust
use std::sync::Arc;

use mikrotik_exporter::{
    AppState, Config, ConnectionPool, MetricsRegistry, Result, create_router,
    start_collection_loop,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env();
    let metrics = MetricsRegistry::new();
    let pool = Arc::new(ConnectionPool::new());
    let state = Arc::new(AppState {
        config: Arc::new(config.clone()),
        metrics: metrics.clone(),
        pool: pool.clone(),
    });

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    start_collection_loop(shutdown_rx, Arc::new(config), metrics, pool);

    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
```
