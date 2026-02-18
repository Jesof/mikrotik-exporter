# MikroTik Prometheus Exporter

[![Crates.io](https://img.shields.io/crates/v/mikrotik-exporter.svg)](https://crates.io/crates/mikrotik-exporter)
[![GitHub release](https://img.shields.io/github/v/release/jesof/mikrotik-exporter.svg)](https://github.com/jesof/mikrotik-exporter/releases)
[![Grafana](https://img.shields.io/badge/Grafana-24875-orange.svg?logo=grafana)](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)
[![Docs.rs](https://docs.rs/mikrotik-exporter/badge.svg)](https://docs.rs/mikrotik-exporter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://github.com/jesof/mikrotik-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/jesof/mikrotik-exporter/actions/workflows/ci.yml)

Prometheus exporter для MikroTik RouterOS API с поддержкой множественных роутеров и асинхронной архитектурой.

## Quick Start

```bash
# Cargo
cargo install mikrotik-exporter

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

| Метрика                                 | Тип     | Описание                        |
| --------------------------------------- | ------- | ------------------------------- |
| `mikrotik_interface_rx_bytes`           | counter | Полученные байты                |
| `mikrotik_interface_tx_bytes`           | counter | Отправленные байты              |
| `mikrotik_system_cpu_load`              | gauge   | Загрузка CPU (%)                |
| `mikrotik_system_free_memory_bytes`     | gauge   | Свободная память                |
| `mikrotik_scrape_duration_milliseconds` | gauge   | Длительность сбора              |
| `mikrotik_connection_pool_size`         | gauge   | Размер пула соединений          |
| `mikrotik_connection_tracking_count`    | gauge   | Connection tracking             |
| `mikrotik_wireguard_peer_rx_bytes`      | gauge   | WireGuard RX bytes              |
| `mikrotik_wireguard_peer_tx_bytes`      | gauge   | WireGuard TX bytes              |
| `mikrotik_certificate_days_until_expiry`| gauge   | Дней до истечения сертификатов  |

[Полный список метрик →](#полный-список-метрик)

## Конфигурация

### Переменные окружения

```bash
SERVER_ADDR=0.0.0.0:9090                    # HTTP server bind address
ROUTERS_CONFIG=[{...}]                      # JSON массив роутеров (рекомендуется)
COLLECTION_INTERVAL_SECONDS=30              # Интервал сбора метрик
STARTUP_CONNECTIVITY_TEST=false             # Проверка доступности роутеров при запуске
STARTUP_CONNECTIVITY_TIMEOUT_SECS=10        # Таймаут проверки доступности (в секундах)
STRICT_STARTUP_MODE=false                   # Завершать работу при недоступности роутеров
RUST_LOG=info                               # Уровень логирования
ROUTEROS_ADDRESS=192.168.88.1:8728          # Legacy: адрес RouterOS API (один роутер)
ROUTEROS_USERNAME=admin                     # Legacy: пользователь (default: admin)
ROUTEROS_PASSWORD=                          # Legacy: пароль (default: пусто)
```

Если `ROUTERS_CONFIG` не задан, используется legacy-конфигурация
`ROUTEROS_ADDRESS/ROUTEROS_USERNAME/ROUTEROS_PASSWORD` с именем роутера `default`.

### Проверка доступности роутеров при запуске

Новые опции позволяют проверить доступность всех сконфигурированных роутеров при запуске сервиса:

- `STARTUP_CONNECTIVITY_TEST=true` - включает проверку доступности роутеров при запуске
- `STARTUP_CONNECTIVITY_TIMEOUT_SECS=10` - таймаут для каждой проверки (по умолчанию 10 секунд)
- `STRICT_STARTUP_MODE=true` - завершает работу сервиса с кодом ошибки, если какой-либо роутер недоступен

Пример использования:
```bash
# Проверить доступность роутеров при запуске, но продолжить работу даже если некоторые недоступны
STARTUP_CONNECTIVITY_TEST=true ./mikrotik-exporter

# Проверить доступность роутеров и завершить работу, если хотя бы один недоступен
STARTUP_CONNECTIVITY_TEST=true STRICT_STARTUP_MODE=true ./mikrotik-exporter
```

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
- [Grafana Dashboard (ID: 24875)](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)

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

# Интеграционные тесты (требуют настроенного MikroTik устройства)
cargo test --test integration_tests

# Сборка
cargo build --release
```

Для запуска интеграционных тестов необходимо настроить подключение к реальному устройству MikroTik через переменные окружения в файле `.env`:

```bash
# Пример .env файла для интеграционных тестов
ROUTEROS_ADDRESS=192.168.88.1:8728
ROUTEROS_USERNAME=admin
ROUTEROS_PASSWORD=your_password
```

Интеграционные тесты автоматически пропускаются, если переменные окружения не настроены.

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

### WireGuard Peers (Labels: router, interface, allowed_address)

| Метрика                                    | Тип   | Описание                            |
| ------------------------------------------ | ----- | ----------------------------------- |
| `mikrotik_wireguard_peer_rx_bytes`         | gauge | Полученные байты от пира            |
| `mikrotik_wireguard_peer_tx_bytes`         | gauge | Отправленные байты пиру             |
| `mikrotik_wireguard_peer_latest_handshake` | gauge | Unix timestamp последнего хендшейка |
| `mikrotik_wireguard_peer_info`             | gauge | Метаданные пира (name, endpoint)    |

### Сертификаты (Labels: router, name)

| Метрика                                     | Тип   | Описание                             |
| ------------------------------------------- | ----- | ------------------------------------ |
| `mikrotik_certificate_days_until_expiry`    | gauge | Дней до истечения срока действия     |

### Информация о системе (Labels: router, version, board)

| Метрика                | Тип   | Описание                                      |
| ---------------------- | ----- | --------------------------------------------- |
| `mikrotik_system_info` | gauge | Статическая информация о роутере (значение=1) |

## Архитектура проекта

```tree
src/
├── lib.rs                  # Публичная библиотека
├── main.rs                 # Точка входа
├── prelude.rs              # Re-exports
├── api/                    # HTTP handlers
│   └── handlers/           # Health and metrics endpoints
├── collector/              # Background metrics collection
│   ├── cache.rs            # System info cache
│   ├── router_task.rs      # Per-router collection task
│   └── cleanup.rs          # Periodic cleanup task
├── config/                 # Configuration loading
├── error.rs                # Error types
├── metrics/                # Prometheus metrics
│   ├── labels.rs           # Label definitions
│   ├── parsers.rs          # Response parsers
│   ├── registry/           # Metrics registry (init/update/cleanup/scrape)
│   └── tests.rs            # Metric tests
└── mikrotik/               # RouterOS API client
    ├── client.rs           # Client implementation
    ├── connection/         # Connection handling (auth/protocol)
    ├── pool.rs             # Connection pool
    ├── responses/          # Response parsers
    ├── types.rs            # Type definitions
    └── mod.rs              # Module exports
```

### Использование как библиотеки

Добавьте в ваш `Cargo.toml`:

```toml
[dependencies]
mikrotik-exporter = "0.2.5"
```

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
        config: config.clone(),
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
