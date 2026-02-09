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

[Полный список метрик →](#полный-список-метрик)

## Конфигурация

### Переменные окружения

```bash
SERVER_ADDR=0.0.0.0:9090                    # HTTP server bind address
ROUTERS_CONFIG=[{...}]                      # JSON массив роутеров (обязательно)
COLLECTION_INTERVAL_SECONDS=30              # Интервал сбора метрик
RUST_LOG=info                               # Уровень логирования
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

## Архитектура проекта

```tree
src/
├── lib.rs                  # Публичная библиотека
├── main.rs                 # Точка входа
├── prelude.rs              # Re-exports
├── api/                    # HTTP handlers
├── collector/              # Background metrics collection
├── config/                 # Configuration loading
├── metrics/                # Prometheus metrics
└── mikrotik/               # RouterOS API client
```

### Использование как библиотеки

```rust
use mikrotik_exporter::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env();
    let client = MikroTikClient::new(/* ... */);
    let stats = client.get_interface_stats().await?;
    Ok(())
}
```
