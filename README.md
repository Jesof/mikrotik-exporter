# MikroTik Prometheus Exporter

Prometheus exporter для сбора метрик с MikroTik роутеров через RouterOS API.

## Возможности

- ✅ Сбор метрик с нескольких MikroTik роутеров одновременно
- ✅ Экспорт метрик в формате Prometheus
- ✅ Асинхронная архитектура на базе Tokio
- ✅ Настройка через переменные окружения или JSON
- ✅ Health check endpoint
- ✅ Периодический фоновой сбор метрик с кэшированием
- ✅ Graceful shutdown (Ctrl+C) для корректного завершения фоновых задач

## Собираемые метрики

### Интерфейсы

- `mikrotik_interface_rx_bytes` - Полученные байты
- `mikrotik_interface_tx_bytes` - Отправленные байты
- `mikrotik_interface_rx_packets` - Полученные пакеты
- `mikrotik_interface_tx_packets` - Отправленные пакеты
- `mikrotik_interface_rx_errors` - Ошибки приёма
- `mikrotik_interface_tx_errors` - Ошибки передачи
- `mikrotik_interface_running` - Статус интерфейса (1=работает, 0=не работает)

### Система

- `mikrotik_system_cpu_load` - Загрузка CPU (%)
- `mikrotik_system_free_memory_bytes` - Свободная память (байты)
- `mikrotik_system_total_memory_bytes` - Общая память (байты)
- `mikrotik_system_info` - Информация о системе (version, board)
- `mikrotik_system_uptime_seconds` - Аптайм системы (секунды)

Все метрики имеют лейблы `router` (имя роутера) и `interface` (имя интерфейса, где применимо).

### Сервисные метрики

- `mikrotik_scrape_success` - Количество успешных циклов сбора по роутеру
- `mikrotik_scrape_errors` - Количество ошибок сбора по роутеру

## Установка

### Из исходников

```bash
git clone https://github.com/Jesof/mikrotik-exporter.git
cd mikrotik-exporter
cargo build --release
```

Бинарный файл будет находиться в `target/release/mikrotik-exporter`

## Конфигурация

Создайте `.env` файл на основе `.env.example`:

```bash
cp .env.example .env
```

### Вариант 1: Один роутер (простая конфигурация)

```env
SERVER_ADDR=0.0.0.0:9090
ROUTEROS_ADDRESS=192.168.88.1:8728
ROUTEROS_USERNAME=admin
ROUTEROS_PASSWORD=mypassword
RUST_LOG=info
COLLECTION_INTERVAL_SECONDS=30
```

### Вариант 2: Несколько роутеров (JSON конфигурация)

```env
SERVER_ADDR=0.0.0.0:9090
ROUTERS_CONFIG=[{"name":"office","address":"192.168.88.1:8728","username":"admin","password":"pass1"},{"name":"home","address":"192.168.1.1:8728","username":"admin","password":"pass2"}]
RUST_LOG=info
```

## Запуск

```bash
./target/release/mikrotik-exporter
```

Или в режиме разработки:

```bash
cargo run
```

## API Endpoints

- `GET /health` - Health check (возвращает статус сервиса)
- `GET /metrics` - Prometheus метрики (кэш фонового сбора, без прямого запроса к роутеру)

## Конфигурация Prometheus

Добавьте в `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "mikrotik"
    static_configs:
      - targets: ["localhost:9090"]
    scrape_interval: 30s
```

Если `COLLECTION_INTERVAL_SECONDS` больше чем `scrape_interval`, часть скрапов отдаст те же значения (интервалы можно синхронизировать).

## Требования к MikroTik

- RouterOS с включенным API (порт 8728)
- Пользователь с правами на чтение:
  - `/interface`
  - `/system/resource`

### Включение API на MikroTik

```shell
/ip service
set api address=0.0.0.0/0 disabled=no port=8728
```

### Создание пользователя для мониторинга

```shell
/user group add name=monitoring policy=api,read
/user add name=prometheus group=monitoring password=yourpassword
```

## Разработка

### Структура проекта

```text
src/
├── main.rs              # Точка входа
├── config/mod.rs        # Конфигурация
├── api/
│   ├── mod.rs           # Router setup
│   └── handlers/
│       ├── health.rs    # Health check handler
│       ├── metrics.rs   # Metrics handler
│       └── mod.rs
├── mikrotik/mod.rs      # Низкоуровневый RouterOS API клиент (login, print, парсинг)
└── metrics/mod.rs       # Prometheus metrics registry
```

### Запуск тестов

```bash
cargo test
```

### Проверка форматирования

```bash
cargo fmt --check
cargo clippy
```

## Лицензия

MIT

## Статус реализации

Реализовано:

- Challenge-response `/login`
- Команды `/interface/print` и `/system/resource/print`
- Парсинг ответов (`!re`, `!done`, обработка `!trap`)
- Таймауты и повторные попытки
- Фоновый сбор с расчётом дельт для интерфейсных counters

Добавлены сервисные счётчики успехов и ошибок сбора.

План улучшений:

- Дополнительные метрики (uptime, temperature, wireless, queue, dhcp)
- Метрики длительности и времени последнего успешного сбора
- Расширенные тесты парсера
- Пул и реиспользование подключений
- Улучшенная обработка ошибок / перманентных отказов

## Автор

Jesof <jesof@me.com>
