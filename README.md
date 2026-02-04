# GatekeeperVPN

Простой и безопасный VPN на Rust. Использует Noise Protocol (как WireGuard) для шифрования.

## Возможности

- **Noise IK handshake** — безопасное установление соединения с forward secrecy
- **ChaCha20-Poly1305** — быстрое AEAD-шифрование
- **X25519** — эллиптический обмен ключами (128-bit equivalent security)
- **Replay protection** — защита от повторных пакетов (SlidingWindow 2048 бит)
- **Roaming** — переключение сети (WiFi→LTE, смена NAT) без разрыва VPN-сессии
- **Per-client IP** — каждый клиент получает уникальный IP из пула
- **Авторизация** — только клиенты из белого списка (peers.toml)
- **Unicast роутинг** — трафик идёт только нужному клиенту
- **Traffic Obfuscation** — anti-DPI: XOR header, random padding, junk packets
- **Автоматическая настройка NAT** — сервер автоматически включает IP forwarding и настраивает NAT
- **Hot-reload** — изменения peers.toml применяются без перезапуска сервера
- **Keep-alive + автопереподключение** — клиент восстанавливает соединение при обрыве
- **Graceful shutdown** — корректная очистка маршрутов и NAT-правил при остановке (SIGINT/SIGTERM)
- **macOS + Linux** — поддержка обеих платформ с автоматическим исправлением маршрутов на macOS

## Архитектура

```
┌────────────────────────────────────────────────────────────────┐
│ Client                              Server                     │
│                                                                │
│ TUN read → encrypt → UDP send  →  UDP recv → decrypt → TUN    │
│ TUN write ← decrypt ← UDP recv ←  TUN read → encrypt → UDP   │
│                                                                │
│ Handshake: Noise IK (e, es, s, ss) → (e, ee, se)             │
│ Transport: ChaCha20-Poly1305 + 8-byte counter                  │
└────────────────────────────────────────────────────────────────┘
```

### Структура проекта

```
crates/
├── common/     # Общая библиотека: криптография, протокол, TUN, маршрутизация, NAT
├── server/     # VPN-сервер
├── client/     # VPN-клиент
└── keygen/     # CLI-утилита управления ключами и пирами (gkvpn)
```

## Сборка

**Требования:** Rust 1.75+

```bash
# Debug-сборка
cargo build

# Release-сборка (рекомендуется для деплоя)
cargo build --release

# Запуск тестов
cargo test

# Форматирование + линтер
cargo fmt && cargo clippy
```

Собранные бинарники находятся в `target/release/`:
- `gatekeeper-server` — сервер
- `gatekeeper-client` — клиент
- `gkvpn` — CLI для управления ключами и пирами

## Быстрый старт

### Автоматическая установка сервера (рекомендуется)

```bash
# На чистом сервере Ubuntu/Debian
cd /opt
git clone https://github.com/ArkMaster123/gatekeepervpn.git
cd gatekeepervpn
sudo bash scripts/setup.sh
```

Скрипт автоматически настроит:
- Установку всех зависимостей (Rust, build-essential)
- Сборку проекта в release-режиме
- Генерацию ключей и конфигурации
- NAT и IP forwarding
- Systemd-сервис

Подробнее: [ROADMAP.md](ROADMAP.md)

### Ручная настройка

#### 1. Генерация конфигурации сервера

```bash
# Создать каталог конфигурации
sudo mkdir -p /etc/gatekeeper

# Сгенерировать серверный конфиг с ключами
gkvpn generate-server --output /etc/gatekeeper/server.toml
```

#### 2. Инициализация пула клиентов

```bash
gkvpn init --subnet 10.10.10.0 --mask 24
```

#### 3. Добавление клиента

```bash
gkvpn add "laptop-ilya" --server-address vpn.example.com:51820
```

Профиль сохранится в `/etc/gatekeeper/profiles/laptop-ilya.conf`

#### 4. Запуск сервера

```bash
# Напрямую (требует root для TUN)
sudo gatekeeper-server -c /etc/gatekeeper/server.toml -p /etc/gatekeeper/peers.toml

# Через systemd
sudo systemctl start gatekeeper
sudo systemctl enable gatekeeper   # автозапуск при перезагрузке
```

#### 5. Запуск клиента

```bash
# Скопировать профиль с сервера
scp root@server:/etc/gatekeeper/profiles/laptop-ilya.conf ~/

# Запустить клиент
sudo gatekeeper-client -c ~/laptop-ilya.conf
```

## Запуск

### Сервер

```bash
# Полный запуск с авторизацией
sudo gatekeeper-server -c server.toml -p peers.toml

# Без авторизации (для тестирования)
sudo gatekeeper-server -c server.toml --no-auth

# Echo-режим — без TUN, просто отвечает зеркально (для тестирования)
cargo run --bin server -- --echo

# Указать адрес прослушивания
sudo gatekeeper-server -c server.toml -l 0.0.0.0:51821
```

**Параметры сервера:**

| Флаг | Описание |
|------|----------|
| `-c, --config` | Путь к файлу конфигурации (по умолчанию `server.toml`) |
| `-p, --peers` | Путь к файлу пиров (по умолчанию `/etc/gatekeeper/peers.toml`) |
| `-l, --listen` | Адрес прослушивания (переопределяет config) |
| `-e, --echo` | Echo-режим без TUN (для тестов) |
| `--no-auth` | Отключить авторизацию по ключам |

### Клиент

```bash
# Полный запуск
sudo gatekeeper-client -c client.conf

# Указать сервер вручную (переопределяет config)
sudo gatekeeper-client -c client.conf -s vpn.example.com:51820

# Тестовый режим — handshake + echo-сообщение, без TUN
cargo run --bin client -- --test -c client.conf

# Тестовый режим с кастомным сообщением
cargo run --bin client -- --test -m "ping" -c client.conf
```

**Параметры клиента:**

| Флаг | Описание |
|------|----------|
| `-c, --config` | Путь к файлу конфигурации (по умолчанию `client.toml`) |
| `-s, --server` | Адрес сервера (переопределяет config) |
| `-t, --test` | Тестовый режим: handshake + echo, без TUN |
| `-m, --message` | Сообщение для test mode |

### Генерация ключей (gkvpn)

```bash
gkvpn generate-server         # Сгенерировать конфиг сервера с ключами
gkvpn generate-client          # Сгенерировать конфиг клиента
gkvpn show-public --key "..."  # Показать публичный ключ из приватного
gkvpn init                     # Инициализация peers.toml
gkvpn add "name"               # Добавить клиента с авто-выделением IP
gkvpn remove "name"            # Удалить клиента
gkvpn list                     # Список всех клиентов
gkvpn show "name"              # Показать профиль клиента
```

## Graceful Shutdown

Сервер и клиент корректно обрабатывают сигналы завершения:

| Сигнал | Действие |
|--------|----------|
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGTERM` | Graceful shutdown (systemd, docker) |

**При остановке сервера:**
- Удаляются NAT-правила (iptables/pf)
- Логируется количество подключённых клиентов

**При остановке клиента:**
- Удаляются VPN-маршруты
- Восстанавливается оригинальный default gateway
- Удаляется маршрут к серверу через оригинальный gateway

```bash
# Корректная остановка через systemd
sudo systemctl stop gatekeeper

# Или Ctrl+C в терминале
# Или kill (SIGTERM)
sudo kill $(pgrep gatekeeper-server)
```

## Roaming (переключение сети)

VPN-сессия сохраняется при смене IP клиента (WiFi→LTE, смена NAT, перезагрузка роутера).
Не требует повторного handshake — используется подход WireGuard.

**Как работает:**
1. Клиент обнаруживает потерю связи (KeepAlive timeout)
2. Создаёт новый UDP socket и отправляет зашифрованный "roam ping"
3. Сервер пытается расшифровать пакет ключами каждого клиента (`can_decrypt`)
4. При успехе — обновляет endpoint клиента, трафик продолжается
5. Если soft roam не удался — клиент делает полный re-handshake

**Ограничения:**
- Brute-force поиск клиента при roaming — O(n), приемлемо при n < 100
- KeepAlive от неизвестного адреса игнорируется (roaming срабатывает по Data-пакету)

## Конфигурация

### server.toml

```toml
listen = "0.0.0.0:51820"
private_key = "base64..."

# TUN interface
tun_address = "10.10.10.1"
tun_netmask = "255.255.255.0"
tun_mtu = 1400

# NAT configuration
external_interface = "eth0"  # Внешний интерфейс (eth0, ens3, en0 и т.д.)
enable_nat = true             # Автоматическая настройка NAT
```

**Важно:** Укажите правильный внешний сетевой интерфейс:
```bash
ip route show default   # Linux — покажет интерфейс
ifconfig                # macOS — обычно en0
```

### peers.toml

```toml
subnet = "10.10.10.0"
subnet_mask = 24
next_ip = "10.10.10.3"

[[peers]]
name = "laptop-ilya"
public_key = "abc123..."
assigned_ip = "10.10.10.2"
created_at = "2026-01-19T12:00:00Z"
```

### client.conf

```toml
server = "vpn.example.com:51820"
private_key = "base64..."
server_public_key = "base64..."
tun_address = "10.10.10.2"
tun_netmask = "255.255.255.0"
tun_mtu = 1400

# Маршрутизация
route_all_traffic = true           # Весь трафик через VPN
# routed_subnets = ["10.10.0.0/16"] # Или только указанные подсети

# Keep-alive
keepalive_interval = 25   # секунд
keepalive_timeout = 60    # секунд до признания обрыва

# Переподключение
reconnect_enabled = true
reconnect_delay = 5                # секунд между попытками
max_reconnect_attempts = 0         # 0 = безлимитно
```

### Структура файлов

```
/etc/gatekeeper/
├── server.toml      # Конфигурация сервера
├── peers.toml       # База клиентов (сервер hot-reload каждые 5 сек)
└── profiles/        # Готовые конфиги для клиентов
    ├── laptop.conf
    └── phone.conf
```

## DNS

Клиент автоматически переключает системные DNS при подключении и восстанавливает при отключении. Настройка в `client.conf`:

```toml
dns_servers = ["1.1.1.1", "8.8.8.8"]
```

Если `dns_servers` не указан — DNS не меняется.

## Проверка работы VPN

```bash
# 1. Проверить VPN gateway
ping -c 3 10.10.10.1

# 2. Проверить маршруты
netstat -rn | grep utun     # macOS
ip route | grep tun         # Linux

# 3. Проверить доступность интернета
ping -c 3 8.8.8.8
curl -I https://google.com

# 4. Проверить внешний IP (должен быть IP сервера)
curl ifconfig.me
```

### Ожидаемые маршруты на macOS

```
10.10.10.1         utun8              UH      utun8     # VPN gateway
10.10.10/24        utun8              USc     utun8     # VPN subnet
0.0.0.0/1          utun8              UGSc    utun8     # Default route (part 1)
128.0.0.0/1        utun8              UGSc    utun8     # Default route (part 2)
84.246.85.36       10.240.111.250     UGHS    en0       # Direct route to VPN server
```

## Диагностика проблем

### Автоматическая диагностика (сервер)

```bash
sudo ./scripts/diagnose.sh
```

Проверяет: конфигурацию, сетевые интерфейсы, IP forwarding, NAT/iptables, systemd-сервис, подключение к интернету.

### Типичные проблемы

**1. `external_interface = "tun0"` в server.toml**

```toml
# НЕПРАВИЛЬНО — tun0 это сам VPN интерфейс!
external_interface = "tun0"

# ПРАВИЛЬНО — ваш внешний интерфейс
external_interface = "ens3"   # или eth0, ens5 (Linux), en0 (macOS)
```

```bash
ip route show default  # покажет правильный интерфейс
```

**2. Ping к VPN gateway не работает на macOS**

Клиент автоматически исправляет маршруты. В логах должно быть:
```
[INFO] Removing incorrect VPN subnet route for 10.10.10/24
[INFO] Adding host route for VPN gateway 10.10.10.1 through utun8
[INFO] Adding correct route for VPN subnet 10.10.10/24 through utun8
```

**3. Ручная проверка на сервере**

```bash
# IP forwarding включен?
sudo sysctl net.ipv4.ip_forward   # должно быть = 1

# NAT правила настроены?
sudo iptables -t nat -L -n -v | grep MASQUERADE   # Linux
sudo pfctl -s nat                                   # macOS

# Логи сервера
sudo journalctl -u gatekeeper -f
```

**4. Ручная проверка на клиенте**

```bash
# TUN интерфейс создан?
ifconfig | grep utun   # macOS
ip addr | grep tun     # Linux

# Маршруты настроены?
netstat -rn | grep "0.0.0.0"
```

## Безопасность

| Компонент | Реализация |
|-----------|------------|
| Handshake | Noise Protocol IK pattern |
| Key Exchange | X25519 (Curve25519) |
| Encryption | ChaCha20-Poly1305 (AEAD) |
| Hash | BLAKE2s |
| Replay Protection | SlidingWindow (2048-bit bitmap) |
| Authorization | Per-client public key whitelist |
| Nonce | 8-byte counter (little-endian) |
| DoS Protection | Cookie challenge + per-IP rate limiting |
| Roaming Auth | AEAD decrypt = identity proof (no re-handshake) |
| Obfuscation | Header XOR (BLAKE2s-derived), random padding, junk packets |

Криптография реализована через библиотеку [snow](https://crates.io/crates/snow) — проверенную реализацию Noise Protocol Framework.

## Известные ограничения

### Глобальный Mutex на сервере

Серверное состояние защищено `Arc<Mutex<Server>>`. Каждый пакет (входящий и исходящий)
проходит через этот единственный лок:

- Шифрование/расшифровка выполняется внутри мьютекса
- При roaming — brute-force `can_decrypt()` по всем клиентам тоже под локом
- Contention растёт линейно с числом клиентов и объёмом трафика

**На практике:** достаточно для десятков клиентов. При сотнях клиентов с высоким
трафиком мьютекс станет узким горлом и потребуется рефакторинг на per-client locks
или lock-free структуры (`DashMap`). Transport уже thread-safe — криптографию
можно вынести за пределы лока.

## Порты и протоколы

- **UDP 51820** — основной порт VPN (можно изменить в `listen`)

## Требования

- **ОС:** Linux (Ubuntu/Debian) или macOS
- **Права:** Root (для создания TUN-интерфейса)
- **Сборка:** Rust 1.75+

## Лицензия

MIT
