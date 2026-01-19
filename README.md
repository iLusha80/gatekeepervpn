# GatekeeperVPN

Простой и безопасный VPN на Rust. Использует Noise Protocol (как WireGuard) для шифрования.

## Возможности

- **Noise IK handshake** — безопасное установление соединения
- **ChaCha20-Poly1305** — быстрое шифрование
- **Per-client IP** — каждый клиент получает уникальный IP
- **Авторизация** — только клиенты из белого списка
- **Unicast роутинг** — трафик идёт только нужному клиенту
- **Автоматическая настройка NAT** — сервер автоматически включает IP forwarding и настраивает NAT
- **Hot-reload** — изменения peers.toml применяются без перезапуска
- **Keep-alive + автопереподключение**

## Быстрый старт

### Сборка

```bash
cargo build --release
```

### Установка сервера (Linux)

```bash
./scripts/setup.sh # если вошли под root
```

Скрипт интерактивно настроит:
- Подсеть VPN (по умолчанию 10.10.10.0/24)
- Генерацию ключей
- Определение внешнего интерфейса для NAT
- Systemd сервис

**Примечание:** Сервер автоматически настроит NAT и IP forwarding при запуске (если `enable_nat = true`)

### Ручная настройка

#### 1. Генерация конфигурации сервера

```bash
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
sudo gatekeeper-server -c /etc/gatekeeper/server.toml -p /etc/gatekeeper/peers.toml
```

Или через systemd:
```bash
sudo systemctl start gatekeeper
```

### Клиент

```bash
sudo gatekeeper-client -c /path/to/laptop-ilya.conf
```

**DNS:** Клиент не меняет DNS автоматически. Для работы с доменными именами:

```bash
# macOS
sudo networksetup -setdnsservers "Wi-Fi" 8.8.8.8 1.1.1.1

# Linux (добавить в /etc/resolv.conf)
nameserver 8.8.8.8
nameserver 1.1.1.1
```

## CLI (gkvpn)

```bash
gkvpn init                    # Инициализация peers.toml
gkvpn add "name"              # Добавить клиента
gkvpn remove "name"           # Удалить клиента
gkvpn list                    # Список клиентов
gkvpn show "name"             # Показать профиль клиента
gkvpn generate-server         # Сгенерировать конфиг сервера
gkvpn show-public --key "..." # Показать публичный ключ
```

## Структура файлов

```
/etc/gatekeeper/
├── server.toml      # Конфигурация сервера
├── peers.toml       # База клиентов (сервер следит за изменениями)
└── profiles/        # Готовые конфиги для клиентов
    ├── laptop.conf
    └── phone.conf
```

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

**Важно:** Укажите правильный внешний сетевой интерфейс для вашего сервера:
- Узнать интерфейсы: `ip link show` (Linux) или `ifconfig` (macOS)
- Обычно это: `eth0`, `ens3`, `ens5` на Linux; `en0` на macOS

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
```

## Проверка работы VPN

После подключения клиента проверьте:

```bash
# Проверить маршруты
netstat -rn | grep utun  # macOS
ip route | grep tun      # Linux

# Проверить доступность интернета
ping -c 3 8.8.8.8

# Проверить внешний IP (должен быть IP сервера)
curl ifconfig.me

# Проверить доступ к сайтам
curl -I https://google.com
```

### Диагностика проблем

#### Автоматическая диагностика (сервер)

Запустите скрипт диагностики на сервере:

```bash
sudo ./scripts/diagnose.sh
```

Этот скрипт проверит:
- ✅ Конфигурацию server.toml (external_interface, enable_nat)
- ✅ Сетевые интерфейсы
- ✅ IP forwarding
- ✅ NAT/iptables правила
- ✅ Статус systemd сервиса
- ✅ Подключение к интернету

**Типичная проблема:** `external_interface = "tun0"` в конфигурации

❌ **Неправильно:**
```toml
external_interface = "tun0"  # tun0 - это сам VPN интерфейс!
```

✅ **Правильно:**
```toml
external_interface = "ens3"  # или eth0, ens5 - ваш внешний интерфейс
```

Узнать правильный интерфейс:
```bash
ip route show default  # покажет основной интерфейс
```

#### Ручная проверка на сервере

```bash
# IP forwarding включен?
sudo sysctl net.ipv4.ip_forward  # должно быть = 1

# NAT правила настроены?
sudo iptables -t nat -L -n -v | grep MASQUERADE  # Linux
sudo pfctl -s nat                                # macOS

# Статус сервера
sudo systemctl status gatekeeper
sudo journalctl -u gatekeeper -f
```

#### Проверка на клиенте

```bash
# TUN интерфейс создан?
ifconfig | grep utun  # macOS
ip addr | grep tun    # Linux

# Маршруты настроены?
netstat -rn | grep "0.0.0.0"
```

## Порты и протоколы

- **UDP 51820** — основной порт VPN (можно изменить)

## Требования

- Linux или macOS
- Root права (для TUN интерфейса)
- Rust 1.75+ (для сборки)

## Безопасность

- Noise Protocol IK pattern
- X25519 для обмена ключами
- ChaCha20-Poly1305 для шифрования
- Защита от replay-атак (SlidingWindow)
- Авторизация по публичному ключу

## Лицензия

MIT
