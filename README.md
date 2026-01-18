# GatekeeperVPN

Простой и безопасный VPN на Rust. Использует Noise Protocol (как WireGuard) для шифрования.

## Возможности

- **Noise IK handshake** — безопасное установление соединения
- **ChaCha20-Poly1305** — быстрое шифрование
- **Per-client IP** — каждый клиент получает уникальный IP
- **Авторизация** — только клиенты из белого списка
- **Unicast роутинг** — трафик идёт только нужному клиенту
- **Hot-reload** — изменения peers.toml применяются без перезапуска
- **Keep-alive + автопереподключение**

## Быстрый старт

### Сборка

```bash
cargo build --release
```

### Установка сервера (Linux)

```bash
sudo ./scripts/setup.sh
```

Скрипт интерактивно настроит:
- Подсеть VPN (по умолчанию 10.10.10.0/24)
- Генерацию ключей
- NAT и firewall
- Systemd сервис

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
tun_address = "10.10.10.1"
tun_netmask = "255.255.255.0"
tun_mtu = 1400
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
