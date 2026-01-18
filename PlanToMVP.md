# GatekeeperVPN — План развёртывания MVP

## Обзор

Развёртывание VPN между VPS-сервером (Ubuntu) и клиентом (macOS).

---

## Этап 1: Сборка на локальной машине (macOS)

```bash
# Сборка release-версий
cargo build --release

# Результат:
# target/release/gatekeeper-server
# target/release/gatekeeper-client
# target/release/gatekeeper-keygen
```

---

## Этап 2: Подготовка сервера (Ubuntu VPS)

### 2.1. Копирование бинарников на сервер

```bash
# С локальной машины
scp target/release/gatekeeper-server user@YOUR_VPS_IP:/usr/local/bin/
scp target/release/gatekeeper-keygen user@YOUR_VPS_IP:/usr/local/bin/

# Или кросс-компиляция для Linux:
# cargo build --release --target x86_64-unknown-linux-gnu
```

### 2.2. Генерация ключей на сервере

```bash
ssh user@YOUR_VPS_IP

# Генерация конфига сервера
sudo gatekeeper-keygen generate-server \
  --listen "0.0.0.0:51820" \
  --tun-address "10.0.0.1" \
  -o /etc/gatekeeper/server.toml

# ВАЖНО: Скопировать server_public_key из вывода!
# Пример: server_public_key = "ABC123...xyz="
```

### 2.3. Настройка NAT и firewall

```bash
# Включить IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Настроить NAT (замените eth0 на ваш интерфейс)
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i utun+ -j ACCEPT
sudo iptables -A FORWARD -o utun+ -j ACCEPT

# Открыть порт UDP
sudo ufw allow 51820/udp
```

### 2.4. Запуск сервера

```bash
# Запуск (требует root для TUN)
sudo gatekeeper-server -c /etc/gatekeeper/server.toml

# Или как systemd сервис (см. ниже)
```

---

## Этап 3: Настройка клиента (macOS)

### 3.1. Генерация конфига клиента

```bash
# На локальной машине
# Используем server_public_key полученный на этапе 2.2

./target/release/gatekeeper-keygen generate-client \
  --server-key "ABC123...xyz=" \
  --server "YOUR_VPS_IP:51820" \
  --tun-address "10.0.0.2" \
  -o ~/.config/gatekeeper/client.toml
```

### 3.2. Запуск клиента

```bash
# Требует root для создания TUN интерфейса
sudo ./target/release/gatekeeper-client -c ~/.config/gatekeeper/client.toml
```

---

## Этап 4: Проверка соединения

```bash
# На клиенте — пинг сервера через туннель
ping 10.0.0.1

# На сервере — пинг клиента
ping 10.0.0.2

# Проверка внешнего IP (должен быть IP сервера)
curl ifconfig.me
```

---

## Дополнительно: Systemd сервис для сервера

Создать файл `/etc/systemd/system/gatekeeper.service`:

```ini
[Unit]
Description=GatekeeperVPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gatekeeper-server -c /etc/gatekeeper/server.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable gatekeeper
sudo systemctl start gatekeeper
sudo systemctl status gatekeeper
```

---

## Структура файлов

### Сервер (Ubuntu VPS)
```
/usr/local/bin/gatekeeper-server
/usr/local/bin/gatekeeper-keygen
/etc/gatekeeper/server.toml
```

### Клиент (macOS)
```
~/bin/gatekeeper-client          # или в target/release/
~/bin/gatekeeper-keygen
~/.config/gatekeeper/client.toml
```

---

## Checklist

- [ ] Сборка release на macOS
- [ ] Копирование бинарников на VPS
- [ ] Генерация server.toml на VPS
- [ ] Сохранение server_public_key
- [ ] Настройка NAT на VPS
- [ ] Открытие порта 51820/udp
- [ ] Запуск сервера на VPS
- [ ] Генерация client.toml на macOS
- [ ] Запуск клиента на macOS
- [ ] Проверка ping 10.0.0.1
- [ ] Проверка curl ifconfig.me
