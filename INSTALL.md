# Установка GatekeeperVPN Server

Полная пошаговая инструкция по установке и настройке VPN сервера на чистой системе Linux.

## 📋 Требования

- **ОС**: Ubuntu 20.04+, Debian 11+, CentOS 8+, или другой Linux
- **Права**: Root доступ (sudo)
- **Сеть**: Публичный IP адрес
- **Память**: Минимум 512MB RAM
- **Диск**: Минимум 2GB свободного места

---

## 🚀 Быстрая установка (рекомендуется)

### Вариант 1: Установка из исходников (на чистом сервере)

```bash
# 1. Подключитесь к серверу
ssh root@YOUR_SERVER_IP

# 2. Склонируйте репозиторий
cd /opt
git clone https://github.com/your-username/gatekeepervpn.git
cd gatekeepervpn

# 3. Запустите автоматическую установку
sudo bash scripts/setup-server-full.sh
```

**Скрипт автоматически:**
- ✅ Установит все зависимости (build-essential, pkg-config, iptables и т.д.)
- ✅ Установит Rust (если не установлен)
- ✅ Соберет проект из исходников
- ✅ Установит бинарники в /usr/local/bin
- ✅ Создаст конфигурацию с правильным external_interface
- ✅ Настроит IP forwarding
- ✅ Настроит NAT через iptables
- ✅ Создаст и запустит systemd сервис

**Время установки:** 5-10 минут (зависит от скорости сервера).

---

### Вариант 2: Установка с уже собранными бинарниками

Если вы собрали проект на локальной машине:

```bash
# 1. На локальной машине соберите проект
cd /path/to/gatekeepervpn
cargo build --release

# 2. Скопируйте файлы на сервер
scp -r scripts root@YOUR_SERVER_IP:/opt/gatekeepervpn/
scp -r target/release root@YOUR_SERVER_IP:/opt/gatekeepervpn/target/

# 3. На сервере запустите установку
ssh root@YOUR_SERVER_IP
cd /opt/gatekeepervpn
sudo bash scripts/setup-server-full.sh
```

---

## 📝 Пошаговая установка вручную

Если хотите контролировать каждый шаг:

### Шаг 1: Установка зависимостей

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    git \
    iptables \
    iptables-persistent

# CentOS/RHEL
sudo yum install -y \
    gcc \
    gcc-c++ \
    make \
    pkgconfig \
    openssl-devel \
    curl \
    git \
    iptables-services
```

### Шаг 2: Установка Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version
```

### Шаг 3: Клонирование и сборка

```bash
cd /opt
git clone https://github.com/your-username/gatekeepervpn.git
cd gatekeepervpn

cargo build --release
```

### Шаг 4: Установка бинарников

```bash
sudo install -m 755 target/release/gatekeeper-server /usr/local/bin/
sudo install -m 755 target/release/gatekeeper-client /usr/local/bin/
sudo install -m 755 target/release/gkvpn /usr/local/bin/
```

### Шаг 5: Создание конфигурации

```bash
# Создать директории
sudo mkdir -p /etc/gatekeeper/profiles

# Сгенерировать конфигурацию сервера
sudo gkvpn generate-server \
    --listen "0.0.0.0:51820" \
    --tun-address "10.10.10.1" \
    --output /etc/gatekeeper/server.toml

# ВАЖНО! Добавить external_interface в конфигурацию
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "" | sudo tee -a /etc/gatekeeper/server.toml
echo "# NAT configuration" | sudo tee -a /etc/gatekeeper/server.toml
echo "external_interface = \"$INTERFACE\"" | sudo tee -a /etc/gatekeeper/server.toml
echo "enable_nat = true" | sudo tee -a /etc/gatekeeper/server.toml

# Инициализировать пул клиентов
sudo gkvpn --config-dir /etc/gatekeeper init \
    --subnet 10.10.10.0 \
    --mask 24 \
    --force

# Установить права
sudo chmod 600 /etc/gatekeeper/server.toml
sudo chmod 600 /etc/gatekeeper/peers.toml
```

### Шаг 6: Настройка сети

```bash
# Включить IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-gatekeeper.conf

# Определить внешний интерфейс
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "External interface: $INTERFACE"

# Настроить NAT
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$INTERFACE" -j MASQUERADE

# Настроить FORWARD правила
sudo iptables -A FORWARD -i tun+ -j ACCEPT
sudo iptables -A FORWARD -o tun+ -j ACCEPT
sudo iptables -A FORWARD -i tun+ -o "$INTERFACE" -j ACCEPT
sudo iptables -A FORWARD -i "$INTERFACE" -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

# Сохранить правила
sudo netfilter-persistent save
# ИЛИ
sudo iptables-save > /etc/iptables/rules.v4
```

### Шаг 7: Создание systemd сервиса

```bash
sudo tee /etc/systemd/system/gatekeeper.service > /dev/null << 'EOF'
[Unit]
Description=GatekeeperVPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gatekeeper-server -c /etc/gatekeeper/server.toml -p /etc/gatekeeper/peers.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

# Security
NoNewPrivileges=no
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/gatekeeper

[Install]
WantedBy=multi-user.target
EOF

# Включить и запустить сервис
sudo systemctl daemon-reload
sudo systemctl enable gatekeeper
sudo systemctl start gatekeeper
```

### Шаг 8: Проверка работы

```bash
# Проверить статус сервиса
sudo systemctl status gatekeeper

# Посмотреть логи
sudo journalctl -u gatekeeper -n 50

# Проверить NAT правила
sudo iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE
sudo iptables -L FORWARD -n -v | grep tun

# Проверить IP forwarding
sysctl net.ipv4.ip_forward
```

---

## 👥 Добавление клиентов

После успешной установки сервера:

```bash
# Узнать публичный IP сервера
curl ifconfig.me

# Добавить клиента (замените YOUR_SERVER_IP на реальный IP)
sudo gkvpn add "laptop-01" --server-address YOUR_SERVER_IP:51820

# Профиль будет создан в:
# /etc/gatekeeper/profiles/laptop-01.conf

# Просмотреть профиль
sudo gkvpn show "laptop-01"

# Список всех клиентов
sudo gkvpn list
```

### Копирование профиля на клиента

```bash
# Скопировать профиль с сервера на клиента
scp root@YOUR_SERVER_IP:/etc/gatekeeper/profiles/laptop-01.conf ~/
```

---

## 💻 Установка клиента

### На Linux:

```bash
# Установить клиент
sudo cp gatekeeper-client /usr/local/bin/

# Подключиться
sudo gatekeeper-client -c laptop-01.conf
```

### На macOS:

```bash
# Собрать клиент на Mac
cargo build --release --bin gatekeeper-client

# Подключиться
sudo ./target/release/gatekeeper-client -c laptop-01.conf
```

---

## 🔍 Диагностика проблем

### Автоматическая диагностика

```bash
# На сервере запустите скрипт диагностики
sudo bash /opt/gatekeepervpn/scripts/diagnose.sh
```

### Ручная проверка на сервере

```bash
# Проверить сервис
sudo systemctl status gatekeeper
sudo journalctl -u gatekeeper -n 50

# Проверить IP forwarding
sysctl net.ipv4.ip_forward  # должно быть = 1

# Проверить NAT
sudo iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE
sudo iptables -L FORWARD -n -v | grep tun

# Проверить TUN интерфейс
ip addr show tun0
ip route | grep tun0

# Проверить external_interface в конфигурации
grep external_interface /etc/gatekeeper/server.toml
```

### Типичные проблемы

#### ❌ Проблема: external_interface = "tun0"

**Решение:**
```bash
# Определить правильный интерфейс
ip route show default
# Вывод: default via X.X.X.X dev ens3

# Исправить конфигурацию
sudo nano /etc/gatekeeper/server.toml
# Изменить: external_interface = "ens3"

# Перезапустить
sudo systemctl restart gatekeeper
```

#### ❌ Проблема: IP forwarding отключен

**Решение:**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-gatekeeper.conf
```

#### ❌ Проблема: NAT не настроен

**Решение:**
```bash
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$INTERFACE" -j MASQUERADE
sudo iptables -A FORWARD -i tun+ -j ACCEPT
sudo iptables -A FORWARD -o tun+ -j ACCEPT
sudo netfilter-persistent save
```

---

## 🛠️ Управление сервером

```bash
# Статус
sudo systemctl status gatekeeper

# Остановить
sudo systemctl stop gatekeeper

# Запустить
sudo systemctl start gatekeeper

# Перезапустить
sudo systemctl restart gatekeeper

# Логи в реальном времени
sudo journalctl -u gatekeeper -f

# Последние 100 строк логов
sudo journalctl -u gatekeeper -n 100
```

---

## 🔒 Безопасность

### Firewall (ufw)

```bash
# Разрешить SSH
sudo ufw allow 22/tcp

# Разрешить VPN порт
sudo ufw allow 51820/udp

# Включить firewall
sudo ufw enable
```

### Обновление

```bash
cd /opt/gatekeepervpn
git pull
cargo build --release
sudo systemctl stop gatekeeper
sudo install -m 755 target/release/gatekeeper-server /usr/local/bin/
sudo systemctl start gatekeeper
```

---

## 📚 Дополнительная информация

- **Документация**: [README.md](README.md)
- **Диагностика**: `scripts/diagnose.sh`
- **Примеры конфигурации**: `server.example.toml`, `client.example.toml`

---

## ✅ Проверка успешной установки

После установки выполните:

```bash
# На сервере
sudo systemctl status gatekeeper  # должен быть active (running)
sudo iptables -t nat -L -n | grep MASQUERADE  # должно быть правило
sysctl net.ipv4.ip_forward  # должно быть = 1

# Добавить тестового клиента
sudo gkvpn add "test" --server-address $(curl -s ifconfig.me):51820

# На клиенте (после копирования профиля)
sudo gatekeeper-client -c test.conf

# Проверить подключение (в другом окне на клиенте)
ping -c 3 10.10.10.1  # должен пинговаться VPN сервер
ping -c 3 8.8.8.8     # должен работать интернет
curl ifconfig.me      # должен показать IP сервера
```

Если все команды работают - **поздравляем, VPN настроен!** 🎉

---

## 🆘 Поддержка

Если возникли проблемы:

1. Запустите диагностику: `sudo bash scripts/diagnose.sh`
2. Проверьте логи: `sudo journalctl -u gatekeeper -n 100`
3. Создайте issue на GitHub с выводом диагностики и логов
