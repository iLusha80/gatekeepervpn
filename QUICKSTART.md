# 🚀 Быстрый старт GatekeeperVPN

## Установка сервера (5 минут)

### На ЧИСТОМ сервере Ubuntu/Debian:

```bash
# 1. Подключитесь к серверу
ssh root@YOUR_SERVER_IP

# 2. Клонируйте репозиторий
cd /opt
git clone https://github.com/your-username/gatekeepervpn.git
cd gatekeepervpn

# 3. Запустите автоматическую установку
sudo bash scripts/setup-server-full.sh
```

**Готово!** Сервер установлен и запущен автоматически.

---

## Добавление первого клиента

```bash
# На сервере
SERVER_IP=$(curl -s ifconfig.me)
sudo gkvpn add "myclient" --server-address $SERVER_IP:51820

# Посмотреть профиль клиента
sudo gkvpn show "myclient"
```

---

## Подключение клиента

### Скопировать профиль с сервера:

```bash
# На клиенте (Mac/Linux)
scp root@YOUR_SERVER_IP:/etc/gatekeeper/profiles/myclient.conf ~/
```

### Подключиться:

```bash
# На Mac (если еще не собран клиент)
cd /path/to/gatekeepervpn
cargo build --release --bin gatekeeper-client

# Подключиться
sudo ./target/release/gatekeeper-client -c ~/myclient.conf
```

### Проверить работу:

```bash
# В другом окне терминала
ping -c 3 10.10.10.1    # VPN сервер
ping -c 3 8.8.8.8       # Интернет
curl ifconfig.me        # Должен показать IP сервера
```

---

## Проверка состояния сервера

```bash
# Статус сервиса
sudo systemctl status gatekeeper

# Логи
sudo journalctl -u gatekeeper -f

# Список клиентов
sudo gkvpn list

# Диагностика
sudo bash /opt/gatekeepervpn/scripts/diagnose.sh
```

---

## Управление клиентами

```bash
# Добавить
sudo gkvpn add "client-name" --server-address YOUR_IP:51820

# Список
sudo gkvpn list

# Показать профиль
sudo gkvpn show "client-name"

# Удалить
sudo gkvpn remove "client-name"
```

---

## Если что-то не работает

### 1. Проверьте external_interface в конфигурации:

```bash
# Должен быть ваш внешний интерфейс (ens3, eth0 и т.д.), НЕ tun0!
grep external_interface /etc/gatekeeper/server.toml
```

### 2. Запустите диагностику:

```bash
sudo bash /opt/gatekeepervpn/scripts/diagnose.sh
```

### 3. Проверьте NAT правила:

```bash
sudo iptables -t nat -L -n | grep MASQUERADE
sudo iptables -L FORWARD -n | grep tun
sysctl net.ipv4.ip_forward  # должно быть = 1
```

---

## 📚 Подробная документация

- **Полная инструкция по установке**: [INSTALL.md](INSTALL.md)
- **Общая документация**: [README.md](README.md)
- **Диагностика проблем**: [README.md#диагностика-проблем](README.md#диагностика-проблем)

---

**Всё! Ваш VPN готов к работе.** 🎉
