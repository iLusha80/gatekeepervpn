# GatekeeperVPN — Roadmap

Идеи, задачи и планы развития.

---

## Что реализовано

| Функция | Описание |
|---------|----------|
| Noise IK handshake | Безопасное соединение с forward secrecy |
| ChaCha20-Poly1305 | AEAD-шифрование всего трафика |
| X25519 key exchange | Эллиптический обмен ключами |
| Replay protection | SlidingWindow 2048 бит |
| Per-client IP | Уникальный IP из пула для каждого клиента |
| Авторизация | Белый список через peers.toml |
| Unicast роутинг | Пакеты идут конкретному клиенту по destination IP |
| NAT | Автоматическая настройка iptables/pf |
| Hot-reload peers | Изменения peers.toml без перезапуска |
| Keep-alive + reconnect | Обнаружение обрывов и автопереподключение |
| Graceful shutdown | Очистка маршрутов и NAT при остановке |
| CLI (gkvpn) | Управление клиентами командами |
| Systemd + setup script | Автоустановка на Linux |
| DoS protection | Cookie challenge + rate limiting |
| Cleanup неактивных | Автоотключение idle-клиентов (client_timeout) |
| DNS через VPN | Автонастройка DNS при подключении (macOS/Linux) |
| Метрики | AtomicU64 счётчики, JSON stats, `gkvpn status` |
| Traffic Obfuscation | Anti-DPI: header XOR, random padding/header, junk packets (PSK-based) |

---

## Phase 2: GUI и удобство

### macOS приложение
Нативное menubar-приложение: Connect/Disconnect, статус, профили, импорт конфигурации.
- Swift/SwiftUI + Network Extension framework
- IPC с Rust core (socket или XPC)
- Notarization для распространения

| Важность | Сложность | Вау-эффект |
|----------|-----------|------------|
| 5 | 4 | 5 |

### iOS приложение
NEPacketTunnelProvider, on-demand VPN, Keychain для ключей.
- Rust -> iOS binding (UniFFI или swift-bridge)
- SwiftUI, background keep-alive

| Важность | Сложность | Вау-эффект |
|----------|-----------|------------|
| 4 | 5 | 5 |

### QR-код для настройки
`gkvpn qr "client-name"` — генерация QR для быстрого импорта на телефон.

| Важность | Сложность | Вау-эффект |
|----------|-----------|------------|
| 3 | 2 | 4 |

### Docker-образы
Multi-stage build, Alpine base, volume для конфигов, health check.

| Важность | Сложность | Вау-эффект |
|----------|-----------|------------|
| 4 | 2 | 3 |

---

## Phase 3: Feature parity с WireGuard

### IPv6 поддержка
Парсинг IPv6 пакетов, dual-stack TUN, IPv6 маршрутизация, ip6tables.

| Важность | Сложность |
|----------|-----------|
| 3 | 3 |

### Roaming
Обновление client endpoint при валидном пакете с нового адреса. Переключение WiFi/LTE без разрыва.

| Важность | Сложность |
|----------|-----------|
| 4 | 3 |

### AllowedIPs (Cryptokey Routing)
Гибкая маршрутизация: per-peer allowed_ips, валидация source IP.

| Важность | Сложность |
|----------|-----------|
| 3 | 3 |

### Key Rotation
Периодическая смена session keys (re-handshake каждые N минут) для forward secrecy.

| Важность | Сложность |
|----------|-----------|
| 3 | 4 |

---

## Phase 4: Безопасность и обфускация

### ~~Traffic Obfuscation~~ ✅ (базовый уровень)
~~Маскировка VPN трафика под HTTPS.~~ Реализовано: header XOR (BLAKE2s), random padding, random header, junk packets. Включено по умолчанию.

**Следующий уровень:** TLS wrapper (rustls) — маскировка под HTTPS, pluggable transports.

| Важность | Сложность |
|----------|-----------|
| 4 | 4 |

### Audit Logging
Structured JSON logging, log rotation, remote logging (syslog).

| Важность | Сложность |
|----------|-----------|
| 3 | 2 |

### MFA
TOTP или FIDO2 дополнительно к ключу при handshake.

| Важность | Сложность |
|----------|-----------|
| 2 | 4 |

### Post-Quantum криптография
Hybrid: X25519 + Kyber768.

| Важность | Сложность |
|----------|-----------|
| 1 | 4 |

---

## Phase 5: Инфраструктура

### CI/CD Pipeline
GitHub Actions: тесты на PR, cross-compilation (Linux ARM, macOS), автоматические релизы.

| Важность | Сложность |
|----------|-----------|
| 4 | 2 |

### Пакеты
Debian (.deb), RPM, AUR, Homebrew formula.

| Важность | Сложность |
|----------|-----------|
| 3 | 3 |

### Web-панель администратора
REST API + фронтенд: подключённые клиенты, метрики, управление peers.

| Важность | Сложность |
|----------|-----------|
| 2 | 4 |

---

## Phase 6: Производительность (low priority)

- **MTU Discovery** — автоподбор оптимального MTU (PMTUD)
- **Zero-Copy I/O** — io_uring, splice, buffer pooling
- **Multi-threading** — per-client crypto offload, lock-free structures
- **Hardware Acceleration** — AES-NI, AVX2/AVX512 для ChaCha20

---

## Сравнение с WireGuard

| Функция | WireGuard | GatekeeperVPN |
|---------|-----------|---------------|
| Noise Protocol | yes | yes |
| ChaCha20-Poly1305 | yes | yes |
| Replay protection | yes | yes |
| Per-client IP | yes | yes |
| Keep-alive | yes | yes |
| Cookie anti-DoS | yes | yes |
| DNS push | yes | yes |
| Hot-reload | no | yes |
| Metrics/stats | no | yes |
| IPv6 | yes | -- |
| Roaming | yes | -- |
| AllowedIPs | yes | -- |
| Key rotation | yes | -- |
| Kernel mode | yes | -- |
| GUI | wg-quick | -- |
| Traffic obfuscation | no | yes (anti-DPI) |
