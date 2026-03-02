# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

* Отвечай **на русском языке строго**
* Используй `context7` MCP tool для проверки актуальной документации библиотек
* При предложении кода учитывать тестируемость и дальнейшую интеграцию в GUI (macOS / iOS)

Подробная архитектура и карта файлов: [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Build & Development Commands

```bash
cargo build                          # debug-сборка
cargo build --release                # release-сборка
cargo test                           # все тесты
cargo test --package gatekeeper-common  # тесты common crate
cargo fmt && cargo clippy            # форматирование + линтер

# Запуск (требует root для TUN)
sudo cargo run --bin server -- -c server.toml
sudo cargo run --bin client -- -c client.toml
cargo run --bin server -- --echo     # echo mode без TUN (для тестов)
cargo run --bin client -- --test     # тест handshake без TUN

# Генерация ключей
cargo run --bin keygen -- generate -o keys/
cargo run --bin keygen -- show-public -k keys/private.key
```

---

## Architecture

### Модули gatekeeper-common

| Модуль | Назначение |
|--------|------------|
| `handshake` | Noise IK protocol: `Initiator`, `Responder`, `Transport`, `can_decrypt()` |
| `protocol` | Бинарный протокол: `Packet`, `PacketType` |
| `crypto` | Генерация ключей X25519 |
| `transport` | `StatelessTransportState` + replay protection (SlidingWindow) |
| `tun_device` | Async TUN интерфейс (`TunDevice`, `TunReader`, `TunWriter`) |
| `routing` | Настройка системных маршрутов |
| `socket` | Настройка UDP буферов |
| `logging` | Rate-limited логирование |
| `config` | `ClientConfig`, `ServerConfig` (TOML) |
| `metrics` | `VpnMetrics` — атомарные счётчики (packets, bytes, handshakes, replay, roaming) |
| `obfuscation` | `PacketObfuscator` — anti-DPI: XOR header, random padding, junk packets |
| `cookie` | `CookieState`, `HandshakeRateLimiter` — DoS protection |
| `nat` | Настройка NAT (iptables/pf) |
| `dns` | Настройка DNS при подключении клиента |
| `ip_pool` | Пул VPN IP-адресов |
| `ip_parser` | Парсинг IP-заголовков для unicast routing |

### Поток данных

```
Client:  TUN read → encrypt → UDP send → Server
Server:  UDP recv → decrypt → TUN write → kernel routing → response
```

### Handshake (Noise IK)

1. Client → Server: `HandshakeInit` (e, es, s, ss)
2. Server → Client: `HandshakeResponse` (e, ee, se)
3. Обе стороны переходят в `Transport` mode с session keys

### Roaming (переключение сети без разрыва)

Подход WireGuard: успешная расшифровка AEAD = аутентификация отправителя.

**Сервер:**
- Primary key клиентов = VPN IP (`clients: HashMap<Ipv4Addr, ConnectedClient>`)
- Обратный индекс `endpoint_to_ip: HashMap<SocketAddr, Ipv4Addr>`
- Data от неизвестного addr → brute-force `can_decrypt()` по всем клиентам → обновление endpoint
- KeepAlive от неизвестного addr → игнорируется (roaming сработает по Data)

**Клиент:**
- `run_vpn_loop` возвращает `VpnExitReason` (Shutdown / ConnectionTimeout)
- Мгновенное обнаружение потери сети: EADDRNOTAVAIL / NetworkUnreachable → немедленный roam (без ожидания keepalive timeout)
- При roam: пауза 500мс → `update_server_route()` (новый default gateway) → новый UDP socket → roam ping → retry
- Если soft roam не удался → fallback на полный re-handshake

### Серверная архитектура (известное ограничение)

**`Arc<Mutex<Server>>`** — глобальный мьютекс на всё серверное состояние. Все операции
(UDP→TUN, TUN→UDP, handshake, cleanup) сериализуются через этот лок. Это основное
узкое горло при масштабировании:

- Каждый входящий/исходящий пакет блокирует мьютекс
- Шифрование/расшифровка пакетов происходит внутри лока
- При N клиентах с высоким трафиком — contention растёт линейно
- Brute-force roaming detection (O(n) `can_decrypt` вызовов) тоже под мьютексом

**Решение (будущее):** заменить на per-client locks или lock-free структуру:
```
HashMap<Ipv4Addr, Arc<RwLock<ConnectedClient>>>   # per-client lock
DashMap<Ipv4Addr, ConnectedClient>                 # lock-free concurrent map
```
Шифрование/расшифровку вынести за пределы лока (Transport уже thread-safe).

---

## Cryptography

* **Noise pattern**: IK (клиент знает публичный ключ сервера)
* **Key exchange**: X25519
* **AEAD**: ChaCha20-Poly1305
* **Nonce**: 8-byte counter (little-endian) + SlidingWindow для replay protection

Не изобретать криптографию — только `snow`.

---

## Error Handling

```rust
// В common используем thiserror
pub enum Error {
    Crypto(snow::Error),
    Io(std::io::Error),
    InvalidPacket,
    ReplayedPacket,  // для replay protection
    // ...
}

// В client/server используем anyhow для контекста
.context("Failed to perform handshake")?
```

---

## Code Guidelines

* `cargo fmt` обязателен перед коммитом
* `unsafe` запрещён без крайней необходимости
* Криптографические тесты не должны зависеть от сети
* Rate-limited логирование для частых ошибок (UDP buffer overflow, replay packets)
* `Transport` — thread-safe без внешнего Mutex (`AtomicU64` counter + `Mutex` внутри SlidingWindow)

---

## Non-Goals (MVP)

* GUI, Mobile SDK
* Advanced obfuscation (TLS camouflage, QUIC mimicry)
* Multi-server routing

## Vibe Kanban — Task Management

This project uses **vibe-kanban** for task tracking via MCP.
Board: http://localhost:3000/projects/0abafe93-63ab-4f02-b297-cb5104e0ea46

### MCP Connection

Endpoint: `http://127.0.0.1:8001/mcp`
Project ID: `0abafe93-63ab-4f02-b297-cb5104e0ea46`

### Workflow

**STRICT: One task at a time.** Take → implement → complete → next.

1. `list_notes(status="new")` — check for user ideas, create tasks from them
2. `list_tasks(status="todo")` — see available tasks
3. `take_task(task_id, agent_id="claude-code")` — claim a task
4. Implement the task (write code, tests, etc.)
5. `complete_task(task_id, result_comment="what was done", agent_report="detailed markdown report")`
6. Tasks with `has_result=true` go to **review** (human checks), others go to **done**

### Available MCP Tools

| Tool | Purpose |
|------|---------|
| `list_tasks` | List tasks. Filter by status/priority/is_blocked/agent_id |
| `get_task` | Get full task details: description, detail, agent_report |
| `take_task` | Take a task — sets in_progress, assigns agent_id, starts timer |
| `complete_task` | Complete task with result_comment and agent_report |
| `update_task` | Update task fields (description, detail, priority) |
| `block_task` | Block a task with reason |
| `unblock_task` | Unblock a task |
| `create_task` | Create a new task |
| `list_stages` | List project stages |
| `list_notes` | List project notes from user |
| `update_note` | Mark note as processed after creating tasks from it |

### Rules

- Use `agent_id="claude-code"` when taking tasks
- Write `agent_report` in markdown — describe what was done, which files changed, what to verify
- Always respond to the user in Russian
- The board at http://localhost:3000 updates in real-time — human sees cards move
