# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

* Отвечай **на русском языке строго**
* Используй `context7` MCP tool для проверки актуальной документации библиотек
* При предложении кода учитывать тестируемость и дальнейшую интеграцию в GUI (macOS / iOS)

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
| `handshake` | Noise IK protocol: `Initiator`, `Responder`, `Transport` |
| `protocol` | Бинарный протокол: `Packet`, `PacketType` |
| `crypto` | Генерация ключей X25519 |
| `transport` | `StatelessTransportState` + replay protection (SlidingWindow) |
| `tun_device` | Async TUN интерфейс |
| `routing` | Настройка системных маршрутов |
| `socket` | Настройка UDP буферов |
| `logging` | Rate-limited логирование |
| `config` | `ClientConfig`, `ServerConfig` (TOML) |

### Поток данных

```
Client:  TUN read → encrypt → UDP send → Server
Server:  UDP recv → decrypt → TUN write → kernel routing → response
```

### Handshake (Noise IK)

1. Client → Server: `HandshakeInit` (e, es, s, ss)
2. Server → Client: `HandshakeResponse` (e, ee, se)
3. Обе стороны переходят в `Transport` mode с session keys

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

---

## Non-Goals (MVP)

* GUI, Mobile SDK
* Advanced obfuscation (TLS camouflage, QUIC mimicry)
* Multi-server routing
