# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# GatekeeperVPN

GatekeeperVPN — это собственный VPN-протокол и реализация VPN-сервера и клиента на Rust,
ориентированные на:
- высокую производительность (по аналогии с WireGuard),
- простоту архитектуры,
- устойчивость к блокировкам (DPI, сигнатуры),
- модульность и расширяемость (desktop и mobile клиенты в будущем).

Проект изначально разрабатывается как закрытый MVP,
с возможностью последующего open-source релиза.


---

## Rules

* Отвечай **на русском языке строго**
* Используй всегда актуальные версии библиотек и инструментов (для этого не забывай проверять информацию в mcp context7 ПО необходимости)
* Always use the `context7` tool to fetch documentation when I ask about specific libraries, APIs, or if you are unsure about the latest syntax
* Всегда учитывать, что проект собирается и управляется через **cargo**
* При предложении кода:
  * учитывать тестируемость
  * учитывать дальнейшую интеграцию в GUI (macOS / iOS)

---

## Build & Development Commands

```bash
# Сборка
cargo build              # debug-сборка
cargo build --release    # release-сборка

# Тесты
cargo test               # запуск всех тестов
cargo test <test_name>   # запуск одного теста
cargo test --package <crate_name>  # тесты конкретного crate

# Форматирование и линтинг
cargo fmt                # форматирование кода
cargo fmt --check        # проверка форматирования
cargo clippy             # линтер

# Запуск
cargo run --bin server   # запуск сервера (после создания)
cargo run --bin client   # запуск клиента (после создания)
```

---

## Project Overview

GatekeeperVPN — собственный VPN-протокол и реализация на Rust:
- Высокая производительность (по аналогии с WireGuard)
- Устойчивость к блокировкам (DPI-resistance)
- Модульность для будущих desktop/mobile клиентов

### Планируемая структура (cargo workspace)

```
gatekeepervpn/
├── Cargo.toml           # workspace root
├── crates/
│   ├── common/          # общие типы, протокол, криптография
│   ├── server/          # VPN-сервер
│   ├── client/          # CLI-клиент
│   └── keygen/          # генерация ключей и конфигов
```

### Компоненты

- **Server**: принимает подключения, handshake, шифрование трафика, маршрутизация
- **Client**: создаёт TUN-интерфейс, перенаправляет трафик через туннель
- **Keygen**: генерация ключей и клиентских конфигов

---

## Cryptography

* **Key exchange**: Noise Protocol Framework (библиотека `snow`)
* **Curve**: X25519
* **Symmetric**: ChaCha20-Poly1305
* **Hash**: BLAKE2s
* Session-based keys

Не изобретать собственную криптографию — использовать только `snow`, `ring`.

---

## Tech Stack

* **Rust**
* **Async**: Tokio
* **Crypto**: snow, ring
* **TUN/TAP**: tun-tap (macOS)
* **CLI**: clap
* **Config**: serde + toml
* **Logging**: log + env_logger
* **Errors**: thiserror

---

## Code Guidelines

* `cargo fmt` обязателен
* `unsafe` запрещён без крайней необходимости
* Ошибки через `Result` + `thiserror`
* Модули маленькие и изолированные
* Криптографические тесты не должны зависеть от сети

---

## Non-Goals (MVP)

* GUI
* Mobile SDK
* Advanced obfuscation (TLS camouflage, QUIC mimicry)
* Multi-server routing
