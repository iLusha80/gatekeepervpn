# Architecture

## Crate-зависимости

```
                    +-----------------+
                    | gatekeeper-     |
                    | common (lib)    |
                    +-----------------+
                     /       |        \
                    /        |         \
          +--------+   +--------+   +--------+
          | server |   | client |   | keygen |
          | (bin)  |   | (bin)  |   | (bin)  |
          +--------+   +--------+   +--------+
```

Все три бинарных крейта зависят от `gatekeeper-common`.
Между собой `server`, `client` и `keygen` не связаны.

---

## gatekeeper-common (библиотека)

Общие примитивы, переиспользуемые всеми бинарями.

| Модуль | Файл | Назначение |
|--------|------|------------|
| `crypto` | `crypto.rs` | X25519 keypair generation, Noise IK pattern constant |
| `handshake` | `handshake.rs` | Noise IK: `Initiator`, `Responder`, `Transport`, `can_decrypt()` |
| `protocol` | `protocol.rs` | Бинарный протокол: `Packet`, `PacketType` (HandshakeInit/Response, Data, KeepAlive, Cookie) |
| `transport` | (внутри `handshake.rs`) | `StatelessTransportState` + replay protection (`SlidingWindow`) |
| `obfuscation` | `obfuscation.rs` | Anti-DPI: `PacketObfuscator` — XOR header, random padding, junk packets; PSK из server public key |
| `cookie` | `cookie.rs` | DoS protection: `CookieState` (BLAKE2s MAC), `HandshakeRateLimiter` (per-IP + global) |
| `config` | `config.rs` | `ServerConfig`, `ClientConfig`, `PeerConfig`, `PeersConfig`, `ObfuscationConfig` (TOML) |
| `tun_device` | `tun_device.rs` | Async TUN: `TunDevice`, `TunReader`, `TunWriter`, `TunConfig` |
| `routing` | `routing.rs` | Маршруты клиента: `RouteConfig`, `setup_routes()`, `cleanup_routes()`, `update_server_route()` |
| `nat` | `nat.rs` | NAT сервера: `NatConfig`, `setup_nat()`, `cleanup_nat()`, `enable_ip_forwarding()` (Linux/macOS) |
| `dns` | `dns.rs` | DNS клиента: `DnsConfig`, `DnsState`, `setup_dns()`, `cleanup_dns()` |
| `socket` | `socket.rs` | UDP socket buffers: `configure_socket()` (2 MB default) |
| `ip_pool` | `ip_pool.rs` | Пул VPN IP-адресов для сервера |
| `ip_parser` | `ip_parser.rs` | Парсинг IPv4 заголовков: `get_destination_ip()`, `get_source_ip()` для unicast routing |
| `metrics` | `metrics.rs` | `VpnMetrics` — атомарные счётчики (packets, bytes, handshakes, replay, roaming) |
| `logging` | `logging.rs` | `RateLimitedLogger`, `VpnErrorLoggers` — rate-limited логирование |
| `error` | `error.rs` | `Error` enum (Crypto, Io, InvalidPacket, ReplayedPacket, Config, Tun, Route, Dns, Obfuscation) |

---

## server crate

```
crates/server/src/
├── main.rs          — точка входа: Args, парсинг конфигов, запуск режимов
├── server.rs        — struct Server, ConnectedClient, AuthorizedPeer + impl Server
├── echo.rs          — run_echo_mode(): echo-сервер без TUN (для тестов)
├── vpn.rs           — run_vpn_mode(): TUN + UDP задачи + NAT + cleanup
├── config.rs        — load_config(), load_peers_config(), get_file_modified_time()
└── signal.rs        — shutdown_signal(): SIGINT/SIGTERM handler
```

### Ключевые структуры

```rust
struct Server {
    private_key: Vec<u8>,
    clients: HashMap<Ipv4Addr, ConnectedClient>,       // primary key = VPN IP
    endpoint_to_ip: HashMap<SocketAddr, Ipv4Addr>,     // reverse index для roaming
    authorized_peers: HashMap<[u8; 32], AuthorizedPeer>,
    auth_enabled: bool,
    cookie_state: CookieState,
    rate_limiter: HandshakeRateLimiter,
}

struct ConnectedClient {
    transport: Transport,
    assigned_ip: Ipv4Addr,
    name: String,
    last_activity: Instant,
    endpoint: SocketAddr,       // мutable — меняется при roaming
}
```

### Задачи в VPN mode (tokio::spawn)

| Задача | Описание |
|--------|----------|
| `peers_watcher` | Горячая перезагрузка peers.toml (каждые 5 сек) |
| `udp_to_tun` | UDP recv → decrypt → TUN write (+ handshake, roaming detection) |
| `tun_to_udp` | TUN read → parse dst IP → encrypt → UDP send (unicast routing) |
| `cleanup_task` | Удаление неактивных клиентов по таймауту |
| `stats_writer` | Запись метрик в файл (каждые 10 сек) |

### Известное ограничение

`Arc<Mutex<Server>>` — глобальный мьютекс. Все операции сериализуются.
Решение (будущее): per-client locks (`DashMap`) + вынос crypto за пределы лока.

---

## client crate

```
crates/client/src/
├── main.rs          — точка входа: Args, загрузка конфигов, запуск
├── handshake.rs     — perform_handshake(), recv_packet(), HANDSHAKE_TIMEOUT
├── vpn.rs           — run_vpn_mode(), run_vpn_loop(), VpnExitReason, ConnectionState
├── test_mode.rs     — run_test_mode(): отправка сообщения + echo
├── connection.rs    — run_vpn_connection(): handshake + VPN + reconnect loop
└── signal.rs        — shutdown_signal(): SIGINT/SIGTERM handler
```

### Поток VPN-подключения

```
main()
  └─ connection::run_with_reconnect()     # reconnect loop
       └─ connection::run_vpn_connection() # single attempt
            ├─ handshake::perform_handshake()
            └─ vpn::run_vpn_mode()         # TUN setup + routes + DNS
                 └─ vpn::run_vpn_loop()    # data loop (tokio::select!)
                      ├─ TUN → UDP (encrypt + send)
                      ├─ UDP → TUN (recv + decrypt)
                      ├─ KeepAlive sender + timeout check
                      └─ shutdown_signal()
```

### Roaming (soft roam)

При `VpnExitReason::ConnectionTimeout`:
1. Пауза 500мс (стабилизация нового интерфейса)
2. `update_server_route()` — обновление маршрута через новый default gateway
3. Новый UDP socket → `connect()` к серверу
4. Roam ping (encrypted empty Data) → сервер обнаруживает roaming
5. Если ответ получен — продолжение с тем же `Transport`
6. Если таймаут — fallback на полный re-handshake

---

## keygen crate

```
crates/keygen/src/
└── main.rs          — CLI утилита управления ключами и конфигами
```

Бинарное имя: `gkvpn`

| Команда | Описание |
|---------|----------|
| `generate-server` | Генерация keypair + server.toml |
| `generate-client` | Генерация keypair + client.toml |
| `show-public` | Показать public key из private key |
| `init` | Инициализация peers.toml с пулом IP |
| `add` | Добавить peer в peers.toml |
| `remove` | Удалить peer из peers.toml |
| `list` | Список всех peers |
| `show` | Детали одного peer |

---

## Потоки данных

### VPN mode

```
Client                              Server
  │                                    │
  │── HandshakeInit ─────────────────>│
  │                                    │── create Responder
  │                                    │── verify public key (peers.toml)
  │<──────────────── HandshakeResponse│
  │                                    │
  │  [Transport mode established]      │
  │                                    │
  │── Data (encrypted IP packet) ────>│── decrypt → TUN write
  │                                    │              │
  │                                    │   kernel routing (IP forwarding)
  │                                    │              │
  │<──── Data (encrypted IP packet) ──│<─ TUN read ──┘
  │                                    │
  │── KeepAlive ─────────────────────>│
  │<──────────────────── KeepAliveAck │
```

### Echo mode (тестирование)

```
Client                              Server
  │── HandshakeInit ────────────────>│
  │<─────────────── HandshakeResponse│
  │── Data ("Hello") ──────────────>│── decrypt → "Echo: Hello"
  │<────────── Data ("Echo: Hello") ─│      → encrypt → send
```

### DoS protection flow

```
Client                              Server
  │── HandshakeInit ────────────────>│
  │                                  │── rate_limiter.check()
  │                                  │   ├── Allow → process handshake
  │                                  │   ├── RequireCookie → send CookieReply
  │<──────────────── CookieReply ────│   └── Drop → silently ignore
  │── HandshakeInitCookie ──────────>│── validate cookie → process
```

---

## Криптография

- **Noise pattern**: IK (клиент знает публичный ключ сервера заранее)
- **Key exchange**: X25519 (Curve25519 DH)
- **AEAD**: ChaCha20-Poly1305
- **Nonce**: 8-byte counter (little-endian), `SlidingWindow` для replay protection
- **Cookie MAC**: BLAKE2s с rotating secret (каждые 120 сек)
- **Obfuscation PSK**: BLAKE2s от server public key (автоматическая деривация)

---

## Platform support

| Функция | macOS | Linux |
|---------|-------|-------|
| TUN | `tun` crate (utun) | `tun` crate (/dev/tun) |
| Routing | `route` command | `ip route` |
| NAT | `pf` (pfctl) | `iptables` |
| DNS | `networksetup` | `/etc/resolv.conf` |
| IP forwarding | `sysctl net.inet.ip.forwarding` | `sysctl net.ipv4.ip_forward` |
