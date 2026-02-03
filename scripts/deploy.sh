#!/bin/bash
#
# GatekeeperVPN — скрипт деплоя на сервер
#
# Два режима работы:
#   1) build  — git push + сборка на сервере через SSH (по умолчанию)
#   2) binary — кросс-компиляция локально + отправка бинарников через SCP
#
# Использование:
#   ./scripts/deploy.sh                          # режим build (по умолчанию)
#   ./scripts/deploy.sh build                    # то же самое
#   ./scripts/deploy.sh binary                   # кросс-компиляция + SCP
#   ./scripts/deploy.sh build --no-restart       # без рестарта сервиса
#   SERVER=user@host ./scripts/deploy.sh         # переопределить сервер
#
# Переменные окружения:
#   SERVER        — SSH-адрес сервера (по умолчанию root@<из конфига>)
#   REMOTE_DIR    — путь к проекту на сервере (по умолчанию /opt/gatekeepervpn)
#   SSH_KEY       — путь к SSH-ключу (опционально)
#   BRANCH        — git-ветка для деплоя (по умолчанию main)
#

set -euo pipefail

# ─── Цвета ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── Конфигурация ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Значения по умолчанию (переопределяются через env)
SERVER="${SERVER:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/gatekeepervpn}"
SSH_KEY="${SSH_KEY:-}"
BRANCH="${BRANCH:-main}"
NO_RESTART=false

# Бинарники для деплоя
BINARIES=("gatekeeper-server" "gatekeeper-client" "gkvpn")
REMOTE_BIN_DIR="/usr/local/bin"
SERVICE_NAME="gatekeeper"

# SSH-опции
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
if [ -n "$SSH_KEY" ]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

# ─── Файл конфигурации деплоя ─────────────────────────────────────────────────

DEPLOY_CONF="$PROJECT_DIR/.deploy.conf"

load_deploy_config() {
    if [ -f "$DEPLOY_CONF" ]; then
        info "Загружаю конфигурацию из .deploy.conf"
        # shellcheck source=/dev/null
        source "$DEPLOY_CONF"
    fi
}

create_deploy_config() {
    if [ -f "$DEPLOY_CONF" ]; then
        return
    fi

    echo ""
    info "Файл .deploy.conf не найден. Создаю..."
    echo ""

    read -rp "SSH-адрес сервера (например root@84.246.85.36): " input_server
    read -rp "Путь к проекту на сервере [$REMOTE_DIR]: " input_dir
    read -rp "Путь к SSH-ключу (оставьте пустым для default): " input_key
    read -rp "Git-ветка для деплоя [$BRANCH]: " input_branch

    cat > "$DEPLOY_CONF" << EOF
# GatekeeperVPN deploy configuration
# Этот файл создан автоматически. Отредактируйте по необходимости.
SERVER="${input_server}"
REMOTE_DIR="${input_dir:-$REMOTE_DIR}"
SSH_KEY="${input_key}"
BRANCH="${input_branch:-$BRANCH}"
EOF

    ok "Конфигурация сохранена в .deploy.conf"
    echo ""

    # Перезагрузить
    source "$DEPLOY_CONF"
}

# ─── Парсинг аргументов ───────────────────────────────────────────────────────

MODE="${1:-build}"
shift || true

for arg in "$@"; do
    case "$arg" in
        --no-restart) NO_RESTART=true ;;
        *) warn "Неизвестный аргумент: $arg" ;;
    esac
done

# ─── Валидация ─────────────────────────────────────────────────────────────────

validate_server() {
    if [ -z "$SERVER" ]; then
        err "Не указан сервер. Задайте SERVER=user@host или создайте .deploy.conf"
    fi
}

check_ssh() {
    info "Проверяю SSH-подключение к $SERVER..."
    if ! ssh $SSH_OPTS "$SERVER" "echo ok" &>/dev/null; then
        err "Не удалось подключиться к $SERVER"
    fi
    ok "SSH-подключение успешно"
}

# ─── Режим BUILD: сборка на сервере ───────────────────────────────────────────

deploy_build() {
    info "═══ Режим: сборка на сервере ═══"
    echo ""

    validate_server
    check_ssh

    # 1. Проверяем есть ли незакоммиченные изменения
    cd "$PROJECT_DIR"
    if ! git diff --quiet HEAD 2>/dev/null; then
        warn "Есть незакоммиченные изменения!"
        read -rp "Продолжить без коммита? (y/N): " yn
        case "$yn" in
            [Yy]*) ;;
            *) err "Закоммитьте изменения и попробуйте снова" ;;
        esac
    fi

    # 2. Пушим в remote
    info "Пушу ветку $BRANCH в remote..."
    if git push origin "$BRANCH" 2>/dev/null; then
        ok "Git push выполнен"
    else
        warn "Git push не удался (возможно, уже up-to-date)"
    fi

    # 3. Сборка на сервере
    info "Запускаю сборку на сервере..."
    ssh $SSH_OPTS "$SERVER" bash -s << REMOTE_SCRIPT
        set -euo pipefail
        cd "$REMOTE_DIR" || { echo "ERROR: Директория $REMOTE_DIR не найдена"; exit 1; }

        echo "[INFO] Git pull..."
        git fetch origin "$BRANCH"
        git checkout "$BRANCH"
        git reset --hard "origin/$BRANCH"

        echo "[INFO] Сборка release..."
        source "\$HOME/.cargo/env" 2>/dev/null || true
        cargo build --release 2>&1 | tail -5

        echo "[INFO] Установка бинарников..."
        cp target/release/gatekeeper-server "$REMOTE_BIN_DIR/" 2>/dev/null || sudo cp target/release/gatekeeper-server "$REMOTE_BIN_DIR/"
        cp target/release/gatekeeper-client "$REMOTE_BIN_DIR/" 2>/dev/null || sudo cp target/release/gatekeeper-client "$REMOTE_BIN_DIR/"
        cp target/release/gkvpn "$REMOTE_BIN_DIR/" 2>/dev/null || sudo cp target/release/gkvpn "$REMOTE_BIN_DIR/"

        echo "[OK] Бинарники установлены"

        # Показать версии
        ls -la "$REMOTE_BIN_DIR"/gatekeeper-* "$REMOTE_BIN_DIR"/gkvpn 2>/dev/null
REMOTE_SCRIPT

    ok "Сборка на сервере завершена"

    # 4. Рестарт
    if [ "$NO_RESTART" = false ]; then
        restart_service
    else
        warn "Рестарт пропущен (--no-restart)"
    fi

    echo ""
    ok "═══ Деплой завершён! ═══"
}

# ─── Режим BINARY: кросс-компиляция + SCP ────────────────────────────────────

deploy_binary() {
    info "═══ Режим: кросс-компиляция + отправка бинарников ═══"
    echo ""

    validate_server
    check_ssh

    # 1. Определяем target
    local target="x86_64-unknown-linux-gnu"

    # Проверяем архитектуру сервера
    local remote_arch
    remote_arch=$(ssh $SSH_OPTS "$SERVER" "uname -m" 2>/dev/null)
    if [ "$remote_arch" = "aarch64" ]; then
        target="aarch64-unknown-linux-gnu"
    fi
    info "Target: $target (сервер: $remote_arch)"

    # 2. Проверяем наличие cross или cargo с target
    cd "$PROJECT_DIR"
    if command -v cross &>/dev/null; then
        info "Кросс-компиляция через cross..."
        cross build --release --target "$target" 2>&1 | tail -5
    else
        info "Кросс-компиляция через cargo (нужен линкер для $target)..."
        if ! cargo build --release --target "$target" 2>&1 | tail -10; then
            echo ""
            err "Кросс-компиляция не удалась. Установите:
  cargo install cross
  # или
  brew install FiloSottile/musl-cross/musl-cross  (для musl target)

  Или используйте режим build: ./scripts/deploy.sh build"
        fi
    fi

    ok "Компиляция завершена"

    # 3. Отправляем бинарники
    local build_dir="$PROJECT_DIR/target/$target/release"
    info "Отправляю бинарники на $SERVER..."

    for bin in "${BINARIES[@]}"; do
        local local_path="$build_dir/$bin"
        if [ ! -f "$local_path" ]; then
            warn "Бинарник не найден: $local_path"
            continue
        fi

        local size
        size=$(du -h "$local_path" | cut -f1)
        info "  $bin ($size)..."
        scp $SSH_OPTS "$local_path" "$SERVER:/tmp/$bin"
        ssh $SSH_OPTS "$SERVER" "sudo mv /tmp/$bin $REMOTE_BIN_DIR/$bin && sudo chmod +x $REMOTE_BIN_DIR/$bin"
        ok "  $bin установлен"
    done

    ok "Бинарники отправлены"

    # 4. Рестарт
    if [ "$NO_RESTART" = false ]; then
        restart_service
    else
        warn "Рестарт пропущен (--no-restart)"
    fi

    echo ""
    ok "═══ Деплой завершён! ═══"
}

# ─── Рестарт сервиса ──────────────────────────────────────────────────────────

restart_service() {
    info "Перезапускаю сервис $SERVICE_NAME..."
    ssh $SSH_OPTS "$SERVER" bash -s << RESTART_SCRIPT
        set -euo pipefail
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            sudo systemctl restart "$SERVICE_NAME"
            sleep 2
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                echo "[OK] Сервис $SERVICE_NAME перезапущен"
                sudo systemctl status "$SERVICE_NAME" --no-pager -l | head -15
            else
                echo "[ERROR] Сервис не запустился!"
                sudo journalctl -u "$SERVICE_NAME" --no-pager -n 20
                exit 1
            fi
        else
            echo "[WARN] Сервис $SERVICE_NAME не был запущен. Запускаю..."
            sudo systemctl start "$SERVICE_NAME"
            sleep 2
            sudo systemctl status "$SERVICE_NAME" --no-pager -l | head -15
        fi
RESTART_SCRIPT
    ok "Сервис перезапущен"
}

# ─── Справка ──────────────────────────────────────────────────────────────────

show_help() {
    cat << 'HELP'
GatekeeperVPN Deploy Script

Использование:
  ./scripts/deploy.sh [MODE] [OPTIONS]

Режимы:
  build    Git push + сборка на сервере через SSH (по умолчанию)
  binary   Кросс-компиляция локально + отправка бинарников через SCP
  help     Показать эту справку

Опции:
  --no-restart   Не перезапускать сервис после деплоя

Конфигурация:
  При первом запуске создаётся файл .deploy.conf с настройками.
  Также можно задать через переменные окружения:

  SERVER=root@1.2.3.4    SSH-адрес сервера
  REMOTE_DIR=/opt/gkvpn  Путь к проекту на сервере
  SSH_KEY=~/.ssh/id_rsa   Путь к SSH-ключу
  BRANCH=main             Git-ветка для деплоя

Примеры:
  ./scripts/deploy.sh                          # build на сервере
  ./scripts/deploy.sh binary                   # кросс-компиляция + SCP
  ./scripts/deploy.sh build --no-restart       # без рестарта
  SERVER=root@84.246.85.36 ./scripts/deploy.sh # с указанием сервера
HELP
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo ""
    info "GatekeeperVPN Deploy"
    info "$(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # Загрузить / создать конфиг
    load_deploy_config

    if [ -z "$SERVER" ]; then
        create_deploy_config
    fi

    case "$MODE" in
        build)  deploy_build ;;
        binary) deploy_binary ;;
        help|-h|--help) show_help ;;
        *) err "Неизвестный режим: $MODE. Используйте: build, binary, help" ;;
    esac
}

main
