#!/bin/bash
# start_backend.sh - Bring the BAS backend API service online (no hardware runtime)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PORT="${PORT:-8080}"
LOG_FILE="$REPO_ROOT/server.log"
PID_FILE="$REPO_ROOT/server.pid"

cd "$REPO_ROOT"

print_status() {
    printf '\033[0;32m✅ %s\033[0m\n' "$1"
}

print_info() {
    printf '\033[0;34mℹ️  %s\033[0m\n' "$1"
}

print_warning() {
    printf '\033[1;33m⚠️  %s\033[0m\n' "$1"
}

print_error() {
    printf '\033[0;31m❌ %s\033[0m\n' "$1"
}

cleanup_on_exit() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        print_info "Stopping backend (PID: $SERVER_PID)"
        kill "$SERVER_PID" 2>/dev/null || true
    fi
}

trap cleanup_on_exit INT TERM

if [[ -f "config/auth.env" ]]; then
    print_info "Loading environment from config/auth.env"
    set -a
    # shellcheck disable=SC1091
    source "config/auth.env"
    set +a
fi

ensure_venv() {
    if [[ ! -d ".venv" ]]; then
        print_info "Creating Python virtual environment (.venv)"
        python3 -m venv .venv
    fi

    # shellcheck disable=SC1091
    source .venv/bin/activate

    if ! python -c "import flask" >/dev/null 2>&1; then
        print_info "Installing backend dependencies"
        python -m pip install --upgrade pip >/dev/null 2>&1 || true
        python -m pip install -r apps/api/requirements.txt
    fi
}

start_backend() {
    local py_bin
    py_bin="$(python -c 'import sys; print(sys.executable)')"

    if lsof -ti ":$PORT" >/dev/null 2>&1; then
        print_warning "Port $PORT already in use; attempting to free it"
        lsof -ti ":$PORT" | xargs kill -9 2>/dev/null || true
        sleep 2
    fi

    print_info "Starting backend on port $PORT"
    PORT="$PORT" LOG_FILE="$LOG_FILE" nohup "$py_bin" -m apps.api.main \
        >"$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" >"$PID_FILE"

    sleep 2

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        print_status "Backend started (PID: $SERVER_PID)"
        print_info "Dashboard: http://localhost:$PORT"
        print_info "Logs: tail -f $LOG_FILE"
    else
        print_error "Backend failed to start; check $LOG_FILE"
        rm -f "$PID_FILE"
        exit 1
    fi
}

ensure_venv
start_backend

wait "$SERVER_PID"

