#!/usr/bin/env bash
#
# mac_spoof.sh - SecV module
# Automated MAC spoofer (per-interface background runner)
#
# Usage (via SecV):
#  - Provide params through SecV's JSON stdin (see module.json inputs)
#  - Or run interactively:
#      ./mac_spoof.sh
#
# Behavior:
#  - start (default), stop, status
#  - iface can be single or comma-separated list
#  - all_up=true will target all non-loopback interfaces that are UP
#  - spawner creates one runner per interface at /tmp/secv_mac_spoof_runner_<iface>.sh
#  - pidfile: /tmp/secv_mac_spoof_<iface>.pid
#  - log: /tmp/secv_mac_spoof_<iface>.log
#  - original MAC saved to /tmp/secv_mac_orig_<iface>.orig
#  - Changes every 0.5s (500ms). Each interface runner runs independently.
#

set -u
INTERVAL="0.5"
PREFIX="02:00:00"  # locally-administered OUI prefix (keeps OUI fixed)
TMPDIR="/tmp"
RUNNER_TEMPLATE="$TMPDIR/secv_mac_spoof_runner_TEMPLATE.sh"

# helpers
json_read_param() {
    local key="$1"
    python3 - "$key" <<'PY' 2>/dev/null
import sys, json
data = json.load(sys.stdin)
key = sys.argv[1]
parts = key.split('.')
val = data
for p in parts:
    val = val.get(p, {})
if val == {}:
    print("")
else:
    if isinstance(val, bool):
        print("true" if val else "false")
    else:
        print(val)
PY
}

which_cmd() {
    command -v "$1" >/dev/null 2>&1
}

ensure_ip() {
    if ! which_cmd ip; then
        echo "[-] 'ip' command not found. Install iproute2."
        return 1
    fi
    return 0
}

validate_iface_exists() {
    local iface="$1"
    [[ -d "/sys/class/net/$iface" ]]
}

get_all_up_ifaces() {
    # exclude loopback
    ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$' || true
}

gen_random_tail() {
    # produce three random octets
    printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

make_mac() {
    local tail
    tail=$(gen_random_tail)
    echo "${PREFIX}:${tail}"
}

save_orig_mac() {
    local iface="$1" path="${TMPDIR}/secv_mac_orig_${iface}.orig"
    if [[ -f "$path" ]]; then
        return 0
    fi
    local cur
    cur=$(cat "/sys/class/net/${iface}/address" 2>/dev/null || true)
    if [[ -n "$cur" ]]; then
        echo "$cur" > "$path"
        chmod 600 "$path" 2>/dev/null || true
    fi
}

read_saved_orig() {
    local iface="$1" path="${TMPDIR}/secv_mac_orig_${iface}.orig"
    [[ -f "$path" ]] && cat "$path" || echo ""
}

runner_path_for_iface() { echo "${TMPDIR}/secv_mac_spoof_runner_${1}.sh"; }
pidfile_for_iface() { echo "${TMPDIR}/secv_mac_spoof_${1}.pid"; }
log_for_iface() { echo "${TMPDIR}/secv_mac_spoof_${1}.log"; }

start_runner_for_iface() {
    local iface="$1"
    local dry_run="$2"
    local runner_path
    runner_path=$(runner_path_for_iface "$iface")
    local pidfile
    pidfile=$(pidfile_for_iface "$iface")
    local logfile
    logfile=$(log_for_iface "$iface")

    # check iface exists
    if ! validate_iface_exists "$iface"; then
        echo "[-] Interface '$iface' does not exist. Skipping."
        return 2
    fi

    # ensure not already running
    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "[*] Runner already active for $iface (pid $pid)."
            return 0
        else
            echo "[*] Removing stale pidfile for $iface."
            rm -f "$pidfile" 2>/dev/null || true
        fi
    fi

    # save original MAC (if not saved)
    save_orig_mac "$iface"

    # create runner file content
    cat > "$runner_path" <<'RUNNER'
#!/usr/bin/env bash
IFACE="{{IFACE}}"
INTERVAL="{{INTERVAL}}"
PIDFILE="{{PIDFILE}}"
LOGFILE="{{LOGFILE}}"
PREFIX="{{PREFIX}}"

set -u
trap 'cleanup' SIGINT SIGTERM

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') $*" >> "$LOGFILE" 2>/dev/null
}

gen_tail() {
    printf "%02x:%02x:%02x" $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

set_mac() {
    local mac="$1"
    ip link set dev "$IFACE" down 2>/dev/null
    ip link set dev "$IFACE" address "$mac" 2>/dev/null
    ip link set dev "$IFACE" up 2>/dev/null
}

cleanup() {
    # attempt to restore original if saved
    local orig_file="/tmp/secv_mac_orig_${IFACE}.orig"
    if [[ -f "$orig_file" ]]; then
        local orig
        orig=$(cat "$orig_file" 2>/dev/null || echo "")
        if [[ -n "$orig" ]]; then
            ip link set dev "$IFACE" down 2>/dev/null
            ip link set dev "$IFACE" address "$orig" 2>/dev/null
            ip link set dev "$IFACE" up 2>/dev/null
            log "RESTORED $IFACE -> $orig"
        fi
    fi
    rm -f "$PIDFILE" 2>/dev/null || true
    exit 0
}

# write pidfile
echo $$ > "$PIDFILE" 2>/dev/null

# main loop
while true; do
    tail=$(gen_tail)
    mac="${PREFIX}:${tail}"
    if set_mac "$mac"; then
        log "SET $IFACE -> $mac"
    else
        log "FAILED SET $IFACE -> $mac"
    fi
    sleep "$INTERVAL"
done
RUNNER

    # replace placeholders
    sed -i "s|{{IFACE}}|$iface|g" "$runner_path"
    sed -i "s|{{INTERVAL}}|$INTERVAL|g" "$runner_path"
    sed -i "s|{{PIDFILE}}|$pidfile|g" "$runner_path"
    sed -i "s|{{LOGFILE}}|$logfile|g" "$runner_path"
    sed -i "s|{{PREFIX}}|$PREFIX|g" "$runner_path"
    chmod 750 "$runner_path" 2>/dev/null || true

    if [[ "$dry_run" == "true" ]]; then
        echo "[DRY-RUN] Would start runner: $runner_path (pidfile $pidfile, log $logfile)"
        return 0
    fi

    # start background
    nohup bash "$runner_path" >/dev/null 2>&1 &
    local pid=$!
    # wait for pidfile to be created by runner (small loop)
    for i in $(seq 1 10); do
        if [[ -f "$pidfile" ]]; then break; fi
        sleep 0.05
    done
    # if pidfile wasn't created, write known pid (best-effort)
    if [[ ! -f "$pidfile" ]]; then
        echo "$pid" > "$pidfile" 2>/dev/null || true
    fi
    echo "[+] Started runner for $iface (pid $pid). pidfile: $pidfile log: $logfile"
    return 0
}

stop_runner_for_iface() {
    local iface="$1"
    local pidfile
    pidfile=$(pidfile_for_iface "$iface")
    if [[ ! -f "$pidfile" ]]; then
        echo "[-] No runner pidfile for $iface."
        return 2
    fi
    local pid
    pid=$(cat "$pidfile" 2>/dev/null || echo "")
    if [[ -n "$pid" ]]; then
        kill -TERM "$pid" 2>/dev/null || true
        sleep 0.1
    fi
    # attempt cleanup: runner removes pidfile and restores original
    if [[ -f "$pidfile" ]]; then
        rm -f "$pidfile" 2>/dev/null || true
    fi
    echo "[+] Stop requested for $iface (pid ${pid:-unknown})."
    return 0
}

status_runner_for_iface() {
    local iface="$1"
    local pidfile
    pidfile=$(pidfile_for_iface "$iface")
    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "[+] Runner active for $iface (pid $pid)."
            return 0
        else
            echo "[-] Stale pidfile for $iface. Removing."
            rm -f "$pidfile" 2>/dev/null || true
            return 3
        fi
    else
        echo "[-] No runner for $iface."
        return 2
    fi
}

# End of functions for start/stop/status
