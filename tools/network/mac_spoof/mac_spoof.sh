#!/usr/bin/env bash
#
# mac_spoof.sh - SecV module (Bash)
# Automated MAC spoofer (per-interface background runner)
#
# - Keeps OUI prefix 02:00:00 (locally-administered).
# - Randomizes last 3 octets every 0.5s.
# - One runner per interface -> pidfile /tmp/secv_mac_spoof_<iface>.pid
# - Log: /tmp/secv_mac_spoof_<iface>.log
# - Original MAC saved to /tmp/secv_mac_orig_<iface>.orig
#
set -u

INTERVAL="0.5"
PREFIX="02:00:00"         # locally-administered OUI prefix
TMPDIR="/tmp"

# ---- helpers ----
which_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_ip() {
    if ! which_cmd ip; then
        echo "[-] 'ip' command not found. Install iproute2." >&2
        return 1
    fi
    return 0
}

validate_iface_exists() {
    local iface="$1"
    [[ -d "/sys/class/net/$iface" ]]
}

get_all_up_ifaces() {
    ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v '^lo$' || true
}

gen_random_tail() {
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

# ---- per-interface runner creator/start/stop/status ----

start_runner_for_iface() {
    local iface="$1"
    local dry_run="$2"
    local runner_path pidfile logfile
    runner_path=$(runner_path_for_iface "$iface")
    pidfile=$(pidfile_for_iface "$iface")
    logfile=$(log_for_iface "$iface")

    if ! validate_iface_exists "$iface"; then
        echo "[-] Interface '$iface' does not exist. Skipping." >&2
        return 2
    fi

    # already running?
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

    # save original mac (if not saved)
    save_orig_mac "$iface"

    # create runner script
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

# write pidfile for this runner
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

    # start background runner (nohup so it survives parent exit)
    nohup bash "$runner_path" >/dev/null 2>&1 &
    local pid=$!
    # wait briefly for runner to create its pidfile
    for i in $(seq 1 10); do
        if [[ -f "$pidfile" ]]; then break; fi
        sleep 0.05
    done
    # if runner didn't write pidfile, write best-effort pid
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

# ---- main: read JSON from stdin (SecV pipes {"target":"...","params":{...}}) ----

CTX_JSON=""
if ! CTX_JSON=$(cat); then
    CTX_JSON=""
fi

# parse params
PARAM_IFACE=$(echo "$CTX_JSON" | python3 - <<'PY' 2>/dev/null
import sys,json
try:
    j=json.load(sys.stdin) or {}
    p=j.get('params',{})
    print(p.get('iface','') or '')
except:
    print('')
PY
)

PARAM_ALL_UP=$(echo "$CTX_JSON" | python3 - <<'PY' 2>/dev/null
import sys,json
try:
    j=json.load(sys.stdin) or {}
    p=j.get('params',{})
    v=p.get('all_up',False)
    print('true' if v in [True,'true','True','1','yes'] else 'false')
except:
    print('false')
PY
)

PARAM_ACTION=$(echo "$CTX_JSON" | python3 - <<'PY' 2>/dev/null
import sys,json
try:
    j=json.load(sys.stdin) or {}
    p=j.get('params',{})
    print(p.get('action','start') or 'start')
except:
    print('start')
PY
)

PARAM_DRY_RUN=$(echo "$CTX_JSON" | python3 - <<'PY' 2>/dev/null
import sys,json
try:
    j=json.load(sys.stdin) or {}
    p=j.get('params',{})
    v=p.get('dry_run',False)
    print('true' if v in [True,'true','True','1','yes'] else 'false')
except:
    print('false')
PY
)

# interactive prompt if needed
if [[ -z "$PARAM_IFACE" && "$PARAM_ALL_UP" != "true" ]]; then
    printf "Interface to spoof (single, csv list, or 'all_up'): "
    read -r USER_IFACE || true
    if [[ -n "$USER_IFACE" ]]; then
        if [[ "$USER_IFACE" == "all_up" ]]; then
            PARAM_ALL_UP="true"
        else
            PARAM_IFACE="$USER_IFACE"
        fi
    fi
fi

# build target list
TARGET_IFACES=()
if [[ "$PARAM_ALL_UP" == "true" ]]; then
    while read -r ifc; do
        [[ -z "$ifc" ]] && continue
        TARGET_IFACES+=("$ifc")
    done < <(get_all_up_ifaces)
else
    if [[ -n "$PARAM_IFACE" ]]; then
        IFS=',' read -r -a parts <<< "$PARAM_IFACE"
        for p in "${parts[@]}"; do
            p=$(echo "$p" | xargs)
            [[ -n "$p" ]] && TARGET_IFACES+=("$p")
        done
    fi
fi

if [[ ${#TARGET_IFACES[@]} -eq 0 ]]; then
    echo "[-] No target interfaces found. Provide iface or set all_up true." >&2
    exit 1
fi

# ensure ip is present
if ! ensure_ip; then
    exit 2
fi

ACTION="${PARAM_ACTION:-start}"
DRY_RUN="${PARAM_DRY_RUN:-false}"

case "$ACTION" in
    start)
        if [[ "$DRY_RUN" != "true" && "$EUID" -ne 0 ]]; then
            echo "[-] Root required to change MACs. Run with sudo." >&2
            exit 3
        fi
        for ifc in "${TARGET_IFACES[@]}"; do
            start_runner_for_iface "$ifc" "$DRY_RUN"
        done
        ;;
    stop)
        for ifc in "${TARGET_IFACES[@]}"; do
            stop_runner_for_iface "$ifc"
            # try immediate restore
            orig=$(read_saved_orig "$ifc")
            if [[ -n "$orig" && "$DRY_RUN" != "true" ]]; then
                echo "[*] Restoring $ifc -> $orig"
                ip link set dev "$ifc" down 2>/dev/null || true
                ip link set dev "$ifc" address "$orig" 2>/dev/null || true
                ip link set dev "$ifc" up 2>/dev/null || true
                rm -f "${TMPDIR}/secv_mac_orig_${ifc}.orig" 2>/dev/null || true
            fi
        done
        ;;
    status)
        for ifc in "${TARGET_IFACES[@]}"; do
            status_runner_for_iface "$ifc"
        done
        ;;
    *)
        echo "[-] Unknown action: $ACTION" >&2
        exit 4
        ;;
esac

exit 0
