#!/usr/bin/env bash
# secV installer
# Reads all rqm.md files in the repo tree and installs listed dependencies.
# Contributors add their tool's requirements to the rqm.md in their module directory.
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'
info()  { echo -e "${CYN}[*]${RST} $*"; }
ok()    { echo -e "${GRN}[+]${RST} $*"; }
warn()  { echo -e "${YLW}[!]${RST} $*"; }

# ── rqm.md parser ────────────────────────────────────────────────────────────
# Collects packages from all rqm.md files. Call after setting DISTRO.
# Populates globals: RQM_PY_PKGS RQM_OS_PKGS
declare -a RQM_PY_PKGS=()
declare -a RQM_OS_PKGS=()
declare -A _seen_py=() _seen_os=()

load_rqm_files() {
    local section=""
    local os_section=""

    case "$DISTRO" in
        arch)   os_section="pacman" ;;
        debian) os_section="apt"    ;;
        *)      os_section=""       ;;
    esac

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        section=""
        while IFS= read -r line || [[ -n "$line" ]]; do
            # strip leading/trailing whitespace
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            # skip blank lines and full-line comments
            [[ -z "$line" || "$line" == \#* ]] && {
                # detect section markers
                case "$line" in
                    "#python") section="python" ;;
                    "#pacman") section="pacman" ;;
                    "#apt")    section="apt"    ;;
                    "#binary") section="binary" ;;
                esac
                continue
            }
            # strip inline comment
            pkg="${line%%#*}"
            pkg="${pkg%"${pkg##*[![:space:]]}"}"
            [[ -z "$pkg" ]] && continue

            case "$section" in
                python)
                    [[ -z "${_seen_py[$pkg]+x}" ]] && { RQM_PY_PKGS+=("$pkg"); _seen_py["$pkg"]=1; }
                    ;;
                "$os_section")
                    [[ -z "${_seen_os[$pkg]+x}" ]] && { RQM_OS_PKGS+=("$pkg"); _seen_os["$pkg"]=1; }
                    ;;
            esac
        done < "$file"
    done < <(find "$SCRIPT_DIR" -name "rqm.md" 2>/dev/null | sort)

    info "rqm.md: found ${#RQM_PY_PKGS[@]} python pkgs, ${#RQM_OS_PKGS[@]} OS pkgs"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect package manager ────────────────────────────────────────────────────
if command -v pacman &>/dev/null; then
    PKG_INSTALL="sudo pacman -S --noconfirm --needed"
    PKG_UPDATE="sudo pacman -Sy"
    DISTRO="arch"
elif command -v apt-get &>/dev/null; then
    PKG_INSTALL="sudo apt-get install -y"
    PKG_UPDATE="sudo apt-get update -qq"
    DISTRO="debian"
else
    warn "Unsupported package manager — install system packages manually"
    PKG_INSTALL="echo SKIP"
    PKG_UPDATE="true"
    DISTRO="unknown"
fi

info "Detected: $DISTRO - installer starting"
$PKG_UPDATE || true

# Load rqm.md files from the repo tree
load_rqm_files

# ── System packages (from rqm.md) ─────────────────────────────────────────────
info "Installing system packages..."

if [ "${#RQM_OS_PKGS[@]}" -gt 0 ] && [ "$DISTRO" != "unknown" ]; then
    $PKG_INSTALL "${RQM_OS_PKGS[@]}" || warn "Some system packages failed - check manually"
else
    # Fallback if no rqm.md found or unsupported distro
    if [ "$DISTRO" = "arch" ]; then
        $PKG_INSTALL python python-pip nmap masscan arp-scan whois iproute2 \
            jdk-openjdk android-tools apktool nmap-ncat git curl wget || warn "Some system packages failed"
    elif [ "$DISTRO" = "debian" ]; then
        $PKG_INSTALL python3 python3-pip nmap masscan arp-scan whois iproute2 \
            android-tools-adb apktool default-jdk git curl wget || warn "Some system packages failed"
    fi
fi

if ! command -v jadx &>/dev/null; then
    if [ "$DISTRO" = "arch" ]; then
        warn "jadx not found - install via AUR: yay -S jadx"
    else
        warn "jadx not found - get it from github.com/skylot/jadx/releases"
    fi
fi

# ── Python packages (from rqm.md) ─────────────────────────────────────────────
info "Installing Python packages..."

if [ "${#RQM_PY_PKGS[@]}" -gt 0 ]; then
    pip3 install --break-system-packages --quiet "${RQM_PY_PKGS[@]}" 2>/dev/null \
        || pip3 install --quiet "${RQM_PY_PKGS[@]}" 2>/dev/null \
        || pip3 install --user --quiet "${RQM_PY_PKGS[@]}" || warn "Some pip packages failed"
else
    # Fallback hardcoded list
    pip3 install --break-system-packages --quiet \
        requests rich psutil scapy aiohttp netifaces frida-tools objection \
        cryptography flask qrcode pillow 2>/dev/null || warn "Some pip packages failed"
fi

ok "Python packages installed"

# ── bore binary ───────────────────────────────────────────────────────────────
info "Checking bore (WAN tunneling)..."
BORE_DEST="/usr/local/bin/bore"

install_bore() {
    # Try to get latest release URL from GitHub
    local arch
    arch=$(uname -m)
    local tarname=""
    case "$arch" in
        x86_64)  tarname="bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz" ;;
        aarch64) tarname="bore-v0.5.1-aarch64-unknown-linux-musl.tar.gz" ;;
        *)       warn "No pre-built bore for arch $arch"; return 1 ;;
    esac

    local url="https://github.com/ekzhang/bore/releases/latest/download/$tarname"
    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    if wget -q "$url" -O "$tmp/bore.tar.gz" 2>/dev/null || curl -fsSL "$url" -o "$tmp/bore.tar.gz" 2>/dev/null; then
        tar -xf "$tmp/bore.tar.gz" -C "$tmp" 2>/dev/null || unzip -q "$tmp/bore.tar.gz" -d "$tmp" 2>/dev/null || true
        local bin
        bin=$(find "$tmp" -name bore -not -name "*.tar.gz" -type f | head -1)
        if [ -n "$bin" ]; then
            sudo install -m755 "$bin" "$BORE_DEST"
            ok "bore installed to $BORE_DEST"
            return 0
        fi
    fi

    # cargo fallback
    if command -v cargo &>/dev/null; then
        cargo install bore-cli --quiet && ok "bore installed via cargo"
        return 0
    fi

    return 1
}

if command -v bore &>/dev/null; then
    ok "bore already installed: $(command -v bore)"
elif [ -f /tmp/bore ]; then
    sudo install -m755 /tmp/bore "$BORE_DEST" && ok "bore installed from /tmp/bore to $BORE_DEST"
else
    install_bore || {
        warn "bore auto-install failed. Download from: https://github.com/ekzhang/bore/releases"
        warn "Then: sudo install -m755 bore /usr/local/bin/bore"
    }
fi

# ── Metasploit (optional) ─────────────────────────────────────────────────────
if ! command -v msfconsole &>/dev/null; then
    warn "Metasploit not found — required for backdoor_apk, msf_handler, wan_expose"
    if [ "$DISTRO" = "debian" ]; then
        echo "  Install Metasploit: https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers"
    elif [ "$DISTRO" = "arch" ]; then
        echo "  Install: sudo pacman -S metasploit  (or via AUR)"
    fi
else
    ok "Metasploit: $(command -v msfconsole)"
fi

# ── Build secV Go binary ──────────────────────────────────────────────────────
if [ ! -f "$SCRIPT_DIR/secV" ]; then
    info "Building secV Go binary..."
    if command -v go &>/dev/null; then
        (cd "$SCRIPT_DIR" && go mod tidy 2>/dev/null; go build -ldflags="-s -w" -o secV . && ok "secV built") || warn "Go build failed"
    else
        warn "Go not installed — install from golang.org to build secV"
    fi
else
    ok "secV binary present"
fi

# ── Set up tools/ directory ───────────────────────────────────────────────────
info "Setting permissions on module scripts..."
find "$SCRIPT_DIR/tools" -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
find "$SCRIPT_DIR/tools" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
chmod +x "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/uninstall.sh" 2>/dev/null || true
ok "Module scripts are executable"

# ── Optional system-wide install ─────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/secV" ]; then
    echo ""
    read -r -p "Install secV to /usr/local/bin? [y/N] " _ans
    if [[ "$_ans" =~ ^[Yy]$ ]]; then
        sudo install -m755 "$SCRIPT_DIR/secV" /usr/local/bin/secV && ok "secV installed to /usr/local/bin/secV"
    fi
fi

# ── Optional C2 persistence service ──────────────────────────────────────────
C2_SERVICE="$SCRIPT_DIR/tools/mobile/android/c2_persistence/secv-c2.service"
if [ -f "$C2_SERVICE" ]; then
    echo ""
    read -r -p "Install secv-c2 systemd service for WAN C2 persistence? [y/N] " _ans
    if [[ "$_ans" =~ ^[Yy]$ ]]; then
        C2_WATCHDOG="$SCRIPT_DIR/tools/mobile/android/c2_persistence/c2_watchdog.sh"
        sudo mkdir -p /opt/secv
        sudo \cp -f "$C2_WATCHDOG" /opt/secv/c2_watchdog.sh
        sudo chmod +x /opt/secv/c2_watchdog.sh
        # Patch ExecStart path in service file
        sed "s|/opt/secv/c2_watchdog.sh|/opt/secv/c2_watchdog.sh|g" "$C2_SERVICE" \
            | sudo tee /etc/systemd/system/secv-c2.service > /dev/null
        sudo systemctl daemon-reload
        ok "secv-c2.service installed — enable with: sudo systemctl enable --now secv-c2"
        warn "Edit /etc/systemd/system/secv-c2.service to set BORE_DEX_PORT, BORE_MSF_PORT, MSF_LPORT"
    fi
fi

echo ""
info "Modules and their key dependencies:"
printf "  %-30s %s\n" "network/netrecon"       "nmap, masscan, arp-scan, scapy, aiohttp"
printf "  %-30s %s\n" "network/mac_spoof"      "iproute2"
printf "  %-30s %s\n" "network/wifi_monitor"   "scapy, aiohttp"
printf "  %-30s %s\n" "mobile/android_pentest" "adb, apktool, jadx, frida-tools, objection, msfvenom"
printf "  %-30s %s\n" "mobile/ios_pentest"     "libimobiledevice, frida-tools, objection"
printf "  %-30s %s\n" "web/webscan"            "requests"
printf "  %-30s %s\n" "WAN tunneling"          "bore (/usr/local/bin/bore)"
echo ""
ok "Installation complete. Run: ./secV"
