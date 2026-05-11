#!/usr/bin/env bash
# secV v2.4.2 "tauri" installer
# Reads the single global rqm.md at the repo root and installs all dependencies.
# Supports: Arch/Manjaro/CachyOS (pacman), Debian/Ubuntu/Kali (apt),
#           Fedora/RHEL/Rocky (dnf), openSUSE (zypper), Alpine (apk), Void (xbps-install)
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'
info()  { echo -e "${CYN}[*]${RST} $*"; }
ok()    { echo -e "${GRN}[+]${RST} $*"; }
warn()  { echo -e "${YLW}[!]${RST} $*"; }
err()   { echo -e "${RED}[!]${RST} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Detect distro and package manager ─────────────────────────────────────────
DISTRO="unknown"
PKG_MGR="unknown"
PKG_UPDATE="true"
PKG_INSTALL="echo SKIP"

detect_distro() {
    local id=""
    if [[ -f /etc/os-release ]]; then
        id=$(. /etc/os-release && echo "${ID:-}")
    fi
    [[ -z "$id" && -f /etc/arch-release ]] && id="arch"

    case "$id" in
        arch|blackarch|archcraft|manjaro|endeavouros|cachyos|artix|garuda)
            DISTRO="arch"; PKG_MGR="pacman"
            PKG_UPDATE="sudo pacman -Sy --noconfirm"
            PKG_INSTALL="sudo pacman -S --noconfirm --needed"
            # Prefer AUR helper if available
            for aur in yay paru trizen; do
                if command -v "$aur" &>/dev/null; then
                    PKG_INSTALL="$aur -S --noconfirm --needed"; break
                fi
            done
            ;;
        ubuntu|debian|kali|parrot|linuxmint|pop|elementary|zorin|mx|raspbian)
            DISTRO="debian"; PKG_MGR="apt"
            PKG_UPDATE="sudo apt-get update -qq"
            PKG_INSTALL="sudo apt-get install -y"
            ;;
        fedora|nobara)
            DISTRO="fedora"; PKG_MGR="dnf"
            PKG_UPDATE="sudo dnf check-update -q || true"
            PKG_INSTALL="sudo dnf install -y"
            ;;
        rhel|centos|rocky|alma|oracle)
            DISTRO="rhel"; PKG_MGR="dnf"
            PKG_UPDATE="sudo dnf check-update -q || true"
            PKG_INSTALL="sudo dnf install -y"
            ;;
        opensuse-leap|opensuse-tumbleweed|opensuse|sles)
            DISTRO="opensuse"; PKG_MGR="zypper"
            PKG_UPDATE="sudo zypper refresh -q"
            PKG_INSTALL="sudo zypper install -y --no-confirm"
            ;;
        alpine)
            DISTRO="alpine"; PKG_MGR="apk"
            PKG_UPDATE="sudo apk update -q"
            PKG_INSTALL="sudo apk add"
            ;;
        void)
            DISTRO="void"; PKG_MGR="xbps-install"
            PKG_UPDATE="sudo xbps-install -Su"
            PKG_INSTALL="sudo xbps-install -Sy"
            ;;
        *)
            if command -v brew &>/dev/null; then
                DISTRO="macos"; PKG_MGR="brew"
                PKG_UPDATE="brew update"
                PKG_INSTALL="brew install"
            else
                warn "Unrecognised distro '$id' — system packages will be skipped"
                return
            fi
            ;;
    esac
    info "Detected: $DISTRO ($PKG_MGR)"
}

detect_distro

# ── rqm.md parser ─────────────────────────────────────────────────────────────
# Reads only the root-level rqm.md. Supports sections:
#   #python  #pacman  #apt  #dnf  #zypper  #apk  #xbps  #binary
declare -a RQM_PY_PKGS=()
declare -a RQM_OS_PKGS=()
declare -a RQM_BIN_ENTRIES=()
declare -A _seen_py=() _seen_os=() _seen_bin=()

load_rqm_files() {
    local os_section
    case "$PKG_MGR" in
        pacman)       os_section="pacman" ;;
        apt)          os_section="apt"    ;;
        dnf)          os_section="dnf"    ;;
        zypper)       os_section="zypper" ;;
        apk)          os_section="apk"    ;;
        xbps-install) os_section="xbps"   ;;
        brew)         os_section="brew"   ;;
        *)            os_section=""       ;;
    esac

    local section=""
    # Read only the root rqm.md (single global manifest)
    local rqm_file="$SCRIPT_DIR/rqm.md"
    [[ -f "$rqm_file" ]] || { warn "rqm.md not found at $SCRIPT_DIR/rqm.md"; return; }

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        if [[ -z "$line" || "$line" == \#* ]]; then
            case "$line" in
                "#python") section="python" ;;
                "#pacman") section="pacman" ;;
                "#apt")    section="apt"    ;;
                "#dnf")    section="dnf"    ;;
                "#zypper") section="zypper" ;;
                "#apk")    section="apk"    ;;
                "#xbps")   section="xbps"   ;;
                "#brew")   section="brew"   ;;
                "#binary") section="binary" ;;
                *)         ;;
            esac
            continue
        fi
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
            binary)
                [[ -z "${_seen_bin[$pkg]+x}" ]] && { RQM_BIN_ENTRIES+=("$pkg"); _seen_bin["$pkg"]=1; }
                ;;
        esac
    done < "$rqm_file"

    info "rqm.md: ${#RQM_PY_PKGS[@]} python pkgs, ${#RQM_OS_PKGS[@]} OS pkgs (${os_section}), ${#RQM_BIN_ENTRIES[@]} binaries"
}

$PKG_UPDATE || true

# Load global rqm.md
load_rqm_files

# ── System packages ────────────────────────────────────────────────────────────
info "Installing system packages..."

if [ "${#RQM_OS_PKGS[@]}" -gt 0 ] && [ "$PKG_MGR" != "unknown" ]; then
    $PKG_INSTALL "${RQM_OS_PKGS[@]}" || warn "Some system packages failed — check manually"
else
    warn "No OS packages to install (distro '$DISTRO' / manager '$PKG_MGR' not matched in rqm.md)"
fi

# jadx is not in most repos — guide the user
if ! command -v jadx &>/dev/null; then
    case "$DISTRO" in
        arch) warn "jadx: install via AUR: yay -S jadx" ;;
        *)    warn "jadx: download from github.com/skylot/jadx/releases" ;;
    esac
fi

# ── Python packages ─────────────────────────────────────────────────────────────
info "Installing Python packages..."

pip_install() {
    local pip_cmd="pip3"
    command -v pip3 &>/dev/null || { warn "pip3 not found — skipping Python packages"; return 1; }
    if pip3 install --break-system-packages --quiet "$@" 2>/dev/null; then return 0; fi
    if pip3 install --quiet "$@" 2>/dev/null; then return 0; fi
    pip3 install --user --quiet "$@" 2>/dev/null
}

if [ "${#RQM_PY_PKGS[@]}" -gt 0 ]; then
    pip_install "${RQM_PY_PKGS[@]}" || warn "Some pip packages failed"
else
    warn "No Python packages found in rqm.md"
fi
ok "Python packages done"

# ── bore binary (WAN tunneling) ────────────────────────────────────────────────
info "Checking bore..."
BORE_DEST="/usr/local/bin/bore"

install_bore() {
    local arch; arch=$(uname -m)
    local tarname
    case "$arch" in
        x86_64)  tarname="bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz" ;;
        aarch64) tarname="bore-v0.5.1-aarch64-unknown-linux-musl.tar.gz" ;;
        *) warn "bore: no pre-built binary for $arch"; return 1 ;;
    esac
    local url="https://github.com/ekzhang/bore/releases/latest/download/$tarname"
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
    if wget -q "$url" -O "$tmp/bore.tar.gz" 2>/dev/null || curl -fsSL "$url" -o "$tmp/bore.tar.gz" 2>/dev/null; then
        tar -xf "$tmp/bore.tar.gz" -C "$tmp" 2>/dev/null || true
        local bin; bin=$(find "$tmp" -name bore -type f ! -name "*.tar.gz" | head -1)
        [[ -n "$bin" ]] && sudo install -m755 "$bin" "$BORE_DEST" && ok "bore → $BORE_DEST" && return 0
    fi
    command -v cargo &>/dev/null && cargo install bore-cli --quiet && ok "bore installed via cargo" && return 0
    return 1
}

if command -v bore &>/dev/null; then
    ok "bore: $(command -v bore)"
elif [[ -f /tmp/bore ]]; then
    sudo install -m755 /tmp/bore "$BORE_DEST" && ok "bore installed from /tmp/bore"
else
    install_bore || {
        warn "bore auto-install failed"
        warn "Manual: https://github.com/ekzhang/bore/releases → sudo install -m755 bore /usr/local/bin/bore"
    }
fi

# ── Metasploit (optional) ─────────────────────────────────────────────────────
if ! command -v msfconsole &>/dev/null; then
    warn "Metasploit not found (optional — needed for msf_handler, wan_expose, backdoor_apk)"
    case "$DISTRO" in
        arch|archcraft|manjaro|cachyos) echo "  → sudo pacman -S metasploit  (or: yay -S metasploit)" ;;
        debian|ubuntu|kali|parrot)     echo "  → https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers" ;;
        fedora|rhel)                   echo "  → sudo dnf install metasploit" ;;
        *)                             echo "  → https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html" ;;
    esac
else
    ok "Metasploit: $(command -v msfconsole)"
fi

# ── Zig cross-compiler (needed for DLL generation in winadsec) ────────────────
if ! command -v zig &>/dev/null && [[ ! -f /tmp/zig-linux-x86_64-0.14.0/zig ]]; then
    warn "zig not found — required for winadsec gen_proxy_dll / gen_uac_dll"
    echo "  → wget https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz"
    echo "     tar xf zig-linux-x86_64-0.14.0.tar.xz -C /tmp"
    echo "     (or: sudo ln -s /tmp/zig-linux-x86_64-0.14.0/zig /usr/local/bin/zig)"
elif command -v zig &>/dev/null; then
    ok "zig: $(zig version 2>/dev/null || command -v zig)"
fi

# ── donut shellcode generator ─────────────────────────────────────────────────
if ! command -v donut &>/dev/null && [[ ! -f /tmp/donut-1.0/donut ]]; then
    warn "donut not found — required for winadsec gen_shellcode"
    echo "  → pip3 install donut-shellcode  (or build: github.com/TheWover/donut)"
elif command -v donut &>/dev/null; then
    ok "donut: $(command -v donut)"
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
# Copies the binary to /usr/local/bin and the tools + updater to /var/lib/secv/
# so secV works from any directory without keeping the repo on PATH.
if [ -f "$SCRIPT_DIR/secV" ]; then
    echo ""
    read -r -p "Install secV system-wide? (/usr/local/bin + /var/lib/secv) [y/N] " _ans
    if [[ "$_ans" =~ ^[Yy]$ ]]; then
        # Binary
        sudo install -m755 "$SCRIPT_DIR/secV" /usr/local/bin/secV
        ok "binary   → /usr/local/bin/secV"

        # Data directory
        sudo mkdir -p /var/lib/secv

        # Tools (full recursive copy; preserves all module sub-directories)
        sudo cp -r "$SCRIPT_DIR/tools" /var/lib/secv/
        sudo find /var/lib/secv/tools -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
        sudo find /var/lib/secv/tools -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
        ok "tools    → /var/lib/secv/tools/"

        # Updater
        sudo install -m755 "$SCRIPT_DIR/update.py" /var/lib/secv/update.py
        ok "updater  → /var/lib/secv/update.py"

        echo ""
        ok "Run 'secV' from anywhere"
        info "Refresh after pulling new module versions:"
        echo "     sudo cp -r tools/ /var/lib/secv/"
        echo "     sudo install -m755 secV /usr/local/bin/secV"
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
info "Modules (10 total):"
printf "  %-32s %s\n" "AD/windows/winadsec"      "impacket, ldap3, zig, donut, xorriso (+ nxc, kerbrute, bloodhound)"
printf "  %-32s %s\n" "AD/linux/adsec"           "impacket, ldap3, smbclient, rpcclient (+ nxc, kerbrute, bloodhound)"
printf "  %-32s %s\n" "network/netrecon"         "nmap, masscan, arp-scan, scapy, aiohttp"
printf "  %-32s %s\n" "network/mac_spoof"        "iproute2, psutil, netifaces"
printf "  %-32s %s\n" "network/wifi_monitor"     "scapy, psutil"
printf "  %-32s %s\n" "network/iot_pwn"          "nmap, paramiko, requests (+ optional: snmpwalk, hydra)"
printf "  %-32s %s\n" "mobile/android_pentest"   "adb, apktool, jadx, frida-tools, objection (+ web GUI)"
printf "  %-32s %s\n" "mobile/ios_pentest"       "libimobiledevice, frida-tools, objection"
printf "  %-32s %s\n" "web/websec"               "requests, beautifulsoup4, dnspython"
printf "  %-32s %s\n" "ctf/ctfpwn"              "nmap, gobuster, hydra (+ optional: sshpass, node)"
printf "  %-32s %s\n" "WAN tunneling"            "bore (/usr/local/bin/bore)"
echo ""
ok "Installation complete"
echo ""
echo "  From repo dir:  ./secV"
echo "  System-wide:    secV            (after system install above)"
echo "  Custom path:    SECV_HOME=/path/to/secv secV"
