# rqm.md - android_pentest + c2_gui
# Module: android_pentest, c2_gui, apk_backdoor

# ── Python packages (pip) ─────────────────────────────────────────────
#python
frida-tools
objection
qrcode[pil]>=8.0
pillow>=10.0.0
requests>=2.31.0
cryptography>=41.0.0
flask>=3.0.0
flask-cors

# ── Official Arch repo (pacman -S) ────────────────────────────────────
#pacman
android-tools
jdk-openjdk
nmap
nmap-ncat
python-pillow
python-flask
python-requests
python-cryptography
ffmpeg
bluez
bluez-utils
lib32-gcc-libs

# ── AUR packages (yay -S) - some not in official repo ─────────────────
# Use yay, not pacman - these are AUR or chaotic-aur packages
#yay
android-apktool-bin
metasploit
jadx
cloudflared
scrcpy

# ── Manual installs ───────────────────────────────────────────────────
#manual

# bore - WAN tunnel (static binary, no AUR package needed)
# curl -sL https://github.com/ekzhang/bore/releases/download/v0.5.1/bore-v0.5.1-x86_64-unknown-linux-musl.tar.gz | tar xz -C ~/.local/bin

# frida-server - pushed to Android device, not host install
# Version must match host frida-tools version exactly:
# VER=$(python3 -c "import frida; print(frida.__version__)")
# curl -sL "https://github.com/frida/frida/releases/download/${VER}/frida-server-${VER}-android-arm64.xz" | xz -d > ~/.secv/frida-server
# adb push ~/.secv/frida-server /data/local/tmp/frida-server
# adb shell chmod 755 /data/local/tmp/frida-server

# tinycap - Android-side audio capture tool (pushed to device)
# Included in secV agent/tinycap - no host install needed

# apksigner - bundled with android-tools or build-tools SDK
# If missing: yay -S android-sdk-build-tools  (AUR)

# ── Bluetooth HID injection (bt_zero_deliver / CVE-2023-45866) ────────
# Requires:
#   1. bluez + bluez-utils installed (see #yay above)          ← already listed
#   2. bluetoothd running: systemctl enable --now bluetooth
#   3. BT adapter unblocked: rfkill unblock bluetooth
#   4. CAP_NET_RAW on python3 for raw L2CAP sockets:
#        sudo setcap cap_net_raw+eip $(which python3)
#      OR run secV as root for BT HID operations
#   5. Target: classic Bluetooth ON (not just BLE)
#              BLE_ON state is insufficient - check with:
#              adb shell dumpsys bluetooth_manager | grep state
#              Enable if needed: adb shell su -c "svc bluetooth enable"
#   6. Target BT MAC - get via ADB:
#              adb shell settings get secure bluetooth_address
#      Without ADB: host BT inquiry (requires discoverable mode):
#              python3 -c "import bluetooth; print(bluetooth.discover_devices(lookup_names=True))"
#              (requires python-pybluez: yay -S python-pybluez)

# ── apt equivalents (Debian/Ubuntu/Kali) ─────────────────────────────
#apt
android-tools-adb
apktool
aapt
default-jdk
netcat-traditional
python3-pil
python3-flask
python3-requests
python3-cryptography
ffmpeg
bluez
bluez-tools
scrcpy
metasploit-framework
