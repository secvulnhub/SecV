# secV Requirements Manifest
# Contributors: add your tool's dependencies in the appropriate section.
# install.sh reads all rqm.md files in the repo tree and installs everything listed.
# If a section is empty or the file does not exist, it is silently skipped.
#
# Sections:
#   #python   - pip packages (installed with pip3 --break-system-packages)
#   #pacman   - Arch/Manjaro/CachyOS packages
#   #apt      - Debian/Ubuntu/Kali packages
#   #binary   - name,url  (downloaded binary, checked by `command -v name`)

#python
requests>=2.31.0
rich>=13.0.0
psutil>=5.9.0
cryptography>=41.0.0
netifaces>=0.11.0
scapy>=2.5.0
aiohttp>=3.9.0
flask>=3.0.0
qrcode[pil]>=8.0
pillow>=10.0.0

#pacman
python
python-pip
nmap
masscan
arp-scan
whois
iproute2
jdk-openjdk
android-tools
apktool
git
curl
wget
nmap-ncat
go

#apt
python3
python3-pip
nmap
masscan
arp-scan
whois
iproute2
default-jdk
android-tools-adb
apktool
git
curl
wget
netcat-traditional
golang-go

#binary
bore,https://github.com/ekzhang/bore/releases/latest
