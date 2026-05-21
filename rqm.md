# secV Global Requirements Manifest
# This is the ONE authoritative requirements file for ALL secV modules.
# Modules covered: netrecon, mac_spoof, wifi_monitor, iot_pwn, revshell, adsec,
#                  android_pentest, ios_pentest, websec, ctfpwn, winadsec, badusb
#
# install.sh reads this file and installs everything listed.
# If a section is empty or does not exist, it is silently skipped.
# Per-module rqm.md files are DEPRECATED - all deps live here.
#
# Sections:
#   #python   - pip packages (installed with pip3 --break-system-packages)
#   #pacman   - Arch/Manjaro/CachyOS packages
#   #apt      - Debian/Ubuntu/Kali packages
#   #dnf      - Fedora/RHEL/Rocky packages
#   #zypper   - openSUSE Leap/Tumbleweed packages
#   #apk      - Alpine Linux packages
#   #xbps     - Void Linux packages
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
impacket>=0.12.0
ldap3>=2.9.1
dnspython>=2.4.0
bloodhound>=1.7.0
frida-tools>=12.5.0
objection>=1.11.0
beautifulsoup4>=4.12.0
shodan>=1.31.0
geoip2>=4.8.0
mmh3>=4.1.0
paramiko>=3.3.0
pyinstaller>=6.0.0

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
smbclient
xorriso
libimobiledevice
ideviceinstaller
python-pillow
aircrack-ng
hcxtools
hostapd
dnsmasq
reaver
hashcat
bettercap
dsniff

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
smbclient
rpcclient
xorriso
libimobiledevice-utils
ideviceinstaller
aircrack-ng
hcxdumptool
hcxtools
hostapd
dnsmasq
reaver
bully
hashcat
bettercap
dsniff

#dnf
python3
python3-pip
nmap
masscan
whois
iproute
java-latest-openjdk
android-tools
git
curl
wget
nmap-ncat
golang
samba-client
xorriso
aircrack-ng
hostapd
dnsmasq
reaver
hashcat
dsniff

#zypper
python3
python3-pip
nmap
masscan
whois
iproute2
java-17-openjdk
android-tools
git
curl
wget
ncat
go
samba-client
xorriso
aircrack-ng
hostapd
dnsmasq
hashcat
dsniff

#apk
python3
py3-pip
nmap
whois
iproute2
openjdk17-jre
android-tools
git
curl
wget
nmap-ncat
go
samba-client
aircrack-ng
hostapd
dnsmasq
hashcat

#xbps
python3
python3-pip
nmap
masscan
whois
iproute2
openjdk17-jre
android-tools
git
curl
wget
go
samba
xorriso
aircrack-ng
hostapd
dnsmasq
hashcat
dsniff

#binary
bore,https://github.com/ekzhang/bore/releases/latest
