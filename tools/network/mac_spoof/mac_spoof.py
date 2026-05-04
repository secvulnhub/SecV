#!/usr/bin/env python3
"""
MAC Address Spoofer for SecV v2.1
Author: 0xb0rn3 | github.com/0xb0rn3
Version: 2.1

Features:
  • Smart MAC rotation with connection awareness
  • Session-based spoofing (changes only between connections)
  • Graceful interface cycling (prevents disruption)
  • Connection state tracking
  • Intelligent pause detection
  • Multiple spoofing modes for different scenarios
"""

import json
import sys
import subprocess
import random
import os
import signal
import time
import psutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

# State directory for tracking spoofers
STATE_DIR = Path.home() / ".secv" / "mac_spoof"
STATE_DIR.mkdir(parents=True, exist_ok=True)

VENDOR_OUIS = {
    "apple":   ["00:1C:B3","00:17:F2","AC:DE:48","3C:07:54","A8:86:DD","00:25:00","98:01:A7","D4:9A:20","B8:FF:61","F0:18:98"],
    "samsung": ["00:26:37","00:1D:25","00:12:47","B4:EF:FA","A0:07:98","70:F9:27","94:51:03","30:CD:A7","78:40:E4","F8:04:2E"],
    "intel":   ["00:1B:21","00:13:02","00:16:EA","8C:8D:28","A4:C3:F0","10:02:B5","F8:16:54","B0:6E:BF","94:65:9C","48:51:B7"],
    "cisco":   ["00:0A:41","00:1B:D4","00:1C:0F","00:23:04","5C:50:15","00:26:CB","A4:18:75","70:CA:9B","00:0E:84","2C:36:F8"],
    "dell":    ["00:14:22","18:03:73","F8:DB:88","B0:83:FE","D4:BE:D9","00:21:70","00:1E:4F","00:23:AE","14:FE:B5","78:2B:CB"],
}

class ConnectionTracker:
    """Track active network connections to prevent disruption"""
    
    @staticmethod
    def has_active_connections(interface: str) -> bool:
        """Check if interface has active TCP connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            # Get interface IPs
            addrs = psutil.net_if_addrs().get(interface, [])
            interface_ips = {addr.address for addr in addrs if addr.family == 2}  # AF_INET
            
            if not interface_ips:
                return False
            
            # Check for ESTABLISHED connections
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.laddr.ip in interface_ips:
                    return True
            
            return False
        except:
            return False
    
    @staticmethod
    def get_connection_count(interface: str) -> int:
        """Get number of active connections on interface"""
        try:
            connections = psutil.net_connections(kind='inet')
            addrs = psutil.net_if_addrs().get(interface, [])
            interface_ips = {addr.address for addr in addrs if addr.family == 2}
            
            count = 0
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.laddr.ip in interface_ips:
                    count += 1
            
            return count
        except:
            return 0
    
    @staticmethod
    def wait_for_quiet_period(interface: str, max_wait: int = 30) -> bool:
        """Wait for connections to close or timeout"""
        start = time.time()
        
        while time.time() - start < max_wait:
            if not ConnectionTracker.has_active_connections(interface):
                return True
            time.sleep(1)
        
        return False

class MACSpoofer:
    def __init__(self, context):
        self.target = context.get('target', 'localhost')
        self.params = context.get('params', {})
        
        # Parse parameters
        self.ifaces = self._parse_interfaces()
        self.all_up = self._parse_bool(self.params.get('all_up', False))
        self.action = self.params.get('action', 'start').lower()
        self.dry_run = self._parse_bool(self.params.get('dry_run', False))
        
        # Additional parameters
        self.mode = self.params.get('mode', 'smart').lower()
        self.interval = float(self.params.get('interval', 30.0))  # Increased default
        self.wait_for_quiet = self._parse_bool(self.params.get('wait_for_quiet', True))
        self.max_wait = int(self.params.get('max_wait', 30))
        self.preserve_connections = self._parse_bool(self.params.get('preserve_connections', True))
        self.vendor = self.params.get('vendor', '').lower()
        self.stealth = self._parse_bool(self.params.get('stealth', False))
        self.persistent = self._parse_bool(self.params.get('persistent', False))
        
        self.errors = []
        self.results = {}
        
    def _parse_bool(self, value):
        """Parse boolean from various inputs"""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)
    
    def _parse_interfaces(self):
        """Parse interface list from parameters"""
        iface_param = self.params.get('iface', '').strip()
        
        if not iface_param:
            return []
        
        if ',' in iface_param:
            return [i.strip() for i in iface_param.split(',') if i.strip()]
        
        return [iface_param]
    
    def get_interfaces(self):
        """Get list of network interfaces"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface != 'lo':
                            interfaces.append(iface)
            
            return interfaces
        except subprocess.CalledProcessError as e:
            self.errors.append(f"Failed to list interfaces: {e}")
            return []
    
    def get_up_interfaces(self):
        """Get only UP interfaces"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', 'up'],
                capture_output=True,
                text=True,
                check=True
            )
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' ') and 'state UP' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface != 'lo':
                            interfaces.append(iface)
            
            return interfaces
        except subprocess.CalledProcessError as e:
            self.errors.append(f"Failed to get UP interfaces: {e}")
            return []
    
    def get_current_mac(self, iface):
        """Get current MAC address of interface"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', iface],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    return line.split()[1]
            
            return None
        except subprocess.CalledProcessError:
            return None
    
    def generate_mac(self):
        """Generate random locally-administered unicast MAC address"""
        # Set locally-administered bit (bit 1) and clear multicast bit (bit 0)
        # Result is 0x02-0xFE with both constraints met
        first = (random.randint(0, 63) << 2) | 0x02
        mac = [f'{first:02x}']
        for _ in range(5):
            mac.append(f'{random.randint(0, 255):02x}')
        return ':'.join(mac)
    
    def set_mac_graceful(self, iface: str, mac: str) -> bool:
        """Set MAC with graceful connection handling"""
        try:
            # Check for active connections
            if self.preserve_connections:
                conn_count = ConnectionTracker.get_connection_count(iface)
                
                if conn_count > 0:
                    print(f"[*] {iface}: {conn_count} active connection(s)", file=sys.stderr)
                    
                    if self.wait_for_quiet:
                        print(f"[*] Waiting up to {self.max_wait}s for connections to close...", file=sys.stderr)
                        if not ConnectionTracker.wait_for_quiet_period(iface, self.max_wait):
                            print(f"[!] Timeout waiting for quiet period, proceeding anyway", file=sys.stderr)
            
            # Bring interface down
            subprocess.run(
                ['ip', 'link', 'set', iface, 'down'],
                capture_output=True,
                check=True
            )
            
            # Small delay to ensure clean shutdown
            time.sleep(0.1)
            
            # Set new MAC
            subprocess.run(
                ['ip', 'link', 'set', iface, 'address', mac],
                capture_output=True,
                check=True
            )
            
            # Bring interface up
            subprocess.run(
                ['ip', 'link', 'set', iface, 'up'],
                capture_output=True,
                check=True
            )
            
            # Wait for interface to stabilize
            time.sleep(0.5)
            
            # Renew DHCP if possible
            self._renew_dhcp(iface)
            
            return True
            
        except subprocess.CalledProcessError as e:
            self.errors.append(f"Failed to set MAC on {iface}: {e}")
            return False
    
    def _renew_dhcp(self, iface: str):
        """Attempt to renew DHCP lease"""
        try:
            # Try dhclient
            subprocess.run(
                ['dhclient', '-r', iface],
                capture_output=True,
                timeout=5
            )
            time.sleep(1)
            subprocess.run(
                ['dhclient', iface],
                capture_output=True,
                timeout=10
            )
        except:
            try:
                # Try NetworkManager
                subprocess.run(
                    ['nmcli', 'device', 'reapply', iface],
                    capture_output=True,
                    timeout=5
                )
            except:
                pass
    
    def save_state(self, iface, pid, original_mac, mode):
        """Save spoofer state"""
        state_file = STATE_DIR / f"{iface}.json"
        state = {
            'interface': iface,
            'pid': pid,
            'original_mac': original_mac,
            'mode': mode,
            'interval': self.interval,
            'started': time.time(),
            'changes': 0
        }
        
        with open(state_file, 'w') as f:
            json.dump(state, f)
    
    def load_state(self, iface):
        """Load spoofer state"""
        state_file = STATE_DIR / f"{iface}.json"
        
        if not state_file.exists():
            return None
        
        try:
            with open(state_file) as f:
                return json.load(f)
        except:
            return None
    
    def update_state(self, iface: str, changes: int):
        """Update state with change count"""
        state = self.load_state(iface)
        if state:
            state['changes'] = changes
            state_file = STATE_DIR / f"{iface}.json"
            with open(state_file, 'w') as f:
                json.dump(state, f)
    
    def remove_state(self, iface):
        """Remove spoofer state"""
        state_file = STATE_DIR / f"{iface}.json"
        if state_file.exists():
            state_file.unlink()
    
    def start_spoofer(self, iface):
        """Start background spoofer with smart rotation"""
        # Check if already running
        state = self.load_state(iface)
        if state:
            try:
                os.kill(state['pid'], 0)
                return {
                    'success': False,
                    'message': f"Spoofer already running for {iface} (PID: {state['pid']})"
                }
            except OSError:
                self.remove_state(iface)
        
        # Get original MAC
        original_mac = self.get_current_mac(iface)
        if not original_mac:
            return {
                'success': False,
                'message': f"Failed to get current MAC for {iface}"
            }
        
        if self.dry_run:
            return {
                'success': True,
                'message': f"[DRY RUN] Would start {self.mode} spoofer for {iface}",
                'original_mac': original_mac,
                'mode': self.mode,
                'interval': self.interval
            }
        
        # Fork background process
        pid = os.fork()
        if pid == 0:
            # Child process
            try:
                os.setsid()
                sys.stdout = open('/dev/null', 'w')
                sys.stderr = open('/dev/null', 'w')

                changes = 0

                if self.stealth:
                    self._stealth_mode(iface, changes)
                elif self.mode == 'aggressive':
                    self._aggressive_mode(iface, changes)
                elif self.mode == 'smart':
                    self._smart_mode(iface, changes)
                elif self.mode == 'session':
                    self._session_mode(iface, changes)
                elif self.mode == 'periodic':
                    self._periodic_mode(iface, changes)
                else:
                    self._smart_mode(iface, changes)

            except:
                sys.exit(1)
        else:
            # Parent process
            self.save_state(iface, pid, original_mac, self.mode)

            if self.persistent:
                self._write_persistent_service(iface)

            return {
                'success': True,
                'message': f"Started {self.mode} spoofer for {iface}",
                'pid': pid,
                'original_mac': original_mac,
                'mode': self.mode,
                'interval': self.interval,
                'preserve_connections': self.preserve_connections,
                'stealth': self.stealth,
                'persistent': self.persistent
            }
    
    def _aggressive_mode(self, iface: str, changes: int):
        """Aggressive mode - frequent changes (use with caution)"""
        while True:
            new_mac = self.generate_mac()
            if self.set_mac_graceful(iface, new_mac):
                changes += 1
                self.update_state(iface, changes)
            time.sleep(self.interval)
    
    def _smart_mode(self, iface: str, changes: int):
        """Smart mode - changes only when no active connections"""
        consecutive_quiet = 0
        required_quiet = 3  # Require 3 consecutive quiet checks
        
        while True:
            if ConnectionTracker.has_active_connections(iface):
                consecutive_quiet = 0
                time.sleep(5)  # Check every 5 seconds
            else:
                consecutive_quiet += 1
                
                if consecutive_quiet >= required_quiet:
                    # No connections for required period, safe to change
                    new_mac = self.generate_mac()
                    if self.set_mac_graceful(iface, new_mac):
                        changes += 1
                        self.update_state(iface, changes)
                    consecutive_quiet = 0
                    time.sleep(self.interval)
                else:
                    time.sleep(5)
    
    def _session_mode(self, iface: str, changes: int):
        """Session mode - changes between connection sessions"""
        last_conn_count = ConnectionTracker.get_connection_count(iface)
        idle_time = 0
        
        while True:
            time.sleep(5)
            current_conn_count = ConnectionTracker.get_connection_count(iface)
            
            if current_conn_count == 0 and last_conn_count > 0:
                # Connections just closed
                idle_time += 5
                
                if idle_time >= 10:  # 10 seconds idle
                    new_mac = self.generate_mac()
                    if self.set_mac_graceful(iface, new_mac):
                        changes += 1
                        self.update_state(iface, changes)
                    idle_time = 0
            elif current_conn_count > 0:
                idle_time = 0
            else:
                idle_time += 5
            
            last_conn_count = current_conn_count
    
    def _periodic_mode(self, iface: str, changes: int):
        """Periodic mode - changes at fixed intervals regardless of connections"""
        while True:
            time.sleep(self.interval)
            new_mac = self.generate_mac()
            if self.set_mac_graceful(iface, new_mac):
                changes += 1
                self.update_state(iface, changes)

    def _stealth_mode(self, iface: str, changes: int):
        """Rotate only when a reconnect (DOWN -> UP transition) is detected."""
        was_down = False
        while True:
            try:
                result = subprocess.run(
                    ['ip', 'link', 'show', iface],
                    capture_output=True, text=True
                )
                is_down = 'state DOWN' in result.stdout or 'state UNKNOWN' in result.stdout
                if was_down and not is_down:
                    new_mac = self.generate_mac()
                    if self.set_mac_graceful(iface, new_mac):
                        changes += 1
                        self.update_state(iface, changes)
                was_down = is_down
            except Exception:
                pass
            time.sleep(2)

    def _write_persistent_service(self, iface: str):
        """Write and enable a systemd user service that starts mac_spoof at login."""
        service_dir = Path.home() / '.config' / 'systemd' / 'user'
        service_dir.mkdir(parents=True, exist_ok=True)
        service_name = f"mac_spoof_{iface}"
        service_file = service_dir / f"{service_name}.service"

        script_path = Path(__file__).resolve()
        exec_cmd = (
            f"python3 {script_path} "
            f"iface={iface} action=start mode={self.mode} interval={self.interval}"
        )

        content = (
            "[Unit]\n"
            f"Description=MAC Spoofer for {iface}\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=forking\n"
            f"ExecStart={exec_cmd}\n"
            "Restart=on-failure\n\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )

        with open(service_file, 'w') as f:
            f.write(content)

        try:
            subprocess.run(
                ['systemctl', '--user', 'daemon-reload'],
                capture_output=True, check=True
            )
            subprocess.run(
                ['systemctl', '--user', 'enable', service_name],
                capture_output=True, check=True
            )
        except Exception:
            pass

    def vendor_spoof(self, iface):
        """Spoof MAC using a real vendor OUI prefix."""
        if self.vendor not in VENDOR_OUIS:
            return {
                'success': False,
                'message': f"Unknown vendor '{self.vendor}'. Valid: {', '.join(VENDOR_OUIS)}"
            }

        oui = random.choice(VENDOR_OUIS[self.vendor])
        b1, b2, b3 = random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
        mac = f"{oui}:{b1:02x}:{b2:02x}:{b3:02x}"

        if self.dry_run:
            return {
                'success': True,
                'message': f"[DRY RUN] Would set {iface} to {mac}",
                'vendor': self.vendor,
                'applied_mac': mac
            }

        try:
            subprocess.run(['ip', 'link', 'set', iface, 'down'], capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', iface, 'address', mac], capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', iface, 'up'], capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            return {'success': False, 'message': f"Failed to set MAC on {iface}: {e}"}

        self._append_history(iface, mac, 'vendor')
        return {'success': True, 'vendor': self.vendor, 'applied_mac': mac}

    def restore_mac(self, iface):
        """Restore the original or permanent MAC address."""
        state = self.load_state(iface)
        original_mac = state.get('original_mac') if state else None

        if not original_mac:
            try:
                result = subprocess.run(
                    ['ethtool', '-P', iface],
                    capture_output=True, text=True, check=True
                )
                for part in result.stdout.split():
                    if ':' in part and len(part) == 17:
                        original_mac = part
                        break
            except Exception:
                pass

        if not original_mac:
            return {'success': False, 'message': f"Could not determine original MAC for {iface}"}

        try:
            subprocess.run(['ip', 'link', 'set', iface, 'down'], capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', iface, 'address', original_mac], capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', iface, 'up'], capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            return {'success': False, 'message': f"Failed to restore MAC on {iface}: {e}"}

        return {'success': True, 'restored_mac': original_mac}

    def get_history(self, iface):
        """Return rotation history for an interface."""
        history_file = STATE_DIR / f"{iface}_history.json"
        if not history_file.exists():
            return []
        try:
            with open(history_file) as f:
                return json.load(f)
        except Exception:
            return []

    def _append_history(self, iface: str, mac: str, method: str):
        """Append a rotation event to the interface history file."""
        history_file = STATE_DIR / f"{iface}_history.json"
        history = self.get_history(iface)
        history.append({
            'timestamp': datetime.utcnow().isoformat(),
            'mac': mac,
            'method': method
        })
        with open(history_file, 'w') as f:
            json.dump(history, f)

    def stop_spoofer(self, iface):
        """Stop spoofer and restore original MAC"""
        state = self.load_state(iface)
        
        if not state:
            return {
                'success': False,
                'message': f"No spoofer running for {iface}"
            }
        
        if self.dry_run:
            return {
                'success': True,
                'message': f"[DRY RUN] Would stop spoofer and restore MAC to {state['original_mac']}"
            }
        
        try:
            # Kill process
            os.kill(state['pid'], signal.SIGTERM)
            time.sleep(0.5)
            
            # Wait for connections to close if enabled
            if self.preserve_connections and self.wait_for_quiet:
                ConnectionTracker.wait_for_quiet_period(iface, self.max_wait)
            
            # Restore original MAC
            current_mac = self.get_current_mac(iface)
            if current_mac != state['original_mac']:
                self.set_mac_graceful(iface, state['original_mac'])
            
            self.remove_state(iface)
            
            return {
                'success': True,
                'message': f"Stopped spoofer for {iface}",
                'restored_mac': state['original_mac'],
                'total_changes': state.get('changes', 0)
            }
            
        except ProcessLookupError:
            self.remove_state(iface)
            return {
                'success': True,
                'message': f"Spoofer process already stopped"
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Failed to stop spoofer: {e}"
            }
    
    def status_spoofer(self, iface):
        """Get detailed spoofer status"""
        state = self.load_state(iface)
        
        if not state:
            return {
                'interface': iface,
                'running': False,
                'message': 'Not running'
            }
        
        try:
            os.kill(state['pid'], 0)
            current_mac = self.get_current_mac(iface)
            uptime = time.time() - state['started']
            conn_count = ConnectionTracker.get_connection_count(iface)
            
            return {
                'interface': iface,
                'running': True,
                'pid': state['pid'],
                'mode': state.get('mode', 'unknown'),
                'original_mac': state['original_mac'],
                'current_mac': current_mac,
                'uptime_seconds': int(uptime),
                'interval': state.get('interval', 0),
                'total_changes': state.get('changes', 0),
                'active_connections': conn_count
            }
        except OSError:
            self.remove_state(iface)
            return {
                'interface': iface,
                'running': False,
                'message': 'Process died unexpectedly'
            }
    
    def execute(self):
        """Execute requested action"""
        # Determine target interfaces
        if self.all_up:
            target_ifaces = self.get_up_interfaces()
            if not target_ifaces:
                return {
                    'success': False,
                    'data': None,
                    'errors': ['No UP interfaces found']
                }
        elif self.ifaces:
            target_ifaces = self.ifaces
        else:
            return {
                'success': False,
                'data': None,
                'errors': ['No interfaces specified']
            }
        
        # Execute action
        for iface in target_ifaces:
            if self.action == 'start':
                result = self.start_spoofer(iface)
            elif self.action == 'stop':
                result = self.stop_spoofer(iface)
            elif self.action == 'status':
                result = self.status_spoofer(iface)
            elif self.action == 'vendor':
                result = self.vendor_spoof(iface)
            elif self.action == 'restore':
                result = self.restore_mac(iface)
            elif self.action == 'history':
                result = {'success': True, 'history': self.get_history(iface)}
            else:
                result = {
                    'success': False,
                    'message': f'Unknown action: {self.action}'
                }
            
            self.results[iface] = result
            
            if not result.get('success', False) and self.action != 'status':
                self.errors.append(result.get('message', 'Unknown error'))
        
        return {
            'success': len(self.errors) == 0,
            'data': {
                'action': self.action,
                'mode': self.mode,
                'results': self.results,
                'dry_run': self.dry_run
            },
            'errors': self.errors
        }

def show_help():
    """Display comprehensive help"""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║  MAC Address Spoofer v2.1                                         ║
║  Built and maintained by 0xb0rn3 | github.com/0xb0rn3            ║
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  MAC spoofer with intelligent connection awareness.
  Minimizes disruption to active network connections while providing
  effective MAC randomization for privacy and testing.

NEW IN v2.1:
  ✓ Connection-aware MAC rotation
  ✓ Multiple spoofing modes
  ✓ Graceful DHCP renewal
  ✓ Active connection tracking
  ✓ Configurable wait periods
  ✓ Session-based rotation

SPOOFING MODES:
  smart           Changes MAC only when no active connections (default)
                  Safest option - waits for idle periods
  
  session         Changes MAC between connection sessions
                  Waits 10s after connections close
  
  periodic        Changes MAC at fixed intervals
                  Respects preserve_connections setting
  
  aggressive      Rapid MAC changes (use with caution!)
                  May break active connections

PARAMETERS:
  iface           Interface name or comma-separated list
                  Examples: wlan0 | eth0,wlan0
  
  all_up          Use all currently UP interfaces
                  Options: true | false
                  Default: false
  
  action          Operation: start | stop | status
                  Default: start
  
  mode            Spoofing mode (see above)
                  Default: smart
  
  interval        Seconds between MAC changes
                  Default: 30.0 (increased for stability)
                  Range: 5.0 - 3600
  
  preserve_connections    Protect active connections
                          Options: true | false
                          Default: true
  
  wait_for_quiet  Wait for connections to close
                  Options: true | false
                  Default: true
  
  max_wait        Maximum wait time for quiet period (seconds)
                  Default: 30
                  Range: 5 - 300
  
  dry_run         Preview actions without changes
                  Options: true | false
                  Default: false

EXAMPLES:
  1. Smart mode (safest - default):
     use mac_spoof
     set iface wlan0
     set mode smart
     run target
  
  2. Session-based rotation:
     use mac_spoof
     set iface wlan0
     set mode session
     run target
  
  3. Periodic with long interval:
     use mac_spoof
     set iface wlan0
     set mode periodic
     set interval 300
     run target
  
  4. Multiple interfaces with smart mode:
     use mac_spoof
     set iface eth0,wlan0
     set mode smart
     set preserve_connections true
     run target
  
  5. Check detailed status:
     use mac_spoof
     set action status
     set all_up true
     run target
  
  6. Aggressive mode (testing only):
     use mac_spoof
     set iface wlan0
     set mode aggressive
     set interval 10
     set preserve_connections false
     run target

FEATURES:
  ✓ Connection tracking - monitors active TCP connections
  ✓ Graceful rotation - waits for idle periods
  ✓ DHCP renewal - automatically requests new lease
  ✓ Smart timing - adapts to network activity
  ✓ Session detection - identifies connection patterns
  ✓ Change counter - tracks total MAC rotations
  ✓ Detailed status - shows connections and uptime

REQUIREMENTS:
  - Linux with iproute2 (ip command)
  - Python 3.6+ with psutil
  - Root privileges (sudo)

INSTALLATION:
  pip3 install psutil --user --break-system-packages

BEST PRACTICES:
  ✓ Use 'smart' or 'session' mode for active use
  ✓ Set interval to 60+ seconds for stability
  ✓ Keep preserve_connections enabled
  ✓ Test with dry_run first
  ✓ Monitor status regularly
  ✓ Stop spoofer cleanly before shutdown

WARNINGS:
  ⚠  Aggressive mode will break connections
  ⚠  Short intervals increase detection risk
  ⚠  Some drivers may not handle frequent changes
  ⚠  Always use in authorized environments
  ⚠  DHCP renewal may briefly interrupt traffic

TROUBLESHOOTING:
  If connections keep breaking:
  - Use 'smart' or 'session' mode
  - Increase interval to 300+ seconds
  - Enable wait_for_quiet
  - Check driver compatibility
  
  If MAC changes too slowly:
  - Use 'periodic' mode
  - Decrease interval
  - Set preserve_connections false
  
  If spoofer stops unexpectedly:
  - Check system logs: journalctl -n 50
  - Verify interface stability
  - Increase interval

STATE FILES:
  ~/.secv/mac_spoof/<interface>.json

AUTHOR: 0xb0rn3 | github.com/0xb0rn3
VERSION: 2.1
""")

def main():
    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        show_help()
        sys.exit(0)
    
    # Check for root
    if os.geteuid() != 0:
        print(json.dumps({
            'success': False,
            'data': None,
            'errors': ['Root privileges required. Run with: sudo secV']
        }))
        sys.exit(1)
    
    # Check for psutil
    try:
        import psutil
    except ImportError:
        print(json.dumps({
            'success': False,
            'data': None,
            'errors': [
                'psutil module required for connection tracking',
                'Install: pip3 install psutil --user --break-system-packages'
            ]
        }))
        sys.exit(1)
    
    try:
        context = json.loads(sys.stdin.read())
        spoofer = MACSpoofer(context)
        result = spoofer.execute()
        print(json.dumps(result, indent=2))
        
    except json.JSONDecodeError as e:
        print(json.dumps({
            'success': False,
            'data': None,
            'errors': [f'Invalid JSON input: {e}']
        }))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            'success': False,
            'data': None,
            'errors': [f'Unexpected error: {e}']
        }))
        sys.exit(1)

if __name__ == '__main__':
    main()
