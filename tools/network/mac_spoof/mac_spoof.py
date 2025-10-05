#!/usr/bin/env python3
"""
MAC Address Spoofer for SecV
Author: 0xb0rn3 (oxbv1) 
Version: 2.0

Automated MAC spoofer with background daemon support.
Supports Linux with iproute2.
"""

import json
import sys
import subprocess
import random
import os
import signal
import time
from pathlib import Path

# State directory for tracking spoofers
STATE_DIR = Path.home() / ".secv" / "mac_spoof"
STATE_DIR.mkdir(parents=True, exist_ok=True)

class MACSpoofer:
    def __init__(self, context):
        self.target = context.get('target', 'localhost')
        self.params = context.get('params', {})
        
        # Parse parameters with fallbacks
        self.ifaces = self._parse_interfaces()
        self.all_up = self._parse_bool(self.params.get('all_up', False))
        self.action = self.params.get('action', 'start').lower()
        self.dry_run = self._parse_bool(self.params.get('dry_run', False))
        self.interval = float(self.params.get('interval', 0.5))
        
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
        
        # Handle comma-separated list
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
                        if iface != 'lo':  # Skip loopback
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
        """Generate random locally-administered MAC address"""
        # First octet: 02 (locally administered, unicast)
        mac = ['02', '00', '00']
        
        # Last three octets: random
        for _ in range(3):
            mac.append(f"{random.randint(0, 255):02x}")
        
        return ':'.join(mac)
    
    def set_mac(self, iface, mac):
        """Set MAC address for interface"""
        try:
            # Bring interface down
            subprocess.run(
                ['ip', 'link', 'set', iface, 'down'],
                capture_output=True,
                check=True
            )
            
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
            
            return True
        except subprocess.CalledProcessError as e:
            self.errors.append(f"Failed to set MAC on {iface}: {e}")
            return False
    
    def save_state(self, iface, pid, original_mac):
        """Save spoofer state"""
        state_file = STATE_DIR / f"{iface}.json"
        state = {
            'interface': iface,
            'pid': pid,
            'original_mac': original_mac,
            'started': time.time()
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
    
    def remove_state(self, iface):
        """Remove spoofer state"""
        state_file = STATE_DIR / f"{iface}.json"
        if state_file.exists():
            state_file.unlink()
    
    def start_spoofer(self, iface):
        """Start background spoofer for interface"""
        # Check if already running
        state = self.load_state(iface)
        if state:
            try:
                os.kill(state['pid'], 0)  # Check if process exists
                return {
                    'success': False,
                    'message': f"Spoofer already running for {iface} (PID: {state['pid']})"
                }
            except OSError:
                # Process dead, clean up
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
                'message': f"[DRY RUN] Would start spoofer for {iface}",
                'original_mac': original_mac
            }
        
        # Fork background process
        pid = os.fork()
        if pid == 0:
            # Child process - become daemon
            try:
                # Detach from parent
                os.setsid()
                
                # Redirect stdout/stderr
                sys.stdout = open('/dev/null', 'w')
                sys.stderr = open('/dev/null', 'w')
                
                # Spoof loop
                while True:
                    new_mac = self.generate_mac()
                    self.set_mac(iface, new_mac)
                    time.sleep(self.interval)
            except:
                sys.exit(1)
        else:
            # Parent process
            self.save_state(iface, pid, original_mac)
            return {
                'success': True,
                'message': f"Started spoofer for {iface}",
                'pid': pid,
                'original_mac': original_mac,
                'interval': self.interval
            }
    
    def stop_spoofer(self, iface):
        """Stop background spoofer for interface"""
        state = self.load_state(iface)
        
        if not state:
            return {
                'success': False,
                'message': f"No spoofer running for {iface}"
            }
        
        if self.dry_run:
            return {
                'success': True,
                'message': f"[DRY RUN] Would stop spoofer for {iface} and restore MAC to {state['original_mac']}"
            }
        
        # Kill process
        try:
            os.kill(state['pid'], signal.SIGTERM)
            time.sleep(0.5)
            
            # Restore original MAC
            current_mac = self.get_current_mac(iface)
            if current_mac != state['original_mac']:
                self.set_mac(iface, state['original_mac'])
            
            self.remove_state(iface)
            
            return {
                'success': True,
                'message': f"Stopped spoofer for {iface}",
                'restored_mac': state['original_mac']
            }
        except ProcessLookupError:
            # Process already dead
            self.remove_state(iface)
            return {
                'success': True,
                'message': f"Spoofer process for {iface} already stopped"
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Failed to stop spoofer for {iface}: {e}"
            }
    
    def status_spoofer(self, iface):
        """Get spoofer status for interface"""
        state = self.load_state(iface)
        
        if not state:
            return {
                'interface': iface,
                'running': False,
                'message': 'Not running'
            }
        
        # Check if process is alive
        try:
            os.kill(state['pid'], 0)
            current_mac = self.get_current_mac(iface)
            uptime = time.time() - state['started']
            
            return {
                'interface': iface,
                'running': True,
                'pid': state['pid'],
                'original_mac': state['original_mac'],
                'current_mac': current_mac,
                'uptime_seconds': int(uptime)
            }
        except OSError:
            # Process dead, clean up
            self.remove_state(iface)
            return {
                'interface': iface,
                'running': False,
                'message': 'Process died unexpectedly'
            }
    
    def execute(self):
        """Execute the requested action"""
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
                'errors': ['No interfaces specified. Set "iface" parameter or enable "all_up"']
            }
        
        # Execute action on each interface
        for iface in target_ifaces:
            if self.action == 'start':
                result = self.start_spoofer(iface)
            elif self.action == 'stop':
                result = self.stop_spoofer(iface)
            elif self.action == 'status':
                result = self.status_spoofer(iface)
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
                'results': self.results,
                'dry_run': self.dry_run
            },
            'errors': self.errors
        }

def show_help():
    """Display module help"""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║  MAC Address Spoofer v2.0
╚═══════════════════════════════════════════════════════════════════╝

DESCRIPTION:
  Automated MAC address spoofer with per-interface background daemon.
  Changes MAC addresses at regular intervals with locally-administered
  OUI prefix (02:00:00) to reduce conflicts.

PARAMETERS:
  iface         Interface name or comma-separated list
                Examples: wlan0 | eth0,wlan0
  
  all_up        Use all currently UP interfaces
                Options: true | false
                Default: false
  
  action        Operation to perform
                Options: start | stop | status
                Default: start
  
  dry_run       Preview actions without making changes
                Options: true | false
                Default: false
  
  interval      Seconds between MAC changes
                Default: 0.5
                Range: 0.1 - 60

EXAMPLES:
  1. Start spoofer on wlan0:
     secV > use mac_spoof
     secV (mac_spoof) > set iface wlan0
     secV (mac_spoof) > run target
  
  2. Start on multiple interfaces:
     secV (mac_spoof) > set iface eth0,wlan0
     secV (mac_spoof) > run target
  
  3. Start on all UP interfaces:
     secV (mac_spoof) > set all_up true
     secV (mac_spoof) > run target
  
  4. Stop spoofer:
     secV (mac_spoof) > set iface wlan0
     secV (mac_spoof) > set action stop
     secV (mac_spoof) > run target
  
  5. Check status:
     secV (mac_spoof) > set action status
     secV (mac_spoof) > set all_up true
     secV (mac_spoof) > run target
  
  6. Dry run (preview):
     secV (mac_spoof) > set iface wlan0
     secV (mac_spoof) > set dry_run true
     secV (mac_spoof) > run target

REQUIREMENTS:
  - Linux with iproute2 (ip command)
  - Root privileges (sudo)
  - Python 3.6+

WARNINGS:
  ⚠ Rapidly changing MACs will break active connections
  ⚠ May cause network instability on some drivers
  ⚠ Use only in authorized lab environments
  ⚠ Each interface runs independent background daemon

STATE FILES:
  ~/.secv/mac_spoof/<interface>.json

AUTHOR: 0xb0rn3 (oxbv1) - Enhanced
VERSION: 2.0
""")

def main():
    # Check for help flag
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
    
    try:
        # Read execution context
        context = json.loads(sys.stdin.read())
        
        # Execute spoofer
        spoofer = MACSpoofer(context)
        result = spoofer.execute()
        
        # Output result
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
