#!/usr/bin/env python3
"""
SecV Dashboard System v1.0
Real-time module status monitoring
"""

import json
import time
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

class ModuleStatus:
    """Track module execution status"""
    def __init__(self):
        self.active_modules: Dict[str, dict] = {}
        self.completed_modules: List[dict] = []
        self.failed_modules: List[dict] = []
        self.lock = threading.Lock()
        self.max_history = 50
    
    def start_module(self, module_name: str, target: str, pid: int):
        """Register module as active"""
        with self.lock:
            self.active_modules[module_name] = {
                'name': module_name,
                'target': target,
                'pid': pid,
                'start_time': time.time(),
                'status': 'running'
            }
    
    def complete_module(self, module_name: str, success: bool, duration: float):
        """Mark module as completed"""
        with self.lock:
            if module_name in self.active_modules:
                module_info = self.active_modules.pop(module_name)
                module_info['duration'] = duration
                module_info['end_time'] = time.time()
                module_info['status'] = 'success' if success else 'failed'
                
                if success:
                    self.completed_modules.insert(0, module_info)
                    if len(self.completed_modules) > self.max_history:
                        self.completed_modules.pop()
                else:
                    self.failed_modules.insert(0, module_info)
                    if len(self.failed_modules) > self.max_history:
                        self.failed_modules.pop()
    
    def get_status(self) -> dict:
        """Get current status snapshot"""
        with self.lock:
            return {
                'active': list(self.active_modules.values()),
                'completed': self.completed_modules[:10],
                'failed': self.failed_modules[:10],
                'stats': {
                    'active_count': len(self.active_modules),
                    'completed_count': len(self.completed_modules),
                    'failed_count': len(self.failed_modules)
                }
            }
    
    def format_duration(self, seconds: float) -> str:
        """Format duration in human readable form"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{int(seconds//60)}m {int(seconds%60)}s"
        else:
            return f"{int(seconds//3600)}h {int((seconds%3600)//60)}m"


class DashboardRenderer:
    """Render dashboard to terminal"""
    
    COLORS = {
        'HEADER': '\033[95m',
        'BLUE': '\033[94m',
        'CYAN': '\033[96m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'RESET': '\033[0m'
    }
    
    def __init__(self, status_tracker: ModuleStatus):
        self.status = status_tracker
    
    def render(self) -> str:
        """Render current dashboard"""
        data = self.status.get_status()
        output = []
        
        # Header
        output.append(f"{self.COLORS['BOLD']}{self.COLORS['CYAN']}")
        output.append("╔═══════════════════════════════════════════════════════════════════╗")
        output.append("║                    SecV Module Dashboard                          ║")
        output.append("╚═══════════════════════════════════════════════════════════════════╝")
        output.append(self.COLORS['RESET'])
        
        # Stats bar
        stats = data['stats']
        output.append(f"\n{self.COLORS['BOLD']}Status:{self.COLORS['RESET']} ")
        output.append(f"{self.COLORS['GREEN']}●{self.COLORS['RESET']} {stats['active_count']} Active  ")
        output.append(f"{self.COLORS['BLUE']}✓{self.COLORS['RESET']} {stats['completed_count']} Completed  ")
        output.append(f"{self.COLORS['RED']}✗{self.COLORS['RESET']} {stats['failed_count']} Failed  ")
        output.append(f"{self.COLORS['DIM']}[{datetime.now().strftime('%H:%M:%S')}]{self.COLORS['RESET']}")
        
        # Active modules
        if data['active']:
            output.append(f"\n\n{self.COLORS['BOLD']}{self.COLORS['GREEN']}Active Modules:{self.COLORS['RESET']}")
            output.append(f"{self.COLORS['DIM']}{'─' * 67}{self.COLORS['RESET']}")
            
            for mod in data['active']:
                elapsed = time.time() - mod['start_time']
                runtime = self.status.format_duration(elapsed)
                
                output.append(f"\n{self.COLORS['GREEN']}●{self.COLORS['RESET']} {self.COLORS['BOLD']}{mod['name']}{self.COLORS['RESET']}")
                output.append(f"  {self.COLORS['DIM']}Target:{self.COLORS['RESET']} {self.COLORS['CYAN']}{mod['target']}{self.COLORS['RESET']}")
                output.append(f"  {self.COLORS['DIM']}Runtime:{self.COLORS['RESET']} {runtime}")
                output.append(f"  {self.COLORS['DIM']}PID:{self.COLORS['RESET']} {mod['pid']}")
        else:
            output.append(f"\n\n{self.COLORS['DIM']}No active modules{self.COLORS['RESET']}")
        
        # Recent completed
        if data['completed']:
            output.append(f"\n\n{self.COLORS['BOLD']}{self.COLORS['BLUE']}Recently Completed:{self.COLORS['RESET']}")
            output.append(f"{self.COLORS['DIM']}{'─' * 67}{self.COLORS['RESET']}")
            
            for mod in data['completed'][:5]:
                duration = self.status.format_duration(mod['duration'])
                output.append(f"\n{self.COLORS['BLUE']}✓{self.COLORS['RESET']} {mod['name']} → {mod['target']} {self.COLORS['DIM']}({duration}){self.COLORS['RESET']}")
        
        # Recent failed
        if data['failed']:
            output.append(f"\n\n{self.COLORS['BOLD']}{self.COLORS['RED']}Recent Failures:{self.COLORS['RESET']}")
            output.append(f"{self.COLORS['DIM']}{'─' * 67}{self.COLORS['RESET']}")
            
            for mod in data['failed'][:5]:
                duration = self.status.format_duration(mod['duration'])
                output.append(f"\n{self.COLORS['RED']}✗{self.COLORS['RESET']} {mod['name']} → {mod['target']} {self.COLORS['DIM']}({duration}){self.COLORS['RESET']}")
        
        output.append("\n")
        return ''.join(output)
    
    def render_compact(self) -> str:
        """Render compact single-line status"""
        data = self.status.get_status()
        stats = data['stats']
        
        parts = [
            f"{self.COLORS['DIM']}[SecV]{self.COLORS['RESET']}",
            f"{self.COLORS['GREEN']}●{stats['active_count']}{self.COLORS['RESET']}",
            f"{self.COLORS['BLUE']}✓{stats['completed_count']}{self.COLORS['RESET']}",
            f"{self.COLORS['RED']}✗{stats['failed_count']}{self.COLORS['RESET']}"
        ]
        
        if data['active']:
            active_names = ', '.join(m['name'] for m in data['active'])
            parts.append(f"{self.COLORS['YELLOW']}Running:{self.COLORS['RESET']} {active_names}")
        
        return ' '.join(parts)


# Global status tracker
_status_tracker = None

def get_status_tracker() -> ModuleStatus:
    """Get or create global status tracker"""
    global _status_tracker
    if _status_tracker is None:
        _status_tracker = ModuleStatus()
    return _status_tracker


def show_dashboard():
    """Display full dashboard (blocking)"""
    tracker = get_status_tracker()
    renderer = DashboardRenderer(tracker)
    
    print("\033[2J\033[H")  # Clear screen and move to top
    print(renderer.render())


def show_compact_status():
    """Display compact status bar"""
    tracker = get_status_tracker()
    renderer = DashboardRenderer(tracker)
    print(renderer.render_compact())


def start_module_tracking(module_name: str, target: str, pid: int):
    """Start tracking a module execution"""
    tracker = get_status_tracker()
    tracker.start_module(module_name, target, pid)


def complete_module_tracking(module_name: str, success: bool, duration: float):
    """Complete tracking a module execution"""
    tracker = get_status_tracker()
    tracker.complete_module(module_name, success, duration)


def export_status_json() -> str:
    """Export current status as JSON"""
    tracker = get_status_tracker()
    return json.dumps(tracker.get_status(), indent=2)


# CLI interface for testing
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == 'dashboard':
            show_dashboard()
        elif cmd == 'compact':
            show_compact_status()
        elif cmd == 'json':
            print(export_status_json())
        elif cmd == 'test':
            # Test with dummy data
            tracker = get_status_tracker()
            tracker.start_module('portscan', '192.168.1.1', 12345)
            tracker.start_module('web-enum', 'example.com', 12346)
            time.sleep(1)
            tracker.complete_module('portscan', True, 2.5)
            tracker.complete_module('web-enum', False, 5.2)
            show_dashboard()
    else:
        print("Usage: dashboard.py [dashboard|compact|json|test]")
