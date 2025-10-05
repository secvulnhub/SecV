#!/usr/bin/env python3
"""
SecV Auto-Updater
Version: 2.1.0

Automatically updates SecV from GitHub repository including:
- Core system files
- Module updates
- Dependency management
- Documentation
"""

import os
import sys
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
NC = '\033[0m'

# Configuration
GITHUB_REPO = "SecVulnHub/SecV"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_RAW = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main"

SECV_HOME = Path(__file__).parent.absolute()
VERSION_FILE = SECV_HOME / ".version"
BACKUP_DIR = SECV_HOME / ".backups"


class SecVUpdater:
    def __init__(self):
        self.current_version = self.get_current_version()
        self.latest_version = None
        self.changes = []
        
    def get_current_version(self) -> str:
        """Get current installed version"""
        if VERSION_FILE.exists():
            return VERSION_FILE.read_text().strip()
        return "0.0.0"
    
    def check_for_updates(self) -> Tuple[bool, str]:
        """Check if updates are available"""
        try:
            print(f"{YELLOW}Checking for updates...{NC}")
            
            # Get latest release info from GitHub
            url = f"{GITHUB_API}/releases/latest"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read())
                self.latest_version = data['tag_name'].lstrip('v')
                
            print(f"{BLUE}Current version: {self.current_version}{NC}")
            print(f"{BLUE}Latest version: {self.latest_version}{NC}")
            
            if self.latest_version > self.current_version:
                return True, self.latest_version
            else:
                print(f"{GREEN}✓ You're already on the latest version!{NC}")
                return False, self.current_version
                
        except urllib.error.URLError as e:
            print(f"{RED}✗ Failed to check for updates: {e}{NC}")
            return False, self.current_version
        except Exception as e:
            print(f"{RED}✗ Error: {e}{NC}")
            return False, self.current_version
    
    def download_file(self, remote_path: str, local_path: Path) -> bool:
        """Download a file from GitHub"""
        try:
            url = f"{GITHUB_RAW}/{remote_path}"
            local_path.parent.mkdir(parents=True, exist_ok=True)
            
            urllib.request.urlretrieve(url, local_path)
            return True
        except Exception as e:
            print(f"{RED}✗ Failed to download {remote_path}: {e}{NC}")
            return False
    
    def backup_current(self):
        """Backup current installation"""
        print(f"\n{YELLOW}Creating backup...{NC}")
        
        timestamp = subprocess.check_output(['date', '+%Y%m%d_%H%M%S']).decode().strip()
        backup_path = BACKUP_DIR / timestamp
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Backup critical files
        critical_files = [
            'secV',
            'requirements.txt',
            'install.sh',
            '.version'
        ]
        
        for file in critical_files:
            src = SECV_HOME / file
            if src.exists():
                dst = backup_path / file
                dst.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(['cp', str(src), str(dst)], check=False)
        
        print(f"{GREEN}✓ Backup created at {backup_path}{NC}")
        return backup_path
    
    def update_dependencies(self, tier: str = "standard") -> bool:
        """Update Python dependencies"""
        print(f"\n{YELLOW}Updating dependencies ({tier} tier)...{NC}")
        
        # Download latest requirements.txt
        req_file = SECV_HOME / "requirements.txt"
        if not self.download_file("requirements.txt", req_file):
            return False
        
        # Parse tier-specific dependencies
        deps = self.parse_requirements(req_file, tier)
        
        if not deps:
            print(f"{YELLOW}No dependencies to update{NC}")
            return True
        
        # Update dependencies
        cmd = [
            sys.executable, '-m', 'pip', 'install',
            '--upgrade',
            '--user',
            '--break-system-packages'
        ] + deps
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{GREEN}✓ Dependencies updated successfully{NC}")
                return True
            else:
                print(f"{RED}✗ Dependency update failed{NC}")
                print(result.stderr)
                return False
        except Exception as e:
            print(f"{RED}✗ Error updating dependencies: {e}{NC}")
            return False
    
    def parse_requirements(self, req_file: Path, tier: str) -> List[str]:
        """Parse requirements.txt for specific tier"""
        deps = []
        current_tier = None
        
        tier_map = {
            'basic': ['CORE'],
            'standard': ['CORE', 'STANDARD'],
            'full': ['CORE', 'STANDARD', 'FULL']
        }
        
        target_tiers = tier_map.get(tier.lower(), ['CORE', 'STANDARD'])
        
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                
                # Detect tier sections
                if 'CORE TIER' in line:
                    current_tier = 'CORE'
                elif 'STANDARD TIER' in line:
                    current_tier = 'STANDARD'
                elif 'FULL TIER' in line:
                    current_tier = 'FULL'
                elif 'OPTIONAL' in line:
                    current_tier = None
                
                # Add dependencies from relevant tiers
                if current_tier in target_tiers:
                    if line and not line.startswith('#') and not line.startswith('='):
                        # Extract package name (before #)
                        pkg = line.split('#')[0].strip()
                        if pkg:
                            deps.append(pkg)
        
        return deps
    
    def update_core_files(self) -> bool:
        """Update core SecV files"""
        print(f"\n{YELLOW}Updating core files...{NC}")
        
        core_files = [
            'secV',
            'install.sh',
            'uninstall.sh',
            'requirements.txt',
            'README.md',
            'INSTALL.md',
            'CONTRIBUTING.md',
            'MODULE_HELP_GUIDE.md'
        ]
        
        success = True
        for file in core_files:
            if self.download_file(file, SECV_HOME / file):
                print(f"{GREEN}✓ Updated {file}{NC}")
                
                # Make scripts executable
                if file.endswith('.sh') or file == 'secV':
                    os.chmod(SECV_HOME / file, 0o755)
            else:
                print(f"{YELLOW}⚠ Skipped {file}{NC}")
                success = False
        
        return success
    
    def update_modules(self) -> bool:
        """Update all modules from repository"""
        print(f"\n{YELLOW}Updating modules...{NC}")
        
        try:
            # Get list of modules from GitHub API
            url = f"{GITHUB_API}/contents/tools"
            with urllib.request.urlopen(url, timeout=10) as response:
                categories = json.loads(response.read())
            
            updated_count = 0
            
            for category in categories:
                if category['type'] != 'dir':
                    continue
                
                cat_name = category['name']
                cat_url = f"{GITHUB_API}/contents/tools/{cat_name}"
                
                with urllib.request.urlopen(cat_url, timeout=10) as response:
                    modules = json.loads(response.read())
                
                for module in modules:
                    if module['type'] != 'dir':
                        continue
                    
                    mod_name = module['name']
                    
                    # Download module files
                    module_dir = SECV_HOME / 'tools' / cat_name / mod_name
                    module_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Download module.json
                    if self.download_file(
                        f"tools/{cat_name}/{mod_name}/module.json",
                        module_dir / "module.json"
                    ):
                        print(f"{GREEN}✓ Updated {cat_name}/{mod_name}{NC}")
                        updated_count += 1
                    
                    # Download README if exists
                    self.download_file(
                        f"tools/{cat_name}/{mod_name}/README.md",
                        module_dir / "README.md"
                    )
            
            print(f"\n{GREEN}✓ Updated {updated_count} modules{NC}")
            return True
            
        except Exception as e:
            print(f"{RED}✗ Failed to update modules: {e}{NC}")
            return False
    
    def update_version(self):
        """Update version file"""
        VERSION_FILE.write_text(self.latest_version)
    
    def run_update(self, update_deps: bool = True, update_mods: bool = True):
        """Run full update process"""
        print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{CYAN}║                    SecV Auto-Updater v2.1                         ║{NC}")
        print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        
        # Check for updates
        has_update, version = self.check_for_updates()
        
        if not has_update:
            return
        
        print(f"\n{GREEN}Update available: v{version}{NC}")
        
        response = input(f"\n{YELLOW}Do you want to update? [Y/n]: {NC}").strip().lower()
        if response and response != 'y':
            print(f"{BLUE}Update cancelled{NC}")
            return
        
        # Backup current installation
        backup_path = self.backup_current()
        
        # Detect current tier
        tier = self.detect_tier()
        print(f"\n{BLUE}Detected installation tier: {tier}{NC}")
        
        # Update core files
        if not self.update_core_files():
            print(f"{YELLOW}⚠ Some core files failed to update{NC}")
        
        # Update dependencies
        if update_deps:
            if not self.update_dependencies(tier):
                print(f"{YELLOW}⚠ Dependency update had issues{NC}")
        
        # Update modules
        if update_mods:
            if not self.update_modules():
                print(f"{YELLOW}⚠ Module update had issues{NC}")
        
        # Update version
        self.update_version()
        
        print(f"\n{GREEN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{GREEN}║                  Update Complete!                                 ║{NC}")
        print(f"{GREEN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        
        print(f"{BLUE}Updated to version: {version}{NC}")
        print(f"{BLUE}Backup location: {backup_path}{NC}")
        print(f"\n{YELLOW}Restart SecV to use the new version: ./secV{NC}\n")
    
    def detect_tier(self) -> str:
        """Detect current installation tier"""
        try:
            # Try importing tier-specific modules
            try:
                import scapy.all
                has_scapy = True
            except ImportError:
                has_scapy = False
            
            try:
                import requests
                has_requests = True
            except ImportError:
                has_requests = False
            
            if has_requests:
                return "full"
            elif has_scapy:
                return "standard"
            else:
                return "basic"
        except:
            return "basic"


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SecV Auto-Updater')
    parser.add_argument('--check', action='store_true', help='Only check for updates')
    parser.add_argument('--no-deps', action='store_true', help='Skip dependency updates')
    parser.add_argument('--no-modules', action='store_true', help='Skip module updates')
    parser.add_argument('--force', action='store_true', help='Force update even if up to date')
    
    args = parser.parse_args()
    
    updater = SecVUpdater()
    
    if args.check:
        has_update, version = updater.check_for_updates()
        sys.exit(0 if not has_update else 1)
    else:
        updater.run_update(
            update_deps=not args.no_deps,
            update_mods=not args.no_modules
        )


if __name__ == '__main__':
    main()
