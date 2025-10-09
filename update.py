#!/usr/bin/env python3
"""
SecV Enhanced Update System v3.0
Features:
- Forced update check with version comparison
- Automatic obsolete file cleanup
- Component-level update tracking
- Rollback capability
- Dependency conflict resolution
"""

import os
import sys
import json
import subprocess
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

# --- Configuration ---
REQUIREMENTS_FILE = "requirements.txt"
SECV_HOME = Path(__file__).parent.absolute()
CACHE_DIR = SECV_HOME / ".cache"
REQUIREMENTS_HASH_FILE = CACHE_DIR / ".requirements_hash"
VERSION_FILE = CACHE_DIR / ".version_info"
OBSOLETE_FILES_DB = CACHE_DIR / ".obsolete_files.json"
UPDATE_LOG = CACHE_DIR / "update.log"
BACKUP_DIR = CACHE_DIR / ".backup"

# Update check interval (in days)
UPDATE_CHECK_INTERVAL = 1

# --- Colors for better output ---
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
BOLD = '\033[1m'
DIM = '\033[2m'
NC = '\033[0m'

# --- Version Info Structure ---
VERSION_INFO = {
    "current_version": "2.3.1",
    "last_check": None,
    "last_update": None,
    "components": {
        "secV": {"version": "2.3.1", "hash": None},
        "install.sh": {"version": "2.3.0", "hash": None},
        "update.py": {"version": "3.0.0", "hash": None},
        "dashboard.py": {"version": "1.0.0", "hash": None},
        "requirements.txt": {"version": "2.3.0", "hash": None}
    }
}

# --- Obsolete Files Database ---
# Maps version → list of files to remove
OBSOLETE_FILES_MAP = {
    "2.2.0": [
        ".cache/old_cache.db",
        "tools/deprecated_module/*"
    ],
    "2.3.0": [
        ".cache/modules.db",
        "old_secV",
        "legacy_installer.sh"
    ]
}


class Logger:
    """Simple logger for update operations"""
    
    @staticmethod
    def log(message: str, level: str = "INFO"):
        """Log message to file and optionally console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(UPDATE_LOG, 'a') as f:
            f.write(log_entry)
    
    @staticmethod
    def clear_old_logs():
        """Keep only last 100 lines of log"""
        if UPDATE_LOG.exists():
            with open(UPDATE_LOG, 'r') as f:
                lines = f.readlines()
            
            if len(lines) > 100:
                with open(UPDATE_LOG, 'w') as f:
                    f.writelines(lines[-100:])


class VersionManager:
    """Manage version information and tracking"""
    
    @staticmethod
    def load_version_info() -> Dict:
        """Load version info from cache"""
        if VERSION_FILE.exists():
            try:
                with open(VERSION_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return VERSION_INFO.copy()
    
    @staticmethod
    def save_version_info(info: Dict):
        """Save version info to cache"""
        VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(VERSION_FILE, 'w') as f:
            json.dump(info, f, indent=2)
        Logger.log(f"Saved version info: {info['current_version']}")
    
    @staticmethod
    def update_component_hash(component: str, filepath: Path, version_info: Dict):
        """Update hash for a specific component"""
        if filepath.exists():
            file_hash = get_file_hash(filepath)
            if component not in version_info["components"]:
                version_info["components"][component] = {}
            version_info["components"][component]["hash"] = file_hash
    
    @staticmethod
    def check_component_changed(component: str, filepath: Path, version_info: Dict) -> bool:
        """Check if component file has changed"""
        if component not in version_info["components"]:
            return True
        
        stored_hash = version_info["components"][component].get("hash")
        if not stored_hash:
            return True
        
        current_hash = get_file_hash(filepath)
        return current_hash != stored_hash
    
    @staticmethod
    def should_check_updates(version_info: Dict) -> bool:
        """Determine if we should check for updates"""
        last_check = version_info.get("last_check")
        if not last_check:
            return True
        
        try:
            last_check_dt = datetime.fromisoformat(last_check)
            next_check = last_check_dt + timedelta(days=UPDATE_CHECK_INTERVAL)
            return datetime.now() >= next_check
        except:
            return True


class BackupManager:
    """Handle backup and rollback operations"""
    
    @staticmethod
    def create_backup(files: List[Path]) -> Optional[Path]:
        """Create backup of specified files"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / timestamp
            backup_path.mkdir(parents=True, exist_ok=True)
            
            for file in files:
                if file.exists():
                    rel_path = file.relative_to(SECV_HOME)
                    dest = backup_path / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file, dest)
            
            Logger.log(f"Created backup: {backup_path}")
            print(f"{GREEN}✓ Backup created: {backup_path.name}{NC}")
            return backup_path
        except Exception as e:
            Logger.log(f"Backup failed: {str(e)}", "ERROR")
            print(f"{RED}✗ Backup failed: {str(e)}{NC}")
            return None
    
    @staticmethod
    def list_backups() -> List[Path]:
        """List available backups"""
        if not BACKUP_DIR.exists():
            return []
        return sorted([d for d in BACKUP_DIR.iterdir() if d.is_dir()], reverse=True)
    
    @staticmethod
    def restore_backup(backup_path: Path) -> bool:
        """Restore from backup"""
        try:
            for item in backup_path.rglob("*"):
                if item.is_file():
                    rel_path = item.relative_to(backup_path)
                    dest = SECV_HOME / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest)
            
            Logger.log(f"Restored backup: {backup_path}")
            print(f"{GREEN}✓ Restored from backup: {backup_path.name}{NC}")
            return True
        except Exception as e:
            Logger.log(f"Restore failed: {str(e)}", "ERROR")
            print(f"{RED}✗ Restore failed: {str(e)}{NC}")
            return False
    
    @staticmethod
    def cleanup_old_backups(keep: int = 5):
        """Keep only the most recent backups"""
        backups = BackupManager.list_backups()
        if len(backups) > keep:
            for old_backup in backups[keep:]:
                try:
                    shutil.rmtree(old_backup)
                    Logger.log(f"Removed old backup: {old_backup}")
                except:
                    pass


class ObsoleteFilesCleaner:
    """Clean up obsolete files from previous versions"""
    
    @staticmethod
    def load_obsolete_db() -> Dict:
        """Load obsolete files database"""
        if OBSOLETE_FILES_DB.exists():
            try:
                with open(OBSOLETE_FILES_DB, 'r') as f:
                    return json.load(f)
            except:
                pass
        return OBSOLETE_FILES_MAP.copy()
    
    @staticmethod
    def save_obsolete_db(db: Dict):
        """Save obsolete files database"""
        OBSOLETE_FILES_DB.parent.mkdir(parents=True, exist_ok=True)
        with open(OBSOLETE_FILES_DB, 'w') as f:
            json.dump(db, f, indent=2)
    
    @staticmethod
    def find_obsolete_files(current_version: str, new_version: str) -> List[str]:
        """Find files that should be removed for this upgrade"""
        db = ObsoleteFilesCleaner.load_obsolete_db()
        obsolete = []
        
        # Check all versions between current and new
        for version, files in db.items():
            if version > current_version and version <= new_version:
                obsolete.extend(files)
        
        return obsolete
    
    @staticmethod
    def clean_obsolete_files(files: List[str]) -> Tuple[int, int]:
        """Remove obsolete files. Returns (removed, failed)"""
        removed = 0
        failed = 0
        
        for file_pattern in files:
            try:
                # Handle wildcards
                if '*' in file_pattern:
                    import glob
                    matches = glob.glob(str(SECV_HOME / file_pattern))
                    for match in matches:
                        path = Path(match)
                        if path.exists():
                            if path.is_dir():
                                shutil.rmtree(path)
                            else:
                                path.unlink()
                            removed += 1
                            Logger.log(f"Removed obsolete: {path}")
                else:
                    path = SECV_HOME / file_pattern
                    if path.exists():
                        if path.is_dir():
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                        removed += 1
                        Logger.log(f"Removed obsolete: {path}")
            except Exception as e:
                failed += 1
                Logger.log(f"Failed to remove {file_pattern}: {str(e)}", "ERROR")
        
        return removed, failed


def run_command(command: list, capture: bool = True, check: bool = True):
    """Helper function to run shell commands"""
    try:
        return subprocess.run(
            command,
            capture_output=capture,
            text=True,
            check=check,
            cwd=SECV_HOME
        )
    except FileNotFoundError:
        print(f"{RED}✗ Error: Command '{command[0]}' not found.{NC}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if check:
            print(f"{RED}✗ Error executing command: {' '.join(command)}{NC}")
            if e.stderr:
                print(f"{RED}{e.stderr}{NC}")
            sys.exit(1)
        return e


def get_file_hash(filepath: Path) -> Optional[str]:
    """Calculate SHA256 hash of a file"""
    if not filepath.exists():
        return None
    
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_git_repository() -> bool:
    """Check if this is a git repository"""
    return (SECV_HOME / '.git').is_dir()


def get_remote_version() -> Optional[str]:
    """Get version from remote repository"""
    try:
        # Fetch latest
        run_command(['git', 'fetch'], capture=True)
        
        # Check if there's a VERSION file or parse from update.py
        result = run_command(['git', 'show', 'origin/main:update.py'], check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'current_version' in line and '=' in line:
                    version = line.split('=')[1].strip().strip('"').strip("'")
                    return version
    except:
        pass
    return None


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns: -1 (v1<v2), 0 (equal), 1 (v1>v2)"""
    try:
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]
        
        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        
        if len(parts1) < len(parts2):
            return -1
        elif len(parts1) > len(parts2):
            return 1
        
        return 0
    except:
        return 0


def check_for_updates(force: bool = False) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if updates are available
    Returns: (has_update, current_version, new_version)
    """
    version_info = VersionManager.load_version_info()
    
    # Check if we should check for updates
    if not force and not VersionManager.should_check_updates(version_info):
        return False, version_info["current_version"], None
    
    print(f"{YELLOW}Checking for updates...{NC}")
    
    if not check_git_repository():
        print(f"{RED}✗ Not a git repository. Cannot check for updates.{NC}")
        return False, version_info["current_version"], None
    
    try:
        # Fetch the latest changes
        run_command(['git', 'fetch'])
        
        # Check if behind remote
        status_result = run_command(['git', 'status', '-uno'])
        
        if "Your branch is up to date" in status_result.stdout:
            # Update last check time
            version_info["last_check"] = datetime.now().isoformat()
            VersionManager.save_version_info(version_info)
            return False, version_info["current_version"], None
        
        elif "Your branch is behind" in status_result.stdout:
            # Get remote version
            remote_version = get_remote_version()
            current_version = version_info["current_version"]
            
            # Update last check time
            version_info["last_check"] = datetime.now().isoformat()
            VersionManager.save_version_info(version_info)
            
            return True, current_version, remote_version
        
    except Exception as e:
        Logger.log(f"Update check failed: {str(e)}", "ERROR")
        print(f"{RED}✗ Failed to check for updates: {str(e)}{NC}")
    
    return False, version_info["current_version"], None


def install_dependencies() -> bool:
    """Install Python dependencies"""
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    
    if not requirements_path.exists():
        print(f"{RED}✗ {REQUIREMENTS_FILE} not found!{NC}")
        return False
    
    print(f"\n{YELLOW}Installing/updating dependencies...{NC}")
    
    # Try multiple installation strategies
    pip_commands = [
        [sys.executable, '-m', 'pip', 'install', '--user', '-r', str(requirements_path)],
        [sys.executable, '-m', 'pip', 'install', '--user', '--break-system-packages', '-r', str(requirements_path)],
        [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_path)],
        [sys.executable, '-m', 'pip', 'install', '--break-system-packages', '-r', str(requirements_path)],
    ]
    
    for i, pip_command in enumerate(pip_commands):
        print(f"{CYAN}Attempt {i+1}/{len(pip_commands)}...{NC}")
        try:
            result = subprocess.run(pip_command, check=False, capture_output=True, cwd=SECV_HOME)
            if result.returncode == 0:
                print(f"{GREEN}✓ Dependencies installed successfully!{NC}")
                Logger.log("Dependencies installed successfully")
                return True
        except Exception as e:
            continue
    
    # Last resort: sudo
    print(f"{YELLOW}⚠ Attempting installation with sudo...{NC}")
    sudo_command = ['sudo', sys.executable, '-m', 'pip', 'install', '--break-system-packages', '-r', str(requirements_path)]
    try:
        result = subprocess.run(sudo_command, check=False, capture_output=False, cwd=SECV_HOME)
        if result.returncode == 0:
            print(f"{GREEN}✓ Dependencies installed with sudo!{NC}")
            Logger.log("Dependencies installed with sudo")
            return True
    except Exception as e:
        pass
    
    print(f"{RED}✗ Failed to install dependencies{NC}")
    Logger.log("Dependency installation failed", "ERROR")
    return False


def perform_update(current_version: str, new_version: str) -> bool:
    """Perform the actual update"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Performing SecV Update                         ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    Logger.log(f"Starting update: {current_version} -> {new_version}")
    
    # Step 1: Create backup
    print(f"{YELLOW}[1/6] Creating backup...{NC}")
    critical_files = [
        SECV_HOME / "secV",
        SECV_HOME / "install.sh",
        SECV_HOME / "update.py",
        SECV_HOME / "requirements.txt",
        CACHE_DIR / ".requirements_hash",
        VERSION_FILE
    ]
    
    backup_path = BackupManager.create_backup(critical_files)
    if not backup_path:
        print(f"{RED}✗ Backup failed. Aborting update.{NC}")
        return False
    
    # Step 2: Pull updates
    print(f"\n{YELLOW}[2/6] Pulling latest changes...{NC}")
    try:
        result = run_command(['git', 'pull'], capture=False)
        print(f"{GREEN}✓ Git pull successful{NC}")
        Logger.log("Git pull successful")
    except Exception as e:
        print(f"{RED}✗ Git pull failed: {str(e)}{NC}")
        Logger.log(f"Git pull failed: {str(e)}", "ERROR")
        
        # Offer rollback
        response = input(f"\n{YELLOW}Restore from backup? [Y/n]: {NC}").strip().lower()
        if not response or response == 'y':
            BackupManager.restore_backup(backup_path)
        return False
    
    # Step 3: Clean obsolete files
    print(f"\n{YELLOW}[3/6] Cleaning obsolete files...{NC}")
    obsolete_files = ObsoleteFilesCleaner.find_obsolete_files(current_version, new_version)
    
    if obsolete_files:
        print(f"{DIM}Found {len(obsolete_files)} obsolete file(s){NC}")
        for file in obsolete_files:
            print(f"  {DIM}• {file}{NC}")
        
        response = input(f"\n{YELLOW}Remove obsolete files? [Y/n]: {NC}").strip().lower()
        if not response or response == 'y':
            removed, failed = ObsoleteFilesCleaner.clean_obsolete_files(obsolete_files)
            print(f"{GREEN}✓ Removed {removed} file(s){NC}")
            if failed > 0:
                print(f"{YELLOW}⚠ Failed to remove {failed} file(s){NC}")
    else:
        print(f"{GREEN}✓ No obsolete files found{NC}")
    
    # Step 4: Update dependencies
    print(f"\n{YELLOW}[4/6] Updating dependencies...{NC}")
    
    # Check if requirements.txt changed
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    old_hash = get_file_hash(requirements_path)
    
    version_info = VersionManager.load_version_info()
    stored_hash = version_info["components"].get("requirements.txt", {}).get("hash")
    
    if old_hash != stored_hash:
        print(f"{CYAN}requirements.txt has changed{NC}")
        if not install_dependencies():
            print(f"{YELLOW}⚠ Dependency update failed, but continuing...{NC}")
    else:
        print(f"{GREEN}✓ No dependency changes{NC}")
    
    # Step 5: Update version info
    print(f"\n{YELLOW}[5/6] Updating version information...{NC}")
    
    version_info["current_version"] = new_version
    version_info["last_update"] = datetime.now().isoformat()
    version_info["last_check"] = datetime.now().isoformat()
    
    # Update component hashes
    components = {
        "secV": SECV_HOME / "secV",
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "dashboard.py": SECV_HOME / "dashboard.py",
        "requirements.txt": requirements_path
    }
    
    for comp_name, comp_path in components.items():
        VersionManager.update_component_hash(comp_name, comp_path, version_info)
    
    VersionManager.save_version_info(version_info)
    print(f"{GREEN}✓ Version info updated{NC}")
    
    # Step 6: Cleanup
    print(f"\n{YELLOW}[6/6] Cleaning up...{NC}")
    BackupManager.cleanup_old_backups(keep=5)
    Logger.cleanup_old_logs()
    print(f"{GREEN}✓ Cleanup complete{NC}")
    
    Logger.log(f"Update completed successfully: {new_version}")
    return True


def show_update_summary(current_version: str, new_version: str):
    """Display update summary"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Update Available!                              ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    print(f"  {BOLD}Current Version:{NC} {RED}{current_version}{NC}")
    print(f"  {BOLD}New Version:{NC}     {GREEN}{new_version}{NC}")
    
    # Check for obsolete files
    obsolete_files = ObsoleteFilesCleaner.find_obsolete_files(current_version, new_version)
    if obsolete_files:
        print(f"\n  {YELLOW}⚠ Will clean {len(obsolete_files)} obsolete file(s){NC}")
    
    print(f"\n  {DIM}This update will:{NC}")
    print(f"    • Pull latest changes from repository")
    print(f"    • Clean obsolete files")
    print(f"    • Update dependencies if needed")
    print(f"    • Create backup before updating")
    print()


def main():
    """Main update process"""
    print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{CYAN}║                      SecV Update System v3.0                      ║{NC}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    Logger.log("Update check initiated")
    
    # Check for updates (force check)
    has_update, current_version, new_version = check_for_updates(force=True)
    
    if not has_update:
        print(f"{GREEN}✓ You're already on the latest version!{NC}")
        print(f"  {BOLD}Current Version:{NC} {GREEN}{current_version}{NC}\n")
        
        # Show when next check will occur
        version_info = VersionManager.load_version_info()
        last_check = version_info.get("last_check")
        if last_check:
            try:
                last_check_dt = datetime.fromisoformat(last_check)
                next_check = last_check_dt + timedelta(days=UPDATE_CHECK_INTERVAL)
                print(f"{DIM}Next automatic check: {next_check.strftime('%Y-%m-%d %H:%M')}{NC}\n")
            except:
                pass
        
        sys.exit(0)
    
    # Show update summary
    show_update_summary(current_version, new_version or "unknown")
    
    # Ask user if they want to update
    response = input(f"{YELLOW}Do you want to update now? [Y/n]: {NC}").strip().lower()
    if response and response != 'y':
        print(f"{CYAN}Update cancelled by user.{NC}")
        Logger.log("Update cancelled by user")
        sys.exit(0)
    
    # Perform update
    success = perform_update(current_version, new_version or "unknown")
    
    if success:
        print(f"\n{BOLD}{GREEN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{GREEN}║                    Update Complete! ✓                             ║{NC}")
        print(f"{BOLD}{GREEN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        
        print(f"{BOLD}{GREEN}✓ SecV has been updated successfully!{NC}\n")
        
        print(f"{BLUE}Next Steps:{NC}")
        print(f"  1. {YELLOW}Restart SecV{NC} to load updated components")
        print(f"  2. {YELLOW}Run 'reload'{NC} inside SecV to rescan modules")
        print(f"  3. {YELLOW}Type 'show modules'{NC} to see all available modules\n")
        
        # Show backup info
        backups = BackupManager.list_backups()
        if backups:
            print(f"{MAGENTA}ℹ Backup available at: {backups[0].name}{NC}")
            print(f"{DIM}  Use 'python3 update.py --rollback' to restore if needed{NC}\n")
    else:
        print(f"\n{RED}✗ Update failed. Check {UPDATE_LOG} for details.{NC}\n")
        Logger.log("Update failed", "ERROR")
        sys.exit(1)


def show_component_status():
    """Show status of all SecV components"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    SecV Component Status                          ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    version_info = VersionManager.load_version_info()
    
    print(f"  {BOLD}Current Version:{NC} {GREEN}{version_info['current_version']}{NC}")
    
    last_update = version_info.get("last_update")
    if last_update:
        try:
            last_update_dt = datetime.fromisoformat(last_update)
            print(f"  {BOLD}Last Update:{NC} {last_update_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            pass
    
    print(f"\n  {BOLD}Components:{NC}")
    print(f"  {DIM}{'─' * 65}{NC}")
    
    components_to_check = {
        "secV": SECV_HOME / "secV",
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "dashboard.py": SECV_HOME / "dashboard.py",
        "requirements.txt": SECV_HOME / REQUIREMENTS_FILE
    }
    
    for comp_name, comp_path in components_to_check.items():
        if comp_path.exists():
            comp_info = version_info["components"].get(comp_name, {})
            comp_version = comp_info.get("version", "unknown")
            
            # Check if component changed
            changed = VersionManager.check_component_changed(comp_name, comp_path, version_info)
            status = f"{YELLOW}[MODIFIED]{NC}" if changed else f"{GREEN}[OK]{NC}"
            
            print(f"    {status} {BOLD}{comp_name:<20}{NC} v{comp_version}")
        else:
            print(f"    {RED}[MISSING]{NC} {BOLD}{comp_name:<20}{NC} {DIM}not found{NC}")
    
    print()


def verify_installation():
    """Verify SecV installation integrity"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Verifying Installation                         ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    issues = []
    
    # Check critical files
    critical_files = {
        "secV": SECV_HOME / "secV",
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "requirements.txt": SECV_HOME / REQUIREMENTS_FILE
    }
    
    print(f"  {BOLD}Checking critical files...{NC}")
    for name, path in critical_files.items():
        if path.exists():
            print(f"    {GREEN}✓{NC} {name}")
        else:
            print(f"    {RED}✗{NC} {name} {DIM}(missing){NC}")
            issues.append(f"Missing critical file: {name}")
    
    # Check directories
    print(f"\n  {BOLD}Checking directories...{NC}")
    critical_dirs = {
        "tools": SECV_HOME / "tools",
        ".cache": CACHE_DIR
    }
    
    for name, path in critical_dirs.items():
        if path.exists() and path.is_dir():
            print(f"    {GREEN}✓{NC} {name}/")
        else:
            print(f"    {YELLOW}⚠{NC} {name}/ {DIM}(will be created){NC}")
            path.mkdir(parents=True, exist_ok=True)
    
    # Check Python dependencies
    print(f"\n  {BOLD}Checking Python dependencies...{NC}")
    required_packages = ['cmd2', 'rich', 'argcomplete']
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"    {GREEN}✓{NC} {package}")
        except ImportError:
            print(f"    {RED}✗{NC} {package} {DIM}(not installed){NC}")
            issues.append(f"Missing Python package: {package}")
    
    # Check git repository
    print(f"\n  {BOLD}Checking git repository...{NC}")
    if check_git_repository():
        print(f"    {GREEN}✓{NC} Git repository initialized")
        
        try:
            result = run_command(['git', 'remote', '-v'], check=False)
            if result.returncode == 0 and result.stdout:
                print(f"    {GREEN}✓{NC} Remote configured")
            else:
                print(f"    {YELLOW}⚠{NC} No remote configured")
                issues.append("Git remote not configured")
        except:
            pass
    else:
        print(f"    {RED}✗{NC} Not a git repository")
        issues.append("Not a git repository - updates disabled")
    
    # Summary
    print(f"\n  {BOLD}{'─' * 65}{NC}")
    
    if issues:
        print(f"\n  {YELLOW}⚠ Found {len(issues)} issue(s):{NC}")
        for issue in issues:
            print(f"    • {issue}")
        print(f"\n  {DIM}Run './install.sh' to fix installation issues{NC}\n")
        return False
    else:
        print(f"\n  {GREEN}✓ Installation verified - all checks passed!{NC}\n")
        return True


def repair_installation():
    """Attempt to repair common installation issues"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Repairing Installation                         ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    repaired = []
    failed = []
    
    # Create missing directories
    print(f"{YELLOW}[1/3] Creating missing directories...{NC}")
    critical_dirs = [CACHE_DIR, SECV_HOME / "tools", BACKUP_DIR]
    for dir_path in critical_dirs:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
            repaired.append(f"Created directory: {dir_path.name}")
        except Exception as e:
            failed.append(f"Failed to create {dir_path.name}: {str(e)}")
    
    if repaired:
        print(f"{GREEN}✓ Created {len(repaired)} directories{NC}")
    
    # Initialize version info if missing
    print(f"\n{YELLOW}[2/3] Checking version information...{NC}")
    version_info = VersionManager.load_version_info()
    
    # Update all component hashes
    components = {
        "secV": SECV_HOME / "secV",
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "dashboard.py": SECV_HOME / "dashboard.py",
        "requirements.txt": SECV_HOME / REQUIREMENTS_FILE
    }
    
    for comp_name, comp_path in components.items():
        if comp_path.exists():
            VersionManager.update_component_hash(comp_name, comp_path, version_info)
    
    VersionManager.save_version_info(version_info)
    repaired.append("Updated version information")
    print(f"{GREEN}✓ Version info updated{NC}")
    
    # Check and fix permissions
    print(f"\n{YELLOW}[3/3] Checking file permissions...{NC}")
    executable_files = [SECV_HOME / "secV", SECV_HOME / "install.sh"]
    
    for file in executable_files:
        if file.exists():
            try:
                os.chmod(file, 0o755)
                repaired.append(f"Fixed permissions: {file.name}")
            except Exception as e:
                failed.append(f"Failed to fix permissions on {file.name}: {str(e)}")
    
    print(f"{GREEN}✓ Permissions checked{NC}")
    
    # Summary
    print(f"\n{BOLD}{'─' * 67}{NC}")
    print(f"\n{BOLD}Repair Summary:{NC}")
    print(f"  {GREEN}✓ Repaired: {len(repaired)}{NC}")
    if failed:
        print(f"  {RED}✗ Failed: {len(failed)}{NC}")
    
    if repaired:
        print(f"\n{DIM}Repaired items:{NC}")
        for item in repaired[:5]:  # Show first 5
            print(f"    • {item}")
    
    if failed:
        print(f"\n{YELLOW}Failed items:{NC}")
        for item in failed:
            print(f"    • {item}")
    
    print()
    
    return len(failed) == 0


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SecV Update System v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 update.py                    # Check and install updates
  python3 update.py --force            # Force update check
  python3 update.py --status           # Show component status
  python3 update.py --verify           # Verify installation
  python3 update.py --repair           # Repair installation
  python3 update.py --rollback         # Rollback to backup
  python3 update.py --list-backups     # List available backups
        """
    )
    
    parser.add_argument('--rollback', action='store_true', 
                       help='Rollback to previous backup')
    parser.add_argument('--list-backups', action='store_true', 
                       help='List available backups')
    parser.add_argument('--force', action='store_true', 
                       help='Force update check (ignore interval)')
    parser.add_argument('--status', action='store_true', 
                       help='Show component status')
    parser.add_argument('--verify', action='store_true', 
                       help='Verify installation integrity')
    parser.add_argument('--repair', action='store_true', 
                       help='Repair installation issues')
    parser.add_argument('--clean', action='store_true', 
                       help='Clean old backups and logs')
    
    args = parser.parse_args()
    
    try:
        if args.status:
            show_component_status()
        
        elif args.verify:
            verify_installation()
        
        elif args.repair:
            if repair_installation():
                print(f"{GREEN}✓ Repair completed successfully!{NC}\n")
            else:
                print(f"{YELLOW}⚠ Repair completed with some failures{NC}\n")
        
        elif args.clean:
            print(f"\n{YELLOW}Cleaning old backups and logs...{NC}\n")
            BackupManager.cleanup_old_backups(keep=3)
            Logger.cleanup_old_logs()
            print(f"{GREEN}✓ Cleanup complete{NC}\n")
        
        elif args.list_backups:
            backups = BackupManager.list_backups()
            if backups:
                print(f"\n{BOLD}Available Backups:{NC}\n")
                for i, backup in enumerate(backups, 1):
                    # Get backup info
                    try:
                        backup_time = datetime.strptime(backup.name, "%Y%m%d_%H%M%S")
                        time_str = backup_time.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        time_str = backup.name
                    
                    # Calculate size
                    total_size = sum(f.stat().st_size for f in backup.rglob('*') if f.is_file())
                    size_mb = total_size / (1024 * 1024)
                    
                    print(f"  {BOLD}{i}.{NC} {time_str} {DIM}({size_mb:.2f} MB){NC}")
                print()
            else:
                print(f"\n{YELLOW}No backups available{NC}\n")
        
        elif args.rollback:
            backups = BackupManager.list_backups()
            if not backups:
                print(f"\n{YELLOW}No backups available for rollback{NC}\n")
                sys.exit(1)
            
            print(f"\n{BOLD}Available Backups:{NC}\n")
            for i, backup in enumerate(backups, 1):
                try:
                    backup_time = datetime.strptime(backup.name, "%Y%m%d_%H%M%S")
                    time_str = backup_time.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    time_str = backup.name
                print(f"  {i}. {time_str}")
            
            try:
                choice = int(input(f"\n{YELLOW}Select backup to restore [1-{len(backups)}]: {NC}"))
                if 1 <= choice <= len(backups):
                    selected_backup = backups[choice - 1]
                    
                    # Confirm
                    response = input(f"\n{RED}This will restore files from backup. Continue? [y/N]: {NC}").strip().lower()
                    if response != 'y':
                        print(f"{CYAN}Rollback cancelled{NC}\n")
                        sys.exit(0)
                    
                    print(f"\n{YELLOW}Restoring backup: {selected_backup.name}...{NC}")
                    if BackupManager.restore_backup(selected_backup):
                        print(f"{GREEN}✓ Rollback successful!{NC}")
                        print(f"{DIM}Restart SecV to use restored version{NC}\n")
                    else:
                        print(f"{RED}✗ Rollback failed{NC}\n")
                        sys.exit(1)
                else:
                    print(f"{RED}Invalid selection{NC}")
                    sys.exit(1)
            except (ValueError, KeyboardInterrupt):
                print(f"\n{CYAN}Rollback cancelled{NC}\n")
                sys.exit(0)
        
        else:
            # Default: run update check and install
            main()
    
    except KeyboardInterrupt:
        print(f"\n\n{CYAN}Operation cancelled by user{NC}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}✗ Unexpected error: {str(e)}{NC}\n")
        Logger.log(f"Unexpected error: {str(e)}", "ERROR")
        sys.exit(1)
