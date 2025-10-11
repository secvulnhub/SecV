#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecV Enhanced Update System v4.1
Features:
- First-run automatic update checking
- Go binary recompilation support
- Forced update check with version comparison
- Automatic obsolete file cleanup
- Component-level update tracking
- Rollback capability
- Dependency conflict resolution
- Git conflict resolution (stash/restore)
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
LAST_CHECK_FILE = CACHE_DIR / ".last_update_check"
OBSOLETE_FILES_DB = CACHE_DIR / ".obsolete_files.json"
UPDATE_LOG = CACHE_DIR / "update.log"
BACKUP_DIR = CACHE_DIR / ".backup"
MAIN_GO = SECV_HOME / "main.go"
SECV_BINARY = SECV_HOME / "secV"

# Update check interval (in hours)
UPDATE_CHECK_INTERVAL = 24

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

# --- Symbols ---
CHECK = "✓"
CROSS = "✗"
BULLET = "•"
WARNING = "⚠"
GEAR = "⚙"
INFO = "ℹ"

# --- Version Info Structure ---
VERSION_INFO = {
    "current_version": "2.4.0",
    "last_check": None,
    "last_update": None,
    "go_compiled": True,
    "components": {
        "main.go": {"version": "2.4.0", "hash": None},
        "install.sh": {"version": "2.4.0", "hash": None},
        "update.py": {"version": "4.1.0", "hash": None},
        "dashboard.py": {"version": "1.0.0", "hash": None},
        "requirements.txt": {"version": "2.3.0", "hash": None},
        "secV": {"version": "2.4.0", "hash": None, "type": "binary"}
    }
}

# --- Obsolete Files Database ---
OBSOLETE_FILES_MAP = {
    "2.2.0": [
        ".cache/old_cache.db",
        "tools/deprecated_module/*"
    ],
    "2.3.0": [
        ".cache/modules.db",
        "old_secV",
        "legacy_installer.sh"
    ],
    "2.4.0": [
        "secV.py",
        ".cache/old_update_check"
    ]
}


class Logger:
    """Simple logger for update operations"""
    
    @staticmethod
    def log(message: str, level: str = "INFO"):
        """Log message to file"""
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


class GitManager:
    """Manage Git operations with conflict resolution"""
    
    @staticmethod
    def has_uncommitted_changes() -> Tuple[bool, List[str]]:
        """Check for uncommitted changes"""
        try:
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=SECV_HOME,
                capture_output=True,
                text=True,
                check=True
            )
            
            if result.stdout.strip():
                changed_files = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        file = line[3:].strip()
                        changed_files.append(file)
                return True, changed_files
            return False, []
        except:
            return False, []
    
    @staticmethod
    def stash_changes() -> bool:
        """Stash uncommitted changes"""
        try:
            print(f"{YELLOW}Stashing local changes...{NC}")
            result = subprocess.run(
                ['git', 'stash', 'push', '-m', f'SecV auto-stash {datetime.now().isoformat()}'],
                cwd=SECV_HOME,
                capture_output=True,
                text=True,
                check=True
            )
            Logger.log("Local changes stashed")
            print(f"{GREEN}{CHECK} Local changes stashed{NC}")
            return True
        except subprocess.CalledProcessError as e:
            Logger.log(f"Git stash failed: {e.stderr}", "ERROR")
            print(f"{RED}{CROSS} Failed to stash changes: {e.stderr}{NC}")
            return False
    
    @staticmethod
    def pop_stash() -> bool:
        """Pop the most recent stash"""
        try:
            print(f"{YELLOW}Restoring local changes...{NC}")
            result = subprocess.run(
                ['git', 'stash', 'pop'],
                cwd=SECV_HOME,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                Logger.log("Stashed changes restored successfully")
                print(f"{GREEN}{CHECK} Local changes restored{NC}")
                return True
            else:
                if "CONFLICT" in result.stdout or "CONFLICT" in result.stderr:
                    Logger.log("Merge conflicts after stash pop", "WARNING")
                    print(f"{YELLOW}{WARNING} Merge conflicts detected after restore{NC}")
                    print(f"{DIM}Your changes are preserved but need manual merge{NC}")
                    print(f"{DIM}Run 'git status' to see conflicts{NC}")
                return False
        except Exception as e:
            Logger.log(f"Git stash pop failed: {str(e)}", "ERROR")
            print(f"{YELLOW}{WARNING} Could not restore changes: {str(e)}{NC}")
            print(f"{DIM}Your changes are saved in git stash{NC}")
            print(f"{DIM}Run 'git stash list' to see stashed changes{NC}")
            return False
    
    @staticmethod
    def list_stashes() -> List[str]:
        """List all stashes"""
        try:
            result = subprocess.run(
                ['git', 'stash', 'list'],
                cwd=SECV_HOME,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        except:
            return []
    
    @staticmethod
    def discard_local_changes(files: List[str]) -> bool:
        """Discard local changes to specific files"""
        try:
            print(f"{YELLOW}Discarding local changes...{NC}")
            for file in files:
                subprocess.run(
                    ['git', 'checkout', '--', file],
                    cwd=SECV_HOME,
                    capture_output=True,
                    check=True
                )
            Logger.log(f"Discarded changes to {len(files)} files")
            print(f"{GREEN}{CHECK} Local changes discarded{NC}")
            return True
        except Exception as e:
            Logger.log(f"Git checkout failed: {str(e)}", "ERROR")
            return False
    
    @staticmethod
    def pull_with_rebase() -> Tuple[bool, str]:
        """Pull with rebase strategy"""
        try:
            result = subprocess.run(
                ['git', 'pull', '--rebase'],
                cwd=SECV_HOME,
                capture_output=True,
                text=True,
                check=True
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr


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
    def should_check_updates(force: bool = False) -> bool:
        """Determine if we should check for updates"""
        if force:
            return True
        
        if not LAST_CHECK_FILE.exists():
            return True
        
        try:
            with open(LAST_CHECK_FILE, 'r') as f:
                last_check_str = f.read().strip()
            
            last_check_dt = datetime.fromisoformat(last_check_str)
            next_check = last_check_dt + timedelta(hours=UPDATE_CHECK_INTERVAL)
            return datetime.now() >= next_check
        except:
            return True
    
    @staticmethod
    def mark_update_checked():
        """Mark that we've checked for updates"""
        LAST_CHECK_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LAST_CHECK_FILE, 'w') as f:
            f.write(datetime.now().isoformat())


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
            print(f"{GREEN}{CHECK} Backup created: {backup_path.name}{NC}")
            return backup_path
        except Exception as e:
            Logger.log(f"Backup failed: {str(e)}", "ERROR")
            print(f"{RED}{CROSS} Backup failed: {str(e)}{NC}")
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
                    
                    if dest.suffix == '' and dest.name in ['secV', 'install.sh']:
                        os.chmod(dest, 0o755)
            
            Logger.log(f"Restored backup: {backup_path}")
            print(f"{GREEN}{CHECK} Restored from backup: {backup_path.name}{NC}")
            return True
        except Exception as e:
            Logger.log(f"Restore failed: {str(e)}", "ERROR")
            print(f"{RED}{CROSS} Restore failed: {str(e)}{NC}")
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


class GoBinaryManager:
    """Manage Go binary compilation"""
    
    @staticmethod
    def check_go_available() -> bool:
        """Check if Go is available"""
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def compile_binary() -> bool:
        """Compile Go binary"""
        if not MAIN_GO.exists():
            print(f"{RED}{CROSS} main.go not found{NC}")
            return False
        
        if not GoBinaryManager.check_go_available():
            print(f"{RED}{CROSS} Go compiler not available{NC}")
            return False
        
        print(f"{YELLOW}[*] Compiling Go binary...{NC}")
        
        try:
            result = subprocess.run(
                ['go', 'build', '-ldflags=-s -w', '-o', 'secV', 'main.go'],
                cwd=SECV_HOME,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                os.chmod(SECV_BINARY, 0o755)
                
                size = SECV_BINARY.stat().st_size / 1024
                print(f"{GREEN}{CHECK} Binary compiled successfully ({size:.1f} KB){NC}")
                Logger.log(f"Go binary compiled: {size:.1f} KB")
                return True
            else:
                print(f"{RED}{CROSS} Compilation failed:{NC}")
                print(f"{DIM}{result.stderr}{NC}")
                Logger.log(f"Compilation failed: {result.stderr}", "ERROR")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{RED}{CROSS} Compilation timed out{NC}")
            return False
        except Exception as e:
            print(f"{RED}{CROSS} Compilation error: {str(e)}{NC}")
            return False
    
    @staticmethod
    def needs_recompilation(version_info: Dict) -> bool:
        """Check if binary needs recompilation"""
        if not SECV_BINARY.exists():
            return True
        
        if VersionManager.check_component_changed("main.go", MAIN_GO, version_info):
            return True
        
        return False


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
        print(f"{RED}{CROSS} Error: Command '{command[0]}' not found.{NC}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if check:
            print(f"{RED}{CROSS} Error executing command: {' '.join(command)}{NC}")
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
        run_command(['git', 'fetch'], capture=True)
        
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


def check_for_updates(force: bool = False, silent: bool = False) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if updates are available
    Returns: (has_update, current_version, new_version)
    """
    version_info = VersionManager.load_version_info()
    
    if not force and not VersionManager.should_check_updates():
        return False, version_info["current_version"], None
    
    if not silent:
        print(f"{YELLOW}Checking for updates...{NC}")
    
    if not check_git_repository():
        if not silent:
            print(f"{RED}{CROSS} Not a git repository. Cannot check for updates.{NC}")
        return False, version_info["current_version"], None
    
    try:
        run_command(['git', 'fetch'])
        
        status_result = run_command(['git', 'status', '-uno'])
        
        if "Your branch is up to date" in status_result.stdout:
            VersionManager.mark_update_checked()
            return False, version_info["current_version"], None
        
        elif "Your branch is behind" in status_result.stdout:
            remote_version = get_remote_version()
            current_version = version_info["current_version"]
            
            VersionManager.mark_update_checked()
            
            return True, current_version, remote_version
        
    except Exception as e:
        Logger.log(f"Update check failed: {str(e)}", "ERROR")
        if not silent:
            print(f"{RED}{CROSS} Failed to check for updates: {str(e)}{NC}")
    
    return False, version_info["current_version"], None


def install_dependencies() -> bool:
    """Install Python dependencies"""
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    
    if not requirements_path.exists():
        print(f"{RED}{CROSS} {REQUIREMENTS_FILE} not found!{NC}")
        return False
    
    print(f"\n{YELLOW}Installing/updating dependencies...{NC}")
    
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
                print(f"{GREEN}{CHECK} Dependencies installed successfully!{NC}")
                Logger.log("Dependencies installed successfully")
                return True
        except Exception:
            continue
    
    print(f"{YELLOW}{WARNING} Attempting installation with sudo...{NC}")
    sudo_command = ['sudo', sys.executable, '-m', 'pip', 'install', '--break-system-packages', '-r', str(requirements_path)]
    try:
        result = subprocess.run(sudo_command, check=False, capture_output=False, cwd=SECV_HOME)
        if result.returncode == 0:
            print(f"{GREEN}{CHECK} Dependencies installed with sudo!{NC}")
            Logger.log("Dependencies installed with sudo")
            return True
    except Exception:
        pass
    
    print(f"{RED}{CROSS} Failed to install dependencies{NC}")
    Logger.log("Dependency installation failed", "ERROR")
    return False


def perform_update(current_version: str, new_version: str) -> bool:
    """Perform the actual update"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Performing SecV Update                         ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    Logger.log(f"Starting update: {current_version} -> {new_version}")
    
    stashed_changes = False
    
    # Step 1: Create backup
    print(f"{YELLOW}[1/8] Creating backup...{NC}")
    critical_files = [
        SECV_BINARY,
        MAIN_GO,
        SECV_HOME / "install.sh",
        SECV_HOME / "update.py",
        SECV_HOME / "requirements.txt",
        CACHE_DIR / ".requirements_hash",
        VERSION_FILE
    ]
    
    backup_path = BackupManager.create_backup(critical_files)
    if not backup_path:
        print(f"{RED}{CROSS} Backup failed. Aborting update.{NC}")
        return False
    
    # Step 2: Handle local changes
    print(f"\n{YELLOW}[2/8] Checking for local changes...{NC}")
    has_changes, changed_files = GitManager.has_uncommitted_changes()
    
    if has_changes:
        print(f"{YELLOW}{WARNING} Found {len(changed_files)} modified file(s):{NC}")
        for file in changed_files[:5]:
            print(f"  {DIM}{BULLET} {file}{NC}")
        if len(changed_files) > 5:
            print(f"  {DIM}{BULLET} ... and {len(changed_files) - 5} more{NC}")
        
        print(f"\n{BOLD}Options:{NC}")
        print(f"  {GREEN}1{NC} - Stash changes (recommended - you can restore later)")
        print(f"  {YELLOW}2{NC} - Discard changes (⚠ permanent!)")
        print(f"  {RED}3{NC} - Cancel update")
        
        choice = input(f"\n{YELLOW}Choose option [1-3]: {NC}").strip()
        
        if choice == '1':
            if not GitManager.stash_changes():
                print(f"{RED}{CROSS} Failed to stash changes. Aborting.{NC}")
                return False
            stashed_changes = True
        elif choice == '2':
            confirm = input(f"{RED}Are you sure? This cannot be undone! [yes/NO]: {NC}").strip().lower()
            if confirm == 'yes':
                if not GitManager.discard_local_changes(changed_files):
                    print(f"{RED}{CROSS} Failed to discard changes. Aborting.{NC}")
                    return False
            else:
                print(f"{CYAN}Update cancelled{NC}")
                return False
        else:
            print(f"{CYAN}Update cancelled by user{NC}")
            return False
    else:
        print(f"{GREEN}{CHECK} No local changes detected{NC}")
    
    # Step 3: Pull updates
    print(f"\n{YELLOW}[3/8] Pulling latest changes...{NC}")
    try:
        result = run_command(['git', 'pull'], capture=False)
        print(f"{GREEN}{CHECK} Git pull successful{NC}")
        Logger.log("Git pull successful")
    except Exception as e:
        print(f"{RED}{CROSS} Git pull failed: {str(e)}{NC}")
        Logger.log(f"Git pull failed: {str(e)}", "ERROR")
        
        response = input(f"\n{YELLOW}Restore from backup? [Y/n]: {NC}").strip().lower()
        if not response or response == 'y':
            BackupManager.restore_backup(backup_path)
            if stashed_changes:
                GitManager.pop_stash()
        return False
    
    # Step 4: Restore stashed changes
    if stashed_changes:
        print(f"\n{YELLOW}[4/8] Restoring your changes...{NC}")
        GitManager.pop_stash()
    else:
        print(f"\n{YELLOW}[4/8] No changes to restore{NC}")
        print(f"{GREEN}{CHECK} Skipped{NC}")
    
    # Step 5: Clean obsolete files
    print(f"\n{YELLOW}[5/8] Cleaning obsolete files...{NC}")
    obsolete_files = ObsoleteFilesCleaner.find_obsolete_files(current_version, new_version)
    
    if obsolete_files:
        print(f"{DIM}Found {len(obsolete_files)} obsolete file(s){NC}")
        for file in obsolete_files:
            print(f"  {DIM}{BULLET} {file}{NC}")
        
        response = input(f"\n{YELLOW}Remove obsolete files? [Y/n]: {NC}").strip().lower()
        if not response or response == 'y':
            removed, failed = ObsoleteFilesCleaner.clean_obsolete_files(obsolete_files)
            print(f"{GREEN}{CHECK} Removed {removed} file(s){NC}")
            if failed > 0:
                print(f"{YELLOW}{WARNING} Failed to remove {failed} file(s){NC}")
    else:
        print(f"{GREEN}{CHECK} No obsolete files found{NC}")
    
    # Step 6: Recompile Go binary
    print(f"\n{YELLOW}[6/8] Recompiling Go binary...{NC}")
    
    version_info = VersionManager.load_version_info()
    
    if GoBinaryManager.needs_recompilation(version_info):
        print(f"{CYAN}main.go has changed, recompiling...{NC}")
        if not GoBinaryManager.compile_binary():
            print(f"{YELLOW}{WARNING} Binary compilation failed, but continuing...{NC}")
    else:
        print(f"{GREEN}{CHECK} Binary is up to date{NC}")
    
    # Step 7: Update dependencies
    print(f"\n{YELLOW}[7/8] Updating dependencies...{NC}")
    
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    old_hash = get_file_hash(requirements_path)
    
    stored_hash = version_info["components"].get("requirements.txt", {}).get("hash")
    
    if old_hash != stored_hash:
        print(f"{CYAN}requirements.txt has changed{NC}")
        if not install_dependencies():
            print(f"{YELLOW}{WARNING} Dependency update failed, but continuing...{NC}")
    else:
        print(f"{GREEN}{CHECK} No dependency changes{NC}")
    
    # Step 8: Update version info
    print(f"\n{YELLOW}[8/8] Updating version information...{NC}")
    
    version_info["current_version"] = new_version
    version_info["last_update"] = datetime.now().isoformat()
    version_info["go_compiled"] = SECV_BINARY.exists()
    
    # Update component hashes
    components = {
        "main.go": MAIN_GO,
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "dashboard.py": SECV_HOME / "dashboard.py",
        "requirements.txt": requirements_path,
        "secV": SECV_BINARY
    }
    
    for comp_name, comp_path in components.items():
        VersionManager.update_component_hash(comp_name, comp_path, version_info)
    
    VersionManager.save_version_info(version_info)
    print(f"{GREEN}{CHECK} Version info updated{NC}")
    
    # Cleanup
    print(f"\n{YELLOW}Cleaning up...{NC}")
    BackupManager.cleanup_old_backups(keep=5)
    Logger.cleanup_old_logs()
    print(f"{GREEN}{CHECK} Cleanup complete{NC}")
    
    Logger.log(f"Update completed successfully: {new_version}")
    return True


def show_update_summary(current_version: str, new_version: str):
    """Display update summary"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Update Available!                              ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    print(f"  {BOLD}Current Version:{NC} {RED}{current_version}{NC}")
    print(f"  {BOLD}New Version:{NC}     {GREEN}{new_version}{NC}")
    
    # Check for local changes
    has_changes, changed_files = GitManager.has_uncommitted_changes()
    if has_changes:
        print(f"\n  {YELLOW}{WARNING} You have {len(changed_files)} uncommitted change(s){NC}")
        print(f"  {DIM}These will be automatically stashed during update{NC}")
    
    obsolete_files = ObsoleteFilesCleaner.find_obsolete_files(current_version, new_version)
    if obsolete_files:
        print(f"\n  {YELLOW}{WARNING} Will clean {len(obsolete_files)} obsolete file(s){NC}")
    
    print(f"\n  {DIM}This update will:{NC}")
    print(f"    {BULLET} Create a backup of critical files")
    print(f"    {BULLET} Stash any local changes (can be restored)")
    print(f"    {BULLET} Pull latest changes from repository")
    print(f"    {BULLET} Recompile Go binary if main.go changed")
    print(f"    {BULLET} Clean obsolete files")
    print(f"    {BULLET} Update dependencies if needed")
    print()


def first_run_check(silent: bool = True) -> bool:
    """
    Check for updates on first run (called by Go loader)
    Returns: True if update was performed
    """
    Logger.log("First-run update check initiated")
    
    has_update, current_version, new_version = check_for_updates(force=False, silent=silent)
    
    if not has_update:
        if not silent:
            print(f"{GREEN}{CHECK} SecV is up to date ({current_version}){NC}")
        return False
    
    if not silent:
        print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{CYAN}║          Update Available - v{new_version}                         ║{NC}")
        print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        print(f"{YELLOW}An update is available for SecV.{NC}")
        print(f"Current: {RED}{current_version}{NC} → New: {GREEN}{new_version}{NC}\n")
        
        response = input(f"{YELLOW}Would you like to update now? [Y/n]: {NC}").strip().lower()
        if response and response != 'y':
            print(f"{CYAN}Update skipped. Run 'update' command later to update.{NC}")
            return False
    
    # Perform update
    success = perform_update(current_version, new_version or "unknown")
    
    if success:
        print(f"\n{BOLD}{GREEN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{GREEN}║              Update Complete! {CHECK} Please Restart SecV              ║{NC}")
        print(f"{BOLD}{GREEN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        print(f"{YELLOW}Please restart SecV to use the updated version.{NC}\n")
        sys.exit(2)
    
    return False


def main():
    """Main update process"""
    print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{CYAN}║                      SecV Update System v4.1                      ║{NC}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    Logger.log("Update check initiated")
    
    has_update, current_version, new_version = check_for_updates(force=True)
    
    if not has_update:
        print(f"{GREEN}{CHECK} You're already on the latest version!{NC}")
        print(f"  {BOLD}Current Version:{NC} {GREEN}{current_version}{NC}\n")
        
        version_info = VersionManager.load_version_info()
        last_check = version_info.get("last_check")
        if last_check:
            try:
                last_check_dt = datetime.fromisoformat(last_check)
                next_check = last_check_dt + timedelta(hours=UPDATE_CHECK_INTERVAL)
                print(f"{DIM}Next automatic check: {next_check.strftime('%Y-%m-%d %H:%M')}{NC}\n")
            except:
                pass
        
        sys.exit(0)
    
    show_update_summary(current_version, new_version or "unknown")
    
    response = input(f"{YELLOW}Do you want to update now? [Y/n]: {NC}").strip().lower()
    if response and response != 'y':
        print(f"{CYAN}Update cancelled by user.{NC}")
        Logger.log("Update cancelled by user")
        sys.exit(0)
    
    success = perform_update(current_version, new_version or "unknown")
    
    if success:
        print(f"\n{BOLD}{GREEN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{GREEN}║                    Update Complete! {CHECK}                             ║{NC}")
        print(f"{BOLD}{GREEN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        
        print(f"{BOLD}{GREEN}{CHECK} SecV has been updated successfully!{NC}\n")
        
        print(f"{BLUE}Next Steps:{NC}")
        print(f"  1. {YELLOW}Restart SecV{NC} to load updated components")
        print(f"  2. {YELLOW}Run 'reload'{NC} inside SecV to rescan modules")
        print(f"  3. {YELLOW}Type 'show modules'{NC} to see all available modules\n")
        
        backups = BackupManager.list_backups()
        if backups:
            print(f"{MAGENTA}{INFO} Backup available at: {backups[0].name}{NC}")
            print(f"{DIM}  Use 'python3 update.py --rollback' to restore if needed{NC}")
        
        stashes = GitManager.list_stashes()
        if stashes:
            print(f"\n{MAGENTA}{INFO} Your changes are stashed{NC}")
            print(f"{DIM}  Run 'git stash list' to see stashed changes{NC}")
            print(f"{DIM}  Run 'git stash pop' to restore them{NC}")
        
        print()
        sys.exit(2)
    else:
        print(f"\n{RED}{CROSS} Update failed. Check {UPDATE_LOG} for details.{NC}\n")
        Logger.log("Update failed", "ERROR")
        sys.exit(1)


def show_component_status():
    """Show status of all SecV components"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    SecV Component Status                          ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    version_info = VersionManager.load_version_info()
    
    print(f"  {BOLD}Current Version:{NC} {GREEN}{version_info['current_version']}{NC}")
    print(f"  {BOLD}Go Compiled:{NC} {GREEN if version_info.get('go_compiled') else YELLOW}{'Yes' if version_info.get('go_compiled') else 'No'}{NC}")
    
    last_update = version_info.get("last_update")
    if last_update:
        try:
            last_update_dt = datetime.fromisoformat(last_update)
            print(f"  {BOLD}Last Update:{NC} {last_update_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            pass
    
    # Check for uncommitted changes
    has_changes, changed_files = GitManager.has_uncommitted_changes()
    if has_changes:
        print(f"  {BOLD}Local Changes:{NC} {YELLOW}{len(changed_files)} file(s) modified{NC}")
    
    # Check for stashes
    stashes = GitManager.list_stashes()
    if stashes:
        print(f"  {BOLD}Git Stashes:{NC} {CYAN}{len(stashes)} stash(es) available{NC}")
    
    print(f"\n  {BOLD}Components:{NC}")
    print(f"  {DIM}{'─' * 65}{NC}")
    
    components_to_check = {
        "main.go": MAIN_GO,
        "secV": SECV_BINARY,
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "dashboard.py": SECV_HOME / "dashboard.py",
        "requirements.txt": SECV_HOME / REQUIREMENTS_FILE
    }
    
    for comp_name, comp_path in components_to_check.items():
        if comp_path.exists():
            comp_info = version_info["components"].get(comp_name, {})
            comp_version = comp_info.get("version", "unknown")
            comp_type = comp_info.get("type", "source")
            
            changed = VersionManager.check_component_changed(comp_name, comp_path, version_info)
            status = f"{YELLOW}[MODIFIED]{NC}" if changed else f"{GREEN}[OK]{NC}"
            
            type_label = f" ({comp_type})" if comp_type == "binary" else ""
            print(f"    {status} {BOLD}{comp_name:<20}{NC} v{comp_version}{type_label}")
        else:
            print(f"    {RED}[MISSING]{NC} {BOLD}{comp_name:<20}{NC} {DIM}not found{NC}")
    
    print()


def verify_installation():
    """Verify SecV installation integrity"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Verifying Installation                         ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    issues = []
    
    print(f"  {BOLD}Checking critical files...{NC}")
    critical_files = {
        "main.go": MAIN_GO,
        "secV (binary)": SECV_BINARY,
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "requirements.txt": SECV_HOME / REQUIREMENTS_FILE
    }
    
    for name, path in critical_files.items():
        if path.exists():
            if name == "secV (binary)":
                if os.access(path, os.X_OK):
                    print(f"    {GREEN}{CHECK}{NC} {name} (executable)")
                else:
                    print(f"    {YELLOW}{WARNING}{NC} {name} (not executable)")
                    issues.append(f"{name} not executable")
            else:
                print(f"    {GREEN}{CHECK}{NC} {name}")
        else:
            print(f"    {RED}{CROSS}{NC} {name} {DIM}(missing){NC}")
            issues.append(f"Missing critical file: {name}")
    
    print(f"\n  {BOLD}Checking directories...{NC}")
    critical_dirs = {
        "tools": SECV_HOME / "tools",
        ".cache": CACHE_DIR
    }
    
    for name, path in critical_dirs.items():
        if path.exists() and path.is_dir():
            print(f"    {GREEN}{CHECK}{NC} {name}/")
        else:
            print(f"    {YELLOW}{WARNING}{NC} {name}/ {DIM}(will be created){NC}")
            path.mkdir(parents=True, exist_ok=True)
    
    print(f"\n  {BOLD}Checking Python dependencies...{NC}")
    required_packages = ['cmd2', 'rich', 'argcomplete']
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"    {GREEN}{CHECK}{NC} {package}")
        except ImportError:
            print(f"    {RED}{CROSS}{NC} {package} {DIM}(not installed){NC}")
            issues.append(f"Missing Python package: {package}")
    
    print(f"\n  {BOLD}Checking Go installation...{NC}")
    if GoBinaryManager.check_go_available():
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, text=True)
            version = result.stdout.split()[2] if result.returncode == 0 else "unknown"
            print(f"    {GREEN}{CHECK}{NC} Go compiler ({version})")
        except:
            print(f"    {GREEN}{CHECK}{NC} Go compiler (available)")
    else:
        print(f"    {YELLOW}{WARNING}{NC} Go compiler not available")
        print(f"    {DIM}    Binary can't be recompiled without Go{NC}")
    
    print(f"\n  {BOLD}Checking git repository...{NC}")
    if check_git_repository():
        print(f"    {GREEN}{CHECK}{NC} Git repository initialized")
        
        try:
            result = run_command(['git', 'remote', '-v'], check=False)
            if result.returncode == 0 and result.stdout:
                print(f"    {GREEN}{CHECK}{NC} Remote configured")
            else:
                print(f"    {YELLOW}{WARNING}{NC} No remote configured")
                issues.append("Git remote not configured")
        except:
            pass
    else:
        print(f"    {RED}{CROSS}{NC} Not a git repository")
        issues.append("Not a git repository - updates disabled")
    
    print(f"\n  {BOLD}{'─' * 65}{NC}")
    
    if issues:
        print(f"\n  {YELLOW}{WARNING} Found {len(issues)} issue(s):{NC}")
        for issue in issues:
            print(f"    {BULLET} {issue}")
        print(f"\n  {DIM}Run './install.sh' to fix installation issues{NC}\n")
        return False
    else:
        print(f"\n  {GREEN}{CHECK} Installation verified - all checks passed!{NC}\n")
        return True


def repair_installation():
    """Attempt to repair common installation issues"""
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Repairing Installation                         ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    repaired = []
    failed = []
    
    print(f"{YELLOW}[1/4] Creating missing directories...{NC}")
    critical_dirs = [CACHE_DIR, SECV_HOME / "tools", BACKUP_DIR]
    for dir_path in critical_dirs:
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
            repaired.append(f"Created directory: {dir_path.name}")
        except Exception as e:
            failed.append(f"Failed to create {dir_path.name}: {str(e)}")
    
    if repaired:
        print(f"{GREEN}{CHECK} Created {len(repaired)} directories{NC}")
    
    print(f"\n{YELLOW}[2/4] Checking version information...{NC}")
    version_info = VersionManager.load_version_info()
    
    components = {
        "main.go": MAIN_GO,
        "secV": SECV_BINARY,
        "install.sh": SECV_HOME / "install.sh",
        "update.py": SECV_HOME / "update.py",
        "dashboard.py": SECV_HOME / "dashboard.py",
        "requirements.txt": SECV_HOME / REQUIREMENTS_FILE
    }
    
    for comp_name, comp_path in components.items():
        if comp_path.exists():
            VersionManager.update_component_hash(comp_name, comp_path, version_info)
    
    version_info["go_compiled"] = SECV_BINARY.exists() and os.access(SECV_BINARY, os.X_OK)
    VersionManager.save_version_info(version_info)
    repaired.append("Updated version information")
    print(f"{GREEN}{CHECK} Version info updated{NC}")
    
    print(f"\n{YELLOW}[3/4] Checking file permissions...{NC}")
    executable_files = [SECV_BINARY, SECV_HOME / "install.sh"]
    
    for file in executable_files:
        if file.exists():
            try:
                os.chmod(file, 0o755)
                repaired.append(f"Fixed permissions: {file.name}")
            except Exception as e:
                failed.append(f"Failed to fix permissions on {file.name}: {str(e)}")
    
    print(f"{GREEN}{CHECK} Permissions checked{NC}")
    
    print(f"\n{YELLOW}[4/4] Checking Go binary...{NC}")
    if MAIN_GO.exists() and not SECV_BINARY.exists():
        print(f"{CYAN}Binary missing, attempting compilation...{NC}")
        if GoBinaryManager.compile_binary():
            repaired.append("Compiled Go binary")
        else:
            failed.append("Failed to compile Go binary")
    elif SECV_BINARY.exists() and not os.access(SECV_BINARY, os.X_OK):
        print(f"{CYAN}Binary exists but not executable, fixing...{NC}")
        try:
            os.chmod(SECV_BINARY, 0o755)
            repaired.append("Made binary executable")
            print(f"{GREEN}{CHECK} Binary is now executable{NC}")
        except Exception as e:
            failed.append(f"Failed to make binary executable: {str(e)}")
    else:
        print(f"{GREEN}{CHECK} Binary OK{NC}")
    
    print(f"\n{BOLD}{'─' * 67}{NC}")
    print(f"\n{BOLD}Repair Summary:{NC}")
    print(f"  {GREEN}{CHECK} Repaired: {len(repaired)}{NC}")
    if failed:
        print(f"  {RED}{CROSS} Failed: {len(failed)}{NC}")
    
    if repaired:
        print(f"\n{DIM}Repaired items:{NC}")
        for item in repaired[:5]:
            print(f"    {BULLET} {item}")
    
    if failed:
        print(f"\n{YELLOW}Failed items:{NC}")
        for item in failed:
            print(f"    {BULLET} {item}")
    
    print()
    
    return len(failed) == 0


def handle_rollback():
    """Handle rollback operation"""
    backups = BackupManager.list_backups()
    
    if not backups:
        print(f"{YELLOW}{WARNING} No backups available{NC}")
        return
    
    print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{CYAN}║                    Available Backups                              ║{NC}")
    print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    for i, backup in enumerate(backups, 1):
        backup_time = datetime.strptime(backup.name, "%Y%m%d_%H%M%S")
        print(f"  {i}. {backup.name} ({backup_time.strftime('%Y-%m-%d %H:%M:%S')})")
    
    print()
    try:
        choice = input(f"{YELLOW}Select backup to restore (1-{len(backups)}) or 'q' to quit: {NC}").strip()
        
        if choice.lower() == 'q':
            print(f"{CYAN}Rollback cancelled{NC}")
            return
        
        idx = int(choice) - 1
        if 0 <= idx < len(backups):
            backup_path = backups[idx]
            print(f"\n{YELLOW}Restoring backup: {backup_path.name}{NC}")
            
            confirm = input(f"{RED}This will overwrite current files. Continue? [y/N]: {NC}").strip().lower()
            if confirm == 'y':
                if BackupManager.restore_backup(backup_path):
                    print(f"\n{GREEN}{CHECK} Rollback successful!{NC}")
                    print(f"{YELLOW}Please restart SecV to use the restored version.{NC}\n")
                else:
                    print(f"\n{RED}{CROSS} Rollback failed{NC}\n")
            else:
                print(f"{CYAN}Rollback cancelled{NC}")
        else:
            print(f"{RED}{CROSS} Invalid selection{NC}")
    except (ValueError, KeyboardInterrupt):
        print(f"\n{CYAN}Rollback cancelled{NC}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SecV Update System v4.1 - Enhanced Git Conflict Resolution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 update.py                    # Check and install updates
  python3 update.py --force            # Force update check
  python3 update.py --first-run        # First-run check (silent)
  python3 update.py --status           # Show component status
  python3 update.py --verify           # Verify installation
  python3 update.py --repair           # Repair installation
  python3 update.py --rollback         # Rollback to backup
  python3 update.py --list-backups     # List available backups
  python3 update.py --list-stashes     # List git stashes
        """
    )
    
    parser.add_argument('--first-run', action='store_true',
                       help='First-run update check (called by Go loader)')
    parser.add_argument('--rollback', action='store_true',
                       help='Rollback to previous backup')
    parser.add_argument('--list-backups', action='store_true',
                       help='List available backups')
    parser.add_argument('--list-stashes', action='store_true',
                       help='List git stashes')
    parser.add_argument('--force', action='store_true',
                       help='Force update check (ignore interval)')
    parser.add_argument('--status', action='store_true',
                       help='Show component status')
    parser.add_argument('--verify', action='store_true',
                       help='Verify installation integrity')
    parser.add_argument('--repair', action='store_true',
                       help='Repair common installation issues')
    
    args = parser.parse_args()
    
    try:
        if args.first_run:
            first_run_check(silent=True)
        elif args.status:
            show_component_status()
        elif args.verify:
            verify_installation()
        elif args.repair:
            repair_installation()
        elif args.rollback:
            handle_rollback()
        elif args.list_backups:
            backups = BackupManager.list_backups()
            if backups:
                print(f"\n{BOLD}Available Backups:{NC}")
                for backup in backups:
                    backup_time = datetime.strptime(backup.name, "%Y%m%d_%H%M%S")
                    print(f"  {BULLET} {backup.name} ({backup_time.strftime('%Y-%m-%d %H:%M:%S')})")
                print()
            else:
                print(f"{YELLOW}{WARNING} No backups available{NC}")
        elif args.list_stashes:
            stashes = GitManager.list_stashes()
            if stashes:
                print(f"\n{BOLD}Git Stashes:{NC}")
                for stash in stashes:
                    print(f"  {BULLET} {stash}")
                print()
            else:
                print(f"{YELLOW}{WARNING} No stashes available{NC}")
        else:
            main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Operation cancelled by user{NC}\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}{CROSS} Unexpected error: {str(e)}{NC}\n")
        Logger.log(f"Unexpected error: {str(e)}", "ERROR")
        sys.exit(1)
