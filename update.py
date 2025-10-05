#!/usr/bin/env python3
"""
SecV Git-Based Updater v2.2
Enhanced with automatic requirements.txt management

Updates the project by running 'git pull' and intelligently handles Python dependencies.
Automatically installs new dependencies added to requirements.txt by contributors.
This script must be run from the root of the Git repository.
"""

import os
import sys
import subprocess
import hashlib
from pathlib import Path

# --- Configuration ---
REQUIREMENTS_FILE = "requirements.txt"
SECV_HOME = Path(__file__).parent.absolute()
REQUIREMENTS_HASH_FILE = SECV_HOME / ".cache" / ".requirements_hash"

# --- Colors for better output ---
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
BOLD = '\033[1m'
NC = '\033[0m'

def run_command(command: list, capture: bool = True, check: bool = True):
    """A helper function to run shell commands."""
    try:
        return subprocess.run(
            command,
            capture_output=capture,
            text=True,
            check=check,
            cwd=SECV_HOME
        )
    except FileNotFoundError:
        print(f"{RED}✗ Error: Command '{command[0]}' not found. Is it installed and in your PATH?{NC}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if check:
            print(f"{RED}✗ Error executing command: {' '.join(command)}{NC}")
            if e.stderr:
                print(f"{RED}{e.stderr}{NC}")
            sys.exit(1)
        return e

def get_file_hash(filepath: Path) -> str | None:
    """Calculate SHA256 hash of a file. Returns None if it doesn't exist."""
    if not filepath.exists():
        return None
    
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_stored_hash() -> str | None:
    """Get the stored hash of requirements.txt from last update."""
    if not REQUIREMENTS_HASH_FILE.exists():
        return None
    
    try:
        return REQUIREMENTS_HASH_FILE.read_text().strip()
    except:
        return None

def store_hash(hash_value: str):
    """Store the hash of requirements.txt."""
    REQUIREMENTS_HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    REQUIREMENTS_HASH_FILE.write_text(hash_value)

def check_for_updates() -> bool:
    """Checks if the local repository is behind the remote."""
    print(f"{YELLOW}Checking for updates...{NC}")

    # Fetch the latest changes from the remote without applying them
    run_command(['git', 'fetch'])

    # Check the status against the remote branch
    status_result = run_command(['git', 'status', '-uno'])
    if "Your branch is up to date" in status_result.stdout:
        print(f"{GREEN}✓ You're already on the latest version!{NC}")
        return False
    elif "Your branch is behind" in status_result.stdout:
        print(f"{GREEN}✓ An update is available!{NC}")
        return True
    else:
        print(f"{YELLOW}⚠ Could not determine update status. You may have local changes.{NC}")
        print(f"{YELLOW}It's recommended to commit or stash them before updating.{NC}")
        # Allow user to proceed with caution
        return True

def install_dependencies(install_all: bool = False):
    """Install Python dependencies with --break-system-packages flag."""
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    
    if not requirements_path.exists():
        print(f"{RED}✗ {REQUIREMENTS_FILE} not found!{NC}")
        return False
    
    # Read requirements file
    with open(requirements_path, 'r') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not requirements:
        print(f"{YELLOW}⚠ No dependencies found in {REQUIREMENTS_FILE}{NC}")
        return True
    
    print(f"\n{YELLOW}Installing dependencies...{NC}")
    
    # Try multiple installation strategies for maximum compatibility
    pip_commands = [
        # Try user install first
        [sys.executable, '-m', 'pip', 'install', '--user', '-r', str(requirements_path)],
        # Try user install with --break-system-packages
        [sys.executable, '-m', 'pip', 'install', '--user', '--break-system-packages', '-r', str(requirements_path)],
        # Try system install
        [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_path)],
        # Try system install with --break-system-packages
        [sys.executable, '-m', 'pip', 'install', '--break-system-packages', '-r', str(requirements_path)],
    ]
    
    for i, pip_command in enumerate(pip_commands):
        print(f"{CYAN}Attempt {i+1}: {' '.join(pip_command[3:])}...{NC}")
        try:
            result = subprocess.run(pip_command, check=False, capture_output=False, cwd=SECV_HOME)
            if result.returncode == 0:
                print(f"{GREEN}✓ Dependencies installed successfully!{NC}")
                return True
        except Exception as e:
            print(f"{YELLOW}⚠ Attempt {i+1} failed: {str(e)}{NC}")
            continue
    
    # Last resort: try with sudo
    print(f"{YELLOW}⚠ Attempting installation with sudo (requires password)...{NC}")
    sudo_command = ['sudo', sys.executable, '-m', 'pip', 'install', '--break-system-packages', '-r', str(requirements_path)]
    try:
        result = subprocess.run(sudo_command, check=False, capture_output=False, cwd=SECV_HOME)
        if result.returncode == 0:
            print(f"{GREEN}✓ Dependencies installed successfully with sudo!{NC}")
            return True
    except Exception as e:
        print(f"{RED}✗ Sudo installation failed: {str(e)}{NC}")
    
    print(f"{RED}✗ All installation attempts failed.{NC}")
    print(f"{YELLOW}Please try manual installation:${NC}")
    print(f"{CYAN}pip3 install -r {requirements_path} --break-system-packages{NC}")
    return False

def compare_requirements():
    """Compare old and new requirements.txt to show what changed."""
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    
    if not requirements_path.exists():
        return None, None
    
    # Get current requirements
    with open(requirements_path, 'r') as f:
        new_reqs = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    
    # Try to get old requirements from git
    try:
        result = run_command(['git', 'show', f'HEAD@{{1}}:{REQUIREMENTS_FILE}'], check=False)
        if result.returncode == 0:
            old_reqs = set(line.strip() for line in result.stdout.split('\n') if line.strip() and not line.startswith('#'))
            
            added = new_reqs - old_reqs
            removed = old_reqs - new_reqs
            
            return added, removed
    except:
        pass
    
    return None, None

def show_dependency_changes(added, removed):
    """Display what dependencies were added or removed."""
    if added or removed:
        print(f"\n{BOLD}{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{CYAN}║                   Dependency Changes Detected                     ║{NC}")
        print(f"{BOLD}{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
        
        if added:
            print(f"{GREEN}{BOLD}New Dependencies Added:{NC}")
            for dep in sorted(added):
                print(f"  {GREEN}+ {dep}{NC}")
        
        if removed:
            print(f"\n{RED}{BOLD}Dependencies Removed:{NC}")
            for dep in sorted(removed):
                print(f"  {RED}- {dep}{NC}")
        
        print()

def main():
    """Main update process."""
    print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{CYAN}║                      SecV Git Updater v2.2                        ║{NC}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")

    # --- Initial Sanity Checks ---
    if not (SECV_HOME / '.git').is_dir():
        print(f"{RED}✗ Error: This is not a Git repository.{NC}")
        print(f"{YELLOW}This script can only update projects cloned with 'git clone'.{NC}")
        print(f"\n{BLUE}To enable updates:{NC}")
        print(f"  {CYAN}cd {SECV_HOME}{NC}")
        print(f"  {CYAN}git init{NC}")
        print(f"  {CYAN}git remote add origin https://github.com/SecVulnHub/SecV.git{NC}")
        print(f"  {CYAN}git fetch{NC}")
        print(f"  {CYAN}git reset --hard origin/main{NC}\n")
        sys.exit(1)

    if not check_for_updates():
        # Even if no updates, check if requirements.txt needs updating
        requirements_path = SECV_HOME / REQUIREMENTS_FILE
        current_hash = get_file_hash(requirements_path)
        stored_hash = get_stored_hash()
        
        if current_hash != stored_hash and requirements_path.exists():
            print(f"\n{YELLOW}⚠ requirements.txt hash mismatch detected.{NC}")
            print(f"{YELLOW}Dependencies may need updating.{NC}")
            
            response = input(f"\n{YELLOW}Update dependencies? [Y/n]: {NC}").strip().lower()
            if not response or response == 'y':
                if install_dependencies():
                    store_hash(current_hash)
                    print(f"{GREEN}✓ Dependencies updated successfully!{NC}")
        
        sys.exit(0)

    # --- User Confirmation ---
    response = input(f"\n{YELLOW}Do you want to pull the latest changes? [Y/n]: {NC}").strip().lower()
    if response and response != 'y':
        print(f"{CYAN}Update cancelled by user.{NC}")
        sys.exit(0)

    # --- The Update Process ---
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    old_req_hash = get_file_hash(requirements_path)
    old_stored_hash = get_stored_hash()

    print(f"\n{YELLOW}Pulling latest updates from the repository...{NC}")
    run_command(['git', 'pull'], capture=False)
    print(f"{GREEN}✓ Project files updated successfully.{NC}")

    new_req_hash = get_file_hash(requirements_path)

    # --- Intelligent Dependency Management ---
    needs_dependency_update = False
    
    # Case 1: requirements.txt changed in this update
    if old_req_hash != new_req_hash:
        print(f"\n{BOLD}{YELLOW}⚙ {REQUIREMENTS_FILE} has changed in this update.{NC}")
        needs_dependency_update = True
        
        # Show what changed
        added, removed = compare_requirements()
        if added or removed:
            show_dependency_changes(added, removed)
    
    # Case 2: requirements.txt exists but we never installed it before
    elif new_req_hash and not old_stored_hash:
        print(f"\n{BOLD}{YELLOW}⚙ First time dependency installation detected.{NC}")
        needs_dependency_update = True
    
    # Case 3: Hash mismatch from stored value (manual changes or corruption)
    elif new_req_hash != old_stored_hash and old_stored_hash:
        print(f"\n{BOLD}{YELLOW}⚠ requirements.txt hash mismatch detected.{NC}")
        print(f"{YELLOW}Dependencies may have been manually modified.{NC}")
        needs_dependency_update = True
    
    if needs_dependency_update:
        print(f"\n{CYAN}═══════════════════════════════════════════════════════════════════{NC}")
        print(f"{CYAN}           Installing/Updating Python Dependencies...{NC}")
        print(f"{CYAN}═══════════════════════════════════════════════════════════════════{NC}\n")
        
        if install_dependencies():
            store_hash(new_req_hash)
            print(f"\n{GREEN}✓ All dependencies are up to date!{NC}")
        else:
            print(f"\n{RED}✗ Dependency installation encountered errors.{NC}")
            print(f"{YELLOW}⚠ SecV may not function correctly until dependencies are installed.{NC}")
    else:
        print(f"\n{GREEN}✓ No dependency changes detected.{NC}")
        # Update stored hash anyway to keep in sync
        if new_req_hash:
            store_hash(new_req_hash)

    # --- Module reload reminder ---
    print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{CYAN}║                         Update Complete!                          ║{NC}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    
    print(f"{BOLD}{GREEN}✓ SecV has been updated successfully!{NC}\n")
    
    print(f"{BLUE}Next Steps:{NC}")
    print(f"  1. {YELLOW}Restart SecV{NC} to load updated modules")
    print(f"  2. {YELLOW}Run 'reload'{NC} inside SecV to rescan modules")
    print(f"  3. {YELLOW}Type 'show modules'{NC} to see all available modules\n")
    
    # Check if there are new module directories
    tools_dir = SECV_HOME / "tools"
    if tools_dir.exists():
        # Count module.json files
        module_count = len(list(tools_dir.rglob("module.json")))
        print(f"{MAGENTA}ℹ Found {module_count} modules in tools directory{NC}")
        print(f"{MAGENTA}  Use 'reload' command in SecV to refresh module list{NC}\n")


if __name__ == '__main__':
    main()
