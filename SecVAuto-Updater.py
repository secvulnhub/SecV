#!/usr/bin/env python3
"""
SecV Git-Based Updater
Version: 2.1.0

Updates the project by running 'git pull' and handles Python dependencies.
This script must be run from the root of the Git repository.
"""

import os
import sys
import subprocess
from pathlib import Path

# --- Configuration ---
REQUIREMENTS_FILE = "requirements.txt"
SECV_HOME = Path(__file__).parent.absolute()

# --- Colors for better output ---
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'

def run_command(command: list, capture: bool = True):
    """A helper function to run shell commands."""
    try:
        return subprocess.run(
            command,
            capture_output=capture,
            text=True,
            check=True,
            cwd=SECV_HOME
        )
    except FileNotFoundError:
        print(f"{RED}✗ Error: Command '{command[0]}' not found. Is it installed and in your PATH?{NC}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"{RED}✗ Error executing command: {' '.join(command)}{NC}")
        print(f"{RED}{e.stderr}{NC}")
        sys.exit(1)

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

def get_file_hash(filepath: Path) -> str | None:
    """Gets the Git hash of a file. Returns None if it doesn't exist."""
    if not filepath.exists():
        return None
    result = run_command(['git', 'hash-object', str(filepath)])
    return result.stdout.strip()

def main():
    """Main update process."""
    print(f"\n{CYAN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{CYAN}║                      SecV Git Updater                             ║{NC}")
    print(f"{CYAN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")

    # --- Initial Sanity Checks ---
    if not (SECV_HOME / '.git').is_dir():
        print(f"{RED}✗ Error: This is not a Git repository. This script can only update projects cloned with 'git clone'.{NC}")
        sys.exit(1)

    if not check_for_updates():
        sys.exit(0)

    # --- User Confirmation ---
    response = input(f"\n{YELLOW}Do you want to pull the latest changes? [Y/n]: {NC}").strip().lower()
    if response and response != 'y':
        print(f"{CYAN}Update cancelled by user.{NC}")
        sys.exit(0)

    # --- The Update Process ---
    requirements_path = SECV_HOME / REQUIREMENTS_FILE
    old_req_hash = get_file_hash(requirements_path)

    print(f"\n{YELLOW}Pulling latest updates from the repository...{NC}")
    run_command(['git', 'pull'], capture=False) # stream output directly
    print(f"{GREEN}✓ Project files updated successfully.{NC}")

    new_req_hash = get_file_hash(requirements_path)

    # --- Dependency Management ---
    if old_req_hash != new_req_hash:
        print(f"\n{YELLOW}{REQUIREMENTS_FILE} has changed. Updating dependencies...{NC}")
        pip_command = [
            sys.executable, '-m', 'pip', 'install',
            '--upgrade',
            '-r', str(requirements_path),
            '--break-system-packages' # As requested for system-level installs
        ]
        print(f"{CYAN}Running: {' '.join(pip_command)}{NC}")
        try:
            # We run this without capture to show pip's progress live
            subprocess.run(pip_command, check=True, cwd=SECV_HOME)
            print(f"{GREEN}✓ Dependencies updated successfully!{NC}")
        except subprocess.CalledProcessError:
            print(f"{RED}✗ An error occurred while updating dependencies.{NC}")
    else:
        print(f"\n{GREEN}✓ No changes to dependencies were detected.{NC}")

    print(f"\n{GREEN}╔═══════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{GREEN}║                         Update Complete!                          ║{NC}")
    print(f"{GREEN}╚═══════════════════════════════════════════════════════════════════╝{NC}\n")
    print(f"{YELLOW}Please restart SecV to apply the changes.{NC}\n")


if __name__ == '__main__':
    main()
