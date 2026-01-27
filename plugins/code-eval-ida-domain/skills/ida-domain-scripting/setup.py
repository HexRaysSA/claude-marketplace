#!/usr/bin/env python3
"""
IDA Domain Skill Setup Script

This script validates the environment and installs dependencies required for
the IDA Domain scripting skill. Run this before using the skill for the first time.

Usage:
    uv run python setup.py [--ref <git-ref>]

Steps performed:
    1. Check that uv package manager is installed
    2. Clone or update ida-domain repository from GitHub
    3. Run uv sync to install dependencies (ida-domain)
    4. Verify IDADIR environment variable is set and valid
    5. Run a validation test to confirm IDA Domain works

Exit codes:
    0 - Success, setup complete
    1 - Error occurred (check output for details)
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Optional


# ANSI color codes for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_step(step_num: int, message: str) -> None:
    """Print a numbered step header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[{step_num}/5]{Colors.RESET} {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"  {Colors.YELLOW}!{Colors.RESET} {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"  {Colors.GREEN}✓{Colors.RESET} {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"  {Colors.RED}✗{Colors.RESET} {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"  {Colors.YELLOW}→{Colors.RESET} {message}")


def get_skill_dir() -> Path:
    """Get the directory containing this setup script."""
    return Path(__file__).parent.resolve()


def check_uv() -> bool:
    """
    Step 1: Check that uv package manager is installed.

    Returns:
        True if uv is available, False otherwise.
    """
    print_step(1, "Checking for uv package manager...")

    try:
        result = subprocess.run(
            ["uv", "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        version = result.stdout.strip()
        print_success(f"uv is installed ({version})")
        return True
    except FileNotFoundError:
        print_error("uv is not installed")
        print()
        print("  Please install uv using one of these methods:")
        print()
        print(f"  {Colors.BOLD}macOS/Linux:{Colors.RESET}")
        print("    curl -LsSf https://astral.sh/uv/install.sh | sh")
        print()
        print(f"  {Colors.BOLD}Windows:{Colors.RESET}")
        print("    powershell -c \"irm https://astral.sh/uv/install.ps1 | iex\"")
        print()
        print(f"  {Colors.BOLD}pip:{Colors.RESET}")
        print("    pip install uv")
        print()
        print("  For more options, see: https://docs.astral.sh/uv/getting-started/installation/")
        return False
    except subprocess.CalledProcessError as e:
        print_error(f"uv check failed: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        print_error("uv version check timed out after 30 seconds")
        return False


def get_latest_release_tag() -> Optional[str]:
    """Fetch the latest release tag from GitHub API."""
    url = "https://api.github.com/repos/HexRaysSA/ida-domain/releases/latest"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = json.loads(response.read())
            return data.get("tag_name")
    except Exception as e:
        print_warning(f"Could not fetch latest release: {e}")
        return None


def clone_or_update_ida_domain(ref: Optional[str] = None) -> bool:
    """
    Step 2: Clone or update ida-domain repository.

    Args:
        ref: Git ref (branch, tag, or commit). If None, uses latest release tag.

    Returns:
        True if successful, False otherwise.
    """
    skill_dir = get_skill_dir()
    ida_domain_dir = skill_dir / "ida-domain"
    repo_url = "https://github.com/HexRaysSA/ida-domain.git"

    # Determine which ref to use
    if ref is None:
        print_info("Fetching latest release tag from GitHub...")
        ref = get_latest_release_tag()
        if ref is None:
            print_warning("Could not determine latest release, falling back to 'main'")
            ref = "main"
        else:
            print_info(f"Latest release: {ref}")

    if ida_domain_dir.exists():
        # Update existing clone
        print_step(2, f"Updating ida-domain repository (ref: {ref})...")
        try:
            subprocess.run(
                ["git", "fetch", "--all", "--tags"],
                cwd=ida_domain_dir,
                check=True,
                capture_output=True,
                timeout=120,
            )
            subprocess.run(
                ["git", "checkout", ref],
                cwd=ida_domain_dir,
                check=True,
                capture_output=True,
                timeout=30,
            )
            # If it's a branch, pull latest
            result = subprocess.run(
                ["git", "symbolic-ref", "HEAD"],
                cwd=ida_domain_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:  # It's a branch
                subprocess.run(
                    ["git", "pull"],
                    cwd=ida_domain_dir,
                    check=True,
                    capture_output=True,
                    timeout=120,
                )
            print_success(f"ida-domain updated to {ref}")
            return True
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to update ida-domain: {e.stderr or e.stdout}")
            return False
    else:
        # Fresh clone
        print_step(2, f"Cloning ida-domain repository (ref: {ref})...")
        try:
            subprocess.run(
                ["git", "clone", repo_url, str(ida_domain_dir)],
                check=True,
                capture_output=True,
                timeout=300,
            )
            subprocess.run(
                ["git", "checkout", ref],
                cwd=ida_domain_dir,
                check=True,
                capture_output=True,
                timeout=30,
            )
            print_success(f"ida-domain cloned at {ref}")
            return True
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to clone ida-domain: {e.stderr or e.stdout}")
            return False


def run_uv_sync() -> bool:
    """
    Step 3: Run uv sync and install ida-domain as editable package.

    Returns:
        True if sync succeeds, False otherwise.
    """
    print_step(3, "Installing dependencies with uv sync...")

    skill_dir = get_skill_dir()
    ida_domain_dir = skill_dir / "ida-domain"

    try:
        # First, run uv sync for base dependencies
        result = subprocess.run(
            ["uv", "sync"],
            cwd=skill_dir,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )

        # Then install ida-domain as editable package
        print_info("Installing ida-domain as editable package...")
        result = subprocess.run(
            ["uv", "pip", "install", "-e", str(ida_domain_dir)],
            cwd=skill_dir,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
        print_success("Dependencies installed successfully")

        return True
    except subprocess.CalledProcessError as e:
        print_error("uv sync failed")
        print()
        print("  Error output:")
        for line in (e.stderr or e.stdout or "Unknown error").strip().split("\n"):
            print(f"    {line}")
        print()
        print("  Possible fixes:")
        print("    - Ensure pyproject.toml exists and is valid")
        print("    - Check your internet connection")
        print("    - Try running: uv cache clean")
        return False
    except subprocess.TimeoutExpired:
        print_error("uv sync timed out after 5 minutes")
        print()
        print("  Possible causes:")
        print("    - Slow network connection")
        print("    - Large dependencies to download")
        print("    - Try running manually: uv sync")
        return False
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        return False


def check_idadir() -> bool:
    """
    Step 4: Verify IDADIR environment variable is set and points to valid IDA installation.

    Returns:
        True if IDADIR is valid, False otherwise.
    """
    print_step(4, "Checking IDADIR environment variable...")

    idadir = os.environ.get("IDADIR")

    if not idadir:
        print_error("IDADIR environment variable is not set")
        print()
        print("  IDADIR must point to your IDA Pro installation directory.")
        print()
        print("  Set it in your shell configuration:")
        print()
        print(f"  {Colors.BOLD}bash/zsh:{Colors.RESET}")
        print("    export IDADIR=\"/path/to/ida\"")
        print()
        print(f"  {Colors.BOLD}fish:{Colors.RESET}")
        print("    set -gx IDADIR \"/path/to/ida\"")
        print()
        print(f"  {Colors.BOLD}Windows:{Colors.RESET}")
        print("    set IDADIR=C:\\path\\to\\ida")
        print()
        print("  Common IDA locations:")
        print("    - macOS: /Applications/IDA Professional 9.1.app/Contents/MacOS")
        print("    - Linux: /opt/idapro-9.1")
        print("    - Windows: C:\\Program Files\\IDA Professional 9.1")
        return False

    ida_path = Path(idadir)

    if not ida_path.exists():
        print_error(f"IDADIR path does not exist: {idadir}")
        print()
        print("  Please verify the path and update IDADIR accordingly.")
        return False

    if not ida_path.is_dir():
        print_error(f"IDADIR is not a directory: {idadir}")
        print()
        print("  IDADIR should point to the IDA installation directory,")
        print("  not an executable file.")
        return False

    # Check for common IDA files to verify it's a valid installation
    ida_indicators = [
        "idat64",      # Linux/macOS headless IDA 64-bit
        "idat64.exe",  # Windows headless IDA 64-bit
        "idat",        # Linux/macOS headless IDA 32-bit
        "idat.exe",    # Windows headless IDA 32-bit
        "ida64",       # Linux/macOS GUI IDA 64-bit
        "ida64.exe",   # Windows GUI IDA 64-bit
        "libida64.so", # Linux shared library
        "libida64.dylib",  # macOS shared library
        "ida64.dll",   # Windows DLL
    ]

    found_indicators = [f for f in ida_indicators if (ida_path / f).exists()]

    if not found_indicators:
        print_error(f"IDADIR does not appear to contain IDA Pro: {idadir}")
        print()
        print("  Expected to find one of:")
        for indicator in ida_indicators[:6]:  # Show first few
            print(f"    - {indicator}")
        print()
        print("  Please verify IDADIR points to the correct IDA installation directory.")
        return False

    print_success(f"IDADIR is set: {idadir}")
    print_info(f"Found IDA files: {', '.join(found_indicators[:3])}")

    return True


def run_validation_test() -> bool:
    """
    Step 5: Run a minimal script to verify IDA Domain can load.

    Returns:
        True if validation succeeds, False otherwise.
    """
    print_step(5, "Running IDA Domain validation test...")

    skill_dir = get_skill_dir()

    # Minimal test script to verify ida_domain imports correctly
    test_script = """
import sys
try:
    import ida_domain
    print(f"ida_domain version: {ida_domain.__version__}")
    print("SUCCESS: IDA Domain loaded correctly")
    sys.exit(0)
except ImportError as e:
    print(f"IMPORT_ERROR: {e}")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
"""

    try:
        result = subprocess.run(
            ["uv", "run", "python", "-c", test_script],
            cwd=skill_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = result.stdout.strip()
        error_output = result.stderr.strip()

        if result.returncode == 0 and "SUCCESS" in output:
            # Extract version info
            for line in output.split("\n"):
                if "ida_domain version" in line:
                    print_success(line.strip())
                    break
            else:
                print_success("IDA Domain loaded successfully")
            return True
        else:
            print_error("IDA Domain validation failed")
            print()

            if "IMPORT_ERROR" in output:
                print("  Import error:")
                for line in output.split("\n"):
                    if "IMPORT_ERROR" in line:
                        print(f"    {line.replace('IMPORT_ERROR: ', '')}")
            elif output:
                print("  Output:")
                for line in output.split("\n"):
                    print(f"    {line}")

            if error_output:
                print("  Stderr:")
                for line in error_output.split("\n"):
                    print(f"    {line}")

            print()
            print("  Possible fixes:")
            print("    - Verify IDADIR is set correctly")
            print("    - Ensure IDA Pro 9.1+ is installed")
            print("    - Try re-running: uv sync --reinstall")
            print("    - Check IDA Domain docs: https://ida-domain.docs.hex-rays.com/")
            return False

    except subprocess.TimeoutExpired:
        print_error("Validation test timed out after 60 seconds")
        print()
        print("  The import test took too long to complete.")
        print("  This may indicate a problem with the IDA Domain installation.")
        return False
    except Exception as e:
        print_error(f"Validation test failed: {e}")
        return False


def main() -> int:
    """
    Run all setup steps in order.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    parser = argparse.ArgumentParser(
        description="Setup IDA Domain scripting skill environment"
    )
    parser.add_argument(
        "--ref",
        type=str,
        default=None,
        help="Git ref (branch, tag, or commit) for ida-domain. Default: latest release tag",
    )
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}IDA Domain Skill Setup{Colors.RESET}")
    print("=" * 50)

    # Step 1: Check uv
    if not check_uv():
        return 1

    # Step 2: Clone/update ida-domain
    if not clone_or_update_ida_domain(args.ref):
        return 1

    # Step 3: Run uv sync
    if not run_uv_sync():
        return 1

    # Step 4: Check IDADIR
    if not check_idadir():
        return 1

    # Step 5: Validation test
    if not run_validation_test():
        return 1

    # All steps passed
    print()
    print("=" * 50)
    print(f"{Colors.GREEN}{Colors.BOLD}Setup complete! Ready to use.{Colors.RESET}")
    print()
    print("Next steps:")
    print("  - Write scripts to /tmp/ida-domain-*.py")
    print("  - Execute with: uv run python run.py /tmp/script.py -f <binary>")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
