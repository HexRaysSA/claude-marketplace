#!/usr/bin/env python3
"""
IDA Plugin Skill - Package Script

Packages a plugin directory into an HCLI-compatible ZIP archive,
runs lint validation, and optionally installs the plugin.
"""

import argparse
import json
import subprocess
import sys
import zipfile
from pathlib import Path


def validate_plugin_dir(plugin_dir: Path) -> bool:
    """Validate that the plugin directory has required files."""
    manifest = plugin_dir / "ida-plugin.json"

    if not manifest.exists():
        print(f"ERROR: ida-plugin.json not found in {plugin_dir}")
        return False

    # Parse and validate manifest
    try:
        with open(manifest) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in ida-plugin.json: {e}")
        return False

    # Check required fields
    required = ["IDAMetadataDescriptorVersion", "plugin"]
    for field in required:
        if field not in data:
            print(f"ERROR: Missing required field: {field}")
            return False

    plugin_data = data.get("plugin", {})
    plugin_required = ["name", "version", "entryPoint", "authors", "urls"]
    for field in plugin_required:
        if field not in plugin_data:
            print(f"ERROR: Missing required plugin field: {field}")
            return False

    # Check entry point exists
    entry_point = plugin_data.get("entryPoint", "")
    entry_path = plugin_dir / entry_point
    if not entry_path.exists():
        print(f"ERROR: Entry point not found: {entry_point}")
        return False

    return True


def create_zip(plugin_dir: Path, output_path: Path) -> bool:
    """Create a ZIP archive from the plugin directory."""
    try:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in plugin_dir.rglob('*'):
                if file_path.is_file():
                    # Skip common unwanted files
                    if file_path.name.startswith('.') or file_path.suffix == '.pyc':
                        continue
                    if '__pycache__' in str(file_path):
                        continue

                    arcname = file_path.relative_to(plugin_dir)
                    zf.write(file_path, arcname)
        return True
    except Exception as e:
        print(f"ERROR: Failed to create ZIP: {e}")
        return False


def run_lint(zip_path: Path) -> bool:
    """Run hcli plugin lint on the ZIP archive."""
    try:
        result = subprocess.run(
            ["uv", "run", "--with=ida-hcli", "hcli", "plugin", "lint", str(zip_path)],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)

        return result.returncode == 0
    except FileNotFoundError:
        print("ERROR: hcli not found. Run setup.py first.")
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: hcli lint timed out")
        return False


def install_plugin(zip_path: Path) -> bool:
    """Install the plugin using hcli."""
    try:
        result = subprocess.run(
            ["uv", "run", "--with=ida-hcli", "hcli", "plugin", "install", str(zip_path)],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)

        return result.returncode == 0
    except FileNotFoundError:
        print("ERROR: hcli not found. Run setup.py first.")
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: hcli install timed out")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Package an IDA plugin for distribution"
    )
    parser.add_argument(
        "plugin_dir",
        type=Path,
        help="Path to the plugin directory"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output ZIP path (default: <plugin_name>.zip in current directory)"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install the plugin after packaging"
    )
    parser.add_argument(
        "--no-lint",
        action="store_true",
        help="Skip lint validation"
    )

    args = parser.parse_args()

    plugin_dir = args.plugin_dir.resolve()

    if not plugin_dir.is_dir():
        print(f"ERROR: Not a directory: {plugin_dir}")
        return 1

    print("IDA Plugin Packager")
    print("=" * 40)
    print()

    # Validate
    print(f"Validating: {plugin_dir}")
    if not validate_plugin_dir(plugin_dir):
        return 1
    print("  Validation passed")
    print()

    # Determine output path
    if args.output:
        output_path = args.output.resolve()
    else:
        # Get plugin name from manifest
        with open(plugin_dir / "ida-plugin.json") as f:
            data = json.load(f)
        plugin_name = data["plugin"]["name"]
        output_path = Path.cwd() / f"{plugin_name}.zip"

    # Create ZIP
    print(f"Creating: {output_path}")
    if not create_zip(plugin_dir, output_path):
        return 1
    print("  ZIP created")
    print()

    # Lint
    if not args.no_lint:
        print("Running hcli plugin lint...")
        if not run_lint(output_path):
            print("  Lint FAILED")
            return 1
        print("  Lint passed")
        print()

    # Install
    if args.install:
        print("Installing plugin...")
        if not install_plugin(output_path):
            print("  Install FAILED")
            return 1
        print("  Install successful")
        print()

    print("Done!")
    print(f"Plugin archive: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
