#!/usr/bin/env python3
"""
IDA Domain Universal Script Executor

Executes Python scripts that use IDA Domain with automatic boilerplate wrapping.
This is the main entry point for Claude-generated analysis scripts.

Input file caching:
    The executor uses a persistent cache directory (/tmp/ida-domain-cache/)
    to store input files and their IDA databases. The cache directory structure
    is based on the full path of the input file (with path separators replaced
    by underscores).

    Benefits:
    - Prevents IDA from creating artifact files in the original directory
    - Allows reuse of IDA databases from previous runs, avoiding reanalysis
    - Subsequent runs on the same binary are significantly faster

    When --save is used with an IDA database (.i64/.idb), the modified database
    is copied back to the original location.

Usage:
    # 1. Execute a script file
    uv run python run.py <work_dir>/script.py -f /path/to/binary.exe

    # 2. Execute inline code
    uv run python run.py -c "for f in db.functions: print(f.name)" -f binary.exe

Command-line flags:
    -f, --file      Target binary or .i64 file (required)
    -c, --code      Inline code string
    -s, --save      Enable save_on_close=True (default: False)
    --no-wrap       Skip auto-wrapping (for complete scripts)
    --timeout       Execution timeout in seconds (default: 1800, 0 for no timeout)

Exit codes:
    0 - Success
    1 - Error (setup, parsing, execution)
"""

import argparse
import glob
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# ANSI color codes for terminal output (consistent with setup.py)
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"{Colors.RED}Error:{Colors.RESET} {message}", file=sys.stderr)


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"{Colors.YELLOW}Warning:{Colors.RESET} {message}", file=sys.stderr)


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"{Colors.BLUE}Info:{Colors.RESET} {message}", file=sys.stderr)


def get_skill_dir() -> Path:
    """Get the directory containing this run script."""
    return Path(__file__).parent.resolve()


def check_venv_exists() -> bool:
    """
    Check if the virtual environment exists.

    Returns:
        True if .venv exists, False otherwise.
    """
    venv_path = get_skill_dir() / ".venv"
    return venv_path.exists() and venv_path.is_dir()


def prompt_setup() -> None:
    """Print instructions to run setup if venv is missing."""
    skill_dir = get_skill_dir()
    print_error("Virtual environment not found.")
    print()
    print("Please run setup first:")
    print()
    print(f"  cd {skill_dir}")
    print("  uv run python setup.py")
    print()


def cleanup_old_temp_files() -> int:
    """
    Remove temp files older than 1 hour matching ida-domain-*.py pattern in temp directory.

    Returns:
        Number of files cleaned up.
    """
    cleaned = 0
    cutoff_time = time.time() - 3600  # 1 hour ago

    # Find all matching temp files
    temp_dir = tempfile.gettempdir()
    pattern = str(Path(temp_dir) / "ida-domain-*.py")
    for filepath in glob.glob(pattern):
        try:
            file_path = Path(filepath)
            if file_path.is_file():
                mtime = file_path.stat().st_mtime
                if mtime < cutoff_time:
                    file_path.unlink()
                    cleaned += 1
        except (OSError, PermissionError):
            # Ignore files we can't access or delete
            pass

    return cleaned


def cleanup_old_run_directories() -> int:
    """
    Remove run directories older than 1 hour.

    This handles cleanup of orphaned directories from crashed runs.

    Returns:
        Number of directories cleaned up.
    """
    cleaned = 0
    cutoff_time = time.time() - 3600  # 1 hour ago

    temp_dir = Path(tempfile.gettempdir())
    for dirpath in temp_dir.glob("ida-domain-run-*"):
        try:
            if dirpath.is_dir():
                mtime = dirpath.stat().st_mtime
                if mtime < cutoff_time:
                    shutil.rmtree(dirpath)
                    cleaned += 1
        except (OSError, PermissionError):
            pass

    return cleaned


# IDA database file extensions (created when opening a binary)
IDA_ARTIFACT_EXTENSIONS = {".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"}

# Cache directory for persistent storage of IDA databases
# This avoids reanalysis on subsequent runs of the same binary
CACHE_DIR = Path(tempfile.gettempdir()) / "ida-domain-cache"


def is_ida_database(path: Path) -> bool:
    """
    Check if the file is an IDA database.

    Args:
        path: Path to check.

    Returns:
        True if the file is an IDA database (.i64 or .idb).
    """
    return path.suffix.lower() in {".i64", ".idb"}


def sanitize_path_for_cache(path: Path) -> str:
    """
    Convert a file path to a safe cache directory name.

    Replaces path separators with underscores.

    Args:
        path: Absolute path to the file.

    Returns:
        Sanitized string suitable for use as a directory name.
    """
    path_str = str(path)
    # Replace both forward and back slashes with underscores
    sanitized = path_str.replace("/", "_").replace("\\", "_")
    # Remove leading underscore if present
    if sanitized.startswith("_"):
        sanitized = sanitized[1:]
    return sanitized


def get_or_create_cache_entry(target_path: Path) -> tuple[Path, Path, bool]:
    """
    Get or create a cache entry for the target file.

    The cache uses a persistent directory structure based on the file path.
    If the file already exists in the cache, it is reused (including any
    IDA database files from previous runs).

    Cache structure:
        /tmp/ida-domain-cache/<sanitized_path>/<filename>

    Args:
        target_path: Absolute path to the target binary or .i64 file.

    Returns:
        Tuple of (cache_entry_dir, cached_file_path, already_existed).
        already_existed is True if the file was already in the cache.
    """
    # Ensure cache root exists
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Create cache entry directory based on sanitized path
    cache_name = sanitize_path_for_cache(target_path)
    cache_entry_dir = CACHE_DIR / cache_name
    cache_entry_dir.mkdir(parents=True, exist_ok=True)

    cached_file = cache_entry_dir / target_path.name

    # Check if file already exists in cache
    if cached_file.exists():
        # Check if there's also a cached IDA database for binaries
        if not is_ida_database(target_path):
            cached_i64 = cache_entry_dir / (target_path.stem + ".i64")
            if cached_i64.exists():
                print_info(f"Using cached database: {cached_i64}")
            else:
                print_info(f"Using cached file: {cached_file}")
        else:
            print_info(f"Using cached database: {cached_file}")
        return cache_entry_dir, cached_file, True

    # Copy file to cache
    shutil.copy2(target_path, cached_file)
    print_info(f"Cached file to: {cached_file}")

    return cache_entry_dir, cached_file, False


def handle_save_if_requested(
    cache_dir: Path,
    original_path: Path,
    cached_path: Path,
    save_requested: bool,
) -> None:
    """
    Handle --save flag after execution.

    If save was requested and the input was an IDA database, copy the
    modified database back to the original location.

    Note: The cache directory is NOT cleaned up - this is intentional
    to allow subsequent runs to reuse the cached IDA database.

    Args:
        cache_dir: The cache entry directory.
        original_path: Original path to the input file.
        cached_path: Path to the cached file.
        save_requested: Whether --save was requested.
    """
    if not save_requested:
        return

    try:
        # If save was requested and input was an IDA database, copy it back
        if is_ida_database(original_path):
            if cached_path.exists():
                shutil.copy2(cached_path, original_path)
                print_info(f"Saved modified database back to: {original_path}")
        else:
            # For binaries, the .i64 stays in the cache for reuse
            cached_i64 = cache_dir / (original_path.stem + ".i64")
            if cached_i64.exists():
                print_info(f"Database saved in cache: {cached_i64}")
    except OSError as e:
        print_warning(f"Failed to save database: {e}")


def get_user_code(args: argparse.Namespace) -> tuple[str, str]:
    """
    Get user code from one of three input modes.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Tuple of (code_string, source_description).

    Raises:
        ValueError: If no input provided or conflicting inputs.
    """
    # Check for conflicting inputs
    has_script_file = args.script is not None
    has_inline_code = args.code is not None
    has_stdin = not sys.stdin.isatty()

    input_count = sum([has_script_file, has_inline_code, has_stdin])

    if input_count == 0:
        raise ValueError("No script provided. Use a script file, -c for inline code, or pipe from stdin.")

    if input_count > 1:
        # Prefer explicit arguments over stdin
        if has_script_file and has_stdin:
            has_stdin = False  # Ignore stdin when script file is provided
        elif has_inline_code and has_stdin:
            has_stdin = False  # Ignore stdin when inline code is provided
        elif has_script_file and has_inline_code:
            raise ValueError("Cannot use both script file and -c inline code. Choose one.")

    # Mode 1: Script file
    if has_script_file:
        script_path = Path(args.script)
        if not script_path.exists():
            raise ValueError(f"Script file not found: {script_path}")
        if not script_path.is_file():
            raise ValueError(f"Not a file: {script_path}")
        code = script_path.read_text(encoding="utf-8")
        return code, f"file: {script_path}"

    # Mode 2: Inline code (-c)
    if has_inline_code:
        return args.code, "inline code (-c)"

    # Mode 3: Stdin
    if has_stdin:
        code = sys.stdin.read()
        if not code.strip():
            raise ValueError("Empty input from stdin.")
        return code, "stdin"

    raise ValueError("No script provided.")


def wrap_code(user_code: str, target_file: str, save_on_close: bool) -> str:
    """
    Wrap user code with IDA Domain boilerplate.

    The wrapper provides:
    - ida_domain imports
    - Database.open() context manager
    - The `db` variable for accessing all database entities

    Args:
        user_code: The user's script code.
        target_file: Path to the target binary or .i64 file.
        save_on_close: Whether to save the database on close.

    Returns:
        Wrapped code string ready for execution.
    """
    save_flag = "True" if save_on_close else "False"

    # Escape target file path for Python string
    target_file_escaped = target_file.replace("\\", "\\\\").replace("'", "\\'")

    # Indent user code to be inside the 'with' block
    indented_code = "\n".join("    " + line if line.strip() else line for line in user_code.split("\n"))

    wrapper = f'''#!/usr/bin/env python3
# Auto-wrapped by IDA Domain run.py
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

with Database.open('{target_file_escaped}', IdaCommandOptions(auto_analysis=True), save_on_close={save_flag}) as db:
    # --- User code starts here ---
{indented_code}
    # --- User code ends here ---
'''
    return wrapper


def execute_script(code: str, timeout: int | None = None) -> int:
    """
    Execute the script code via subprocess.

    Args:
        code: Python code to execute.
        timeout: Timeout in seconds (None for no timeout).

    Returns:
        Exit code from the script execution.
    """
    skill_dir = get_skill_dir()
    temp_dir = tempfile.gettempdir()

    # Create a temporary file for the wrapped script
    # Using a predictable prefix for cleanup
    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="ida-domain-",
        suffix=".py",
        dir=temp_dir,
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(code)
        temp_script = f.name

    try:
        # Execute using uv run python
        result = subprocess.run(
            ["uv", "run", "python", temp_script],
            cwd=skill_dir,
            text=True,
            timeout=timeout,
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        print_error(f"Script execution timed out after {timeout} seconds.")
        print()
        print("To increase the timeout, use the --timeout flag:")
        print(f"  uv run python run.py --timeout 3600 ...")
        print()
        print("To disable the timeout entirely, use --timeout 0")
        return 124  # Standard timeout exit code
    except FileNotFoundError:
        print_error("uv is not installed. Please install uv first.")
        print()
        print("Installation:")
        print("  curl -LsSf https://astral.sh/uv/install.sh | sh")
        return 1
    except KeyboardInterrupt:
        print_warning("Execution interrupted by user.")
        return 130
    finally:
        # Clean up the temp file we just created
        try:
            Path(temp_script).unlink()
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Execute IDA Domain scripts with automatic boilerplate wrapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Execute a script file
  uv run python run.py /tmp/analyze.py -f /path/to/binary.exe

  # Execute inline code
  uv run python run.py -c "for f in db.functions: print(f.name)" -f binary.exe

  # Execute from stdin
  cat /tmp/analyze.py | uv run python run.py -f binary.exe

  # Execute without wrapping (complete script)
  uv run python run.py /tmp/complete_script.py --no-wrap

  # Execute and save database changes
  uv run python run.py -c "db.functions[0].name = 'main'" -f binary.exe -s
""",
    )

    parser.add_argument(
        "script",
        nargs="?",
        help="Path to Python script file to execute",
    )

    parser.add_argument(
        "-f", "--file",
        dest="target",
        required=True,
        help="Target binary or .i64 file (required)",
    )

    parser.add_argument(
        "-c", "--code",
        dest="code",
        help="Inline Python code to execute",
    )

    parser.add_argument(
        "-s", "--save",
        dest="save",
        action="store_true",
        default=False,
        help="Enable save_on_close=True (default: False)",
    )

    parser.add_argument(
        "--no-wrap",
        dest="no_wrap",
        action="store_true",
        default=False,
        help="Skip auto-wrapping (for complete scripts that handle their own setup)",
    )

    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=1800,
        help="Execution timeout in seconds (default: 1800 = 30 minutes, 0 for no timeout)",
    )

    return parser.parse_args()


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    # Parse arguments first
    args = parse_args()

    # Step 1: Check venv exists
    if not check_venv_exists():
        prompt_setup()
        return 1

    # Step 2: Clean up old temp files and orphaned run directories (non-blocking, best effort)
    cleaned_files = cleanup_old_temp_files()
    cleaned_dirs = cleanup_old_run_directories()
    if cleaned_files > 0 or cleaned_dirs > 0:
        print_info(f"Cleaned up {cleaned_files} old temp file(s) and {cleaned_dirs} orphaned run dir(s).")

    # Step 3: Validate target file (moved before cache lookup)
    target_path = Path(args.target)
    if not target_path.exists():
        print_error(f"Target file not found: {args.target}")
        return 1
    if not target_path.is_file():
        print_error(f"Target is not a file: {args.target}")
        return 1

    # Resolve to absolute path
    original_path = target_path.resolve()

    # Step 4: Get or create cache entry for the input file
    # This prevents IDA from creating artifacts in the original directory
    # and allows reuse of IDA databases from previous runs
    cache_dir, cached_path, _ = get_or_create_cache_entry(original_path)

    # Step 5: Get user code
    try:
        user_code, source_desc = get_user_code(args)
    except ValueError as e:
        print_error(str(e))
        return 1

    # Step 6: Wrap code (unless --no-wrap)
    # Use the cached file path so IDA operates in the cache directory
    if args.no_wrap:
        final_code = user_code
        print_info(f"Executing {source_desc} without wrapping...")
    else:
        final_code = wrap_code(user_code, str(cached_path), args.save)
        print_info(f"Executing wrapped {source_desc}...")

    # Step 7: Execute
    # Convert timeout: 0 means no timeout (None), otherwise use the value
    timeout = args.timeout if args.timeout > 0 else None
    exit_code = execute_script(final_code, timeout=timeout)

    # Step 8: Handle --save if requested
    # Note: Cache directory is NOT cleaned up to allow reuse on subsequent runs
    handle_save_if_requested(cache_dir, original_path, cached_path, args.save)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
