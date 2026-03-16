---
name: ida-domain-api
description: Analyze binaries using the Domain API for IDA Pro. Use when examining program structure, functions, disassembly, cross-references, or strings.
---

# Domain API for IDA Pro

Use this skill to efficiently use the Domain API for IDA Pro, which is easier and more concise than the legacy IDA Python SDK.

**Always prefer the IDA Domain API** over the legacy low-level IDA Python SDK. The Domain API provides a clean, Pythonic interface that is easier to use and understand.

### Documentation Resources

| Resource | URL |
|----------|-----|
| **LLM-optimized overview** | https://ida-domain.docs.hex-rays.com/llms.txt |
| **Getting Started** | https://ida-domain.docs.hex-rays.com/getting_started/index.md |
| **Examples** | https://ida-domain.docs.hex-rays.com/examples/index.md |
| **API Reference** | https://ida-domain.docs.hex-rays.com/ref/{module}/index.md |

Available API modules: `bytes`, `comments`, `database`, `entries`, `flowchart`, `functions`, `heads`, `hooks`, `instructions`, `names`, `operands`, `segments`, `signature_files`, `strings`, `types`, `xrefs`

**To fetch specific API documentation**, use URLs like:
- `https://ida-domain.docs.hex-rays.com/ref/functions/index.md` - Function analysis API
- `https://ida-domain.docs.hex-rays.com/ref/xrefs/index.md` - Cross-reference API
- `https://ida-domain.docs.hex-rays.com/ref/strings/index.md` - String analysis API

### Opening a Database

```python
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

# Open an existing .i64/.idb
ida_options = IdaCommandOptions(auto_analysis=False, new_database=False)
with Database.open("path/to/sample.i64", ida_options, save_on_close=False) as db:
    pass

# Analyze a raw input file and create a new database
ida_options = IdaCommandOptions(
    auto_analysis=True,
    new_database=True,
    output_database="path/to/cache/sample.i64",
    load_resources=True,
)
with Database.open("path/to/input.exe", ida_options, save_on_close=True) as db:
    pass
```

### Commonly Used IdaCommandOptions

`IdaCommandOptions` maps directly to IDA command-line switches. Two options are especially common for headless analysis tools:

**`load_resources=True`** (maps to `-R`): loads MS Windows exe resources. Important for PE analysis that needs resource data.

**`plugin_options`** (maps to `-O`): pass options to IDA plugins. The most common use is **disabling Lumina** to prevent it from injecting bad or non-deterministic names:

```python
ida_options = IdaCommandOptions(
    auto_analysis=True,
    new_database=True,
    output_database=str(cache_path),
    load_resources=True,
    plugin_options="lumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0",
)
```

This sets both primary and secondary Lumina server addresses to `0.0.0.0`, effectively disabling Lumina lookups. The `plugin_options` field is a raw string; `build_args()` emits `-O{value}` verbatim, so embedding `-O` inside the value for additional plugin options works correctly — the above produces `-Olumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0`.

Other useful fields: `processor` (`-p`), `log_file` (`-L`), `script_file` (`-S`), `db_compression` (`-P`). See the `IdaCommandOptions` docstring for the full list.

### Transparent Database Cache for Headless Tools

For repeatable CLI tools, do not re-analyze raw binaries every run. Prefer this pattern:
- if the input is already an `.i64` or `.idb`, use it directly
- otherwise hash the raw input and use the SHA-256 as the cache key
- create `<cache>/<sha256>.i64` on demand
- serialize access with a lock file and an extra `.nam` check, because another IDA process may have the database unpacked
- create the cached database with `save_on_close=True`
- reopen cached databases read-only with `save_on_close=False`
- after requesting auto-analysis, call `ida_auto.auto_wait()` before querying

```python
import contextlib
import fcntl
import hashlib
import os
import time
from pathlib import Path

import ida_auto
from ida_domain import Database
from ida_domain.database import IdaCommandOptions

DATABASE_POLL_INTERVAL = 0.25
DATABASE_ACCESS_TIMEOUT = 5.0
DATABASE_ANALYSIS_TIMEOUT = 120.0


def get_cache_dir() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "your-tool"


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_for_repack(db_path: Path, timeout: float) -> None:
    nam_path = db_path.with_suffix(".nam")
    deadline = time.monotonic() + timeout
    while nam_path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"database appears busy: {db_path}")
        time.sleep(DATABASE_POLL_INTERVAL)


@contextlib.contextmanager
def database_access_guard(db_path: Path, timeout: float):
    wait_for_repack(db_path, timeout)
    lock_path = Path(str(db_path) + ".lock")
    lock_fd = lock_path.open("w")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"timed out waiting for lock: {db_path}")
                time.sleep(DATABASE_POLL_INTERVAL)

        wait_for_repack(db_path, max(0.0, deadline - time.monotonic()))
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def resolve_database(file_path: Path) -> Path:
    if file_path.suffix.lower() in {".i64", ".idb"}:
        return file_path

    cache_dir = get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{compute_sha256(file_path)}.i64"
    if cache_path.exists():
        return cache_path

    with database_access_guard(cache_path, DATABASE_ANALYSIS_TIMEOUT):
        if cache_path.exists():
            return cache_path

        ida_options = IdaCommandOptions(
            auto_analysis=True,
            new_database=True,
            output_database=str(cache_path),
            load_resources=True,
        )
        with Database.open(str(file_path), ida_options, save_on_close=True):
            ida_auto.auto_wait()

        if not cache_path.exists():
            raise RuntimeError(f"analysis did not create {cache_path}")
        return cache_path


@contextlib.contextmanager
def open_database_session(db_path: Path, auto_analysis: bool = False):
    with database_access_guard(db_path, DATABASE_ACCESS_TIMEOUT):
        ida_options = IdaCommandOptions(auto_analysis=auto_analysis, new_database=False)
        with Database.open(str(db_path), ida_options, save_on_close=False) as db:
            if auto_analysis:
                ida_auto.auto_wait()
            yield db
```

Notes:
- keep cached database creation quiet in normal mode; only log cache paths in verbose/debug mode
- if you need a different cache policy, keep the same three-phase guard: wait for `.nam`, acquire `flock`, re-check `.nam`
- if you must fall back to `idapro.open_database(...)` for options not exposed by `ida-domain`, import your local project modules before `import idapro`, because `idapro` can mutate `sys.path`
- disable Lumina via `plugin_options="lumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0"` in `IdaCommandOptions` (see "Commonly Used IdaCommandOptions" above); no need to fall back to `idapro.open_database()` for this

### Key Database Properties

```python
with Database.open(path, ida_options) as db:
    db.minimum_ea      # Start address
    db.maximum_ea      # End address
    db.metadata        # Database metadata
    db.architecture    # Target architecture

    db.functions       # All functions (iterable)
    db.strings         # All strings (iterable)
    db.segments        # Memory segments
    db.names           # Symbols and labels
    db.entries         # Entry points
    db.types           # Type definitions
    db.comments        # All comments
    db.xrefs           # Cross-reference utilities
    db.bytes           # Byte manipulation
    db.instructions    # Instruction access
```

---

## Functions

### Iterating Functions

```python
# Iterate all functions
for func in db.functions:
    print(db.functions.get_name(func))

# Get function count
count = len(db.functions)
```

If your report needs thunk functions or library functions, iterate `db.functions` directly and classify them by flags. Do not assume a higher-level wrapper already included them.

### Finding Functions

```python
func = db.functions.get_at(0x401000)           # By address
func = db.functions.get_function_by_name("main")  # By name
func = db.functions.get_next(ea)               # Next function after ea

# Functions in range
for func in db.functions.get_between(start_ea, end_ea):
    print(func.start_ea)
```

### Function Properties

```python
name = db.functions.get_name(func)
signature = db.functions.get_signature(func)
flags = db.functions.get_flags(func)  # Returns FunctionFlags

# Check function attributes
db.functions.is_far(func)
db.functions.does_return(func)
```

### Function Code

```python
# Get disassembly lines
lines = db.functions.get_disassembly(func, remove_tags=True)

# Get decompiled pseudocode
pseudocode = db.functions.get_pseudocode(func, remove_tags=True)

# Get microcode
microcode = db.functions.get_microcode(func, remove_tags=True)
```

### Function Analysis

```python
# Get instructions in function
for insn in db.functions.get_instructions(func):
    print(insn.ea)

# Get flowchart for basic blocks
flowchart = db.functions.get_flowchart(func)
for block in flowchart:
    print(f"Block: {block.start_ea:#x} - {block.end_ea:#x}")

# Get callers/callees
callers = db.functions.get_callers(func)
callees = db.functions.get_callees(func)

# Get function chunks
for chunk in db.functions.get_chunks(func):
    print(f"Chunk: {chunk.start_ea:#x}, main={chunk.is_main}")

# Get data items within function
for data_ea in db.functions.get_data_items(func):
    print(f"Data at {data_ea:#x}")
```

### Thunk-Aware Analysis

If your tool renders callers/callees, API usage, or function summaries, resolve thunks once and reuse the result everywhere. A good default is:
- check `FunctionFlags.THUNK`
- follow only single-target thunk chains
- stop on cycles, zero-target chains, or multi-target chains
- cap the depth so malformed databases cannot loop forever

```python
from ida_domain.functions import FunctionFlags

MAX_THUNK_DEPTH = 5


def resolve_thunk(db, func):
    current = func
    seen = set()

    for _ in range(MAX_THUNK_DEPTH):
        if not (db.functions.get_flags(current) & FunctionFlags.THUNK):
            return current

        if current.start_ea in seen:
            return current
        seen.add(current.start_ea)

        callees = list(db.functions.get_callees(current))
        if len(callees) != 1:
            return current

        current = callees[0]

    return current
```

Use the resolved target consistently for:
- caller lists
- callee lists
- API/import classification
- attaching per-function metadata like matches or tags

### Local Variables

```python
# Get all local variables
lvars = db.functions.get_local_variables(func)
for lvar in lvars:
    print(f"{lvar.name}: {lvar.type_str}, arg={lvar.is_argument}")

# Find variable by name
lvar = db.functions.get_local_variable_by_name(func, "result")

# Get variable references in pseudocode
refs = db.functions.get_local_variable_references(func, lvar)
for ref in refs:
    print(f"Line {ref.line_number}: {ref.access_type} in {ref.context}")
```

### Modifying Functions

```python
db.functions.set_name(func, "new_name")
db.functions.set_comment(func, "This function does X", repeatable=False)
db.functions.create(ea)   # Create function at address
db.functions.remove(ea)   # Remove function at address
```

---

## Instructions

### Iterating Instructions

```python
# All instructions in database
for insn in db.instructions:
    print(db.instructions.get_disassembly(insn))

# Instructions in range
for insn in db.instructions.get_between(start_ea, end_ea):
    print(insn.ea)
```

### Getting Instructions

```python
insn = db.instructions.get_at(ea)          # Decode at address
insn = db.instructions.get_previous(ea)    # Previous instruction
```

### Instruction Properties

```python
disasm = db.instructions.get_disassembly(insn)
mnemonic = db.instructions.get_mnemonic(insn)  # "mov", "push", etc.
db.instructions.is_valid(insn)
```

### Control Flow Analysis

```python
db.instructions.is_call_instruction(insn)      # Is this a call?
db.instructions.is_indirect_jump_or_call(insn) # Indirect jump/call?
db.instructions.breaks_sequential_flow(insn)   # Stops flow (ret, jmp)?
```

### Working with Operands

```python
count = db.instructions.get_operands_count(insn)
operands = db.instructions.get_operands(insn)  # List of Operand objects

for op in operands:
    info = op.get_info()
    print(f"Operand {op.number}: {op.type.name}")

    if isinstance(op, RegisterOperand):
        print(f"  Register: {op.get_register_name()}")
    elif isinstance(op, ImmediateOperand):
        print(f"  Value: 0x{op.get_value():x}")
    elif isinstance(op, MemoryOperand):
        if op.is_direct_memory():
            print(f"  Memory: 0x{op.get_address():x}")
```

---

## Segments

### Iterating Segments

```python
for segment in db.segments:
    name = db.segments.get_name(segment)
    size = db.segments.get_size(segment)
    print(f"{name}: {segment.start_ea:#x} - {segment.end_ea:#x}")

count = len(db.segments)
```

### Finding Segments

```python
seg = db.segments.get_at(0x401000)      # Segment containing address
seg = db.segments.get_by_name(".text")  # By name
```

### Segment Properties

```python
name = db.segments.get_name(segment)
size = db.segments.get_size(segment)
bitness = db.segments.get_bitness(segment)  # 16, 32, or 64
seg_class = db.segments.get_class(segment)   # "CODE", "DATA", etc.
```

### Creating Segments

```python
from ida_domain.segments import PredefinedClass, AddSegmentFlags

# Add segment with explicit range
seg = db.segments.add(
    seg_para=0,
    start_ea=0x1000,
    end_ea=0x2000,
    seg_name="MySegment",
    seg_class=PredefinedClass.CODE
)

# Append segment after last one
seg = db.segments.append(seg_para=0, seg_size=0x1000, seg_name="NewSeg")
```

### Modifying Segments

```python
from ida_domain.segments import SegmentPermissions, AddressingMode

db.segments.set_name(segment, "new_name")
db.segments.set_permissions(segment, SegmentPermissions.READ | SegmentPermissions.EXEC)
db.segments.add_permissions(segment, SegmentPermissions.WRITE)
db.segments.remove_permissions(segment, SegmentPermissions.WRITE)
db.segments.set_addressing_mode(segment, AddressingMode.BIT64)
db.segments.set_comment(segment, "Code section", repeatable=False)
```

---

## Strings

### Iterating Strings

```python
for string in db.strings:
    print(f"{string.address:#x}: {string}")

# By index
first_string = db.strings[0]
count = len(db.strings)
```

### Finding Strings

```python
string = db.strings.get_at(0x402000)  # String at address

# Strings in range
for s in db.strings.get_between(start_ea, end_ea):
    print(s.contents)
```

### String Properties

```python
print(string.address)       # Address
print(string.length)        # Length in characters
print(string.type)          # StringType enum
print(string.encoding)      # Internal encoding
print(string.contents)      # UTF-8 bytes
print(str(string))          # Decoded string
```

### Rebuilding String List

```python
from ida_domain.strings import StringListConfig, StringType

config = StringListConfig(
    string_types=[StringType.C, StringType.C_16],
    min_len=3,
    only_ascii_7bit=False
)
db.strings.rebuild(config)
db.strings.clear()  # Clear string list
```

---

## Xrefs

### Getting References TO an Address

```python
# All xrefs to an address
for xref in db.xrefs.to_ea(target_ea):
    print(f"{xref.from_ea:#x} -> {xref.to_ea:#x} ({xref.type.name})")

# Just code references
for ea in db.xrefs.code_refs_to_ea(target_ea, flow=False):
    print(f"Code ref from {ea:#x}")

# Just data references
for ea in db.xrefs.data_refs_to_ea(target_ea):
    print(f"Data ref from {ea:#x}")

# Call references only
for ea in db.xrefs.calls_to_ea(func_ea):
    print(f"Called from {ea:#x}")

# Detailed caller information
for caller in db.xrefs.get_callers(func_ea):
    print(f"Called from {caller.name} at {caller.ea:#x}")
```

### Getting References FROM an Address

```python
# All xrefs from an address
for xref in db.xrefs.from_ea(source_ea):
    print(f"{xref.from_ea:#x} -> {xref.to_ea:#x}")

# Code/data refs from
for ea in db.xrefs.code_refs_from_ea(source_ea):
    print(f"Code ref to {ea:#x}")

for ea in db.xrefs.calls_from_ea(source_ea):
    print(f"Calls {ea:#x}")
```

### Data Access Analysis

```python
# Who reads this data?
for ea in db.xrefs.reads_of_ea(data_ea):
    print(f"Read by {ea:#x}")

# Who writes to this data?
for ea in db.xrefs.writes_to_ea(data_ea):
    print(f"Written by {ea:#x}")
```

### XrefInfo Properties

```python
xref.is_call    # Is this a call reference?
xref.is_jump    # Is this a jump reference?
xref.is_read    # Is this a data read?
xref.is_write   # Is this a data write?
xref.is_flow    # Is this ordinary flow?
xref.user       # Is this user-defined?
```

---

## Names

### Iterating Names

```python
for ea, name in db.names:
    print(f"{ea:#x}: {name}")

count = len(db.names)
```

### Getting Names

```python
name = db.names.get_at(0x401000)
ea, name = db.names[0]  # By index
```

### Setting Names

```python
from ida_domain.names import SetNameFlags

db.names.set_name(ea, "my_function")
db.names.set_name(ea, "my_func", flags=SetNameFlags.CHECK)  # Validate chars
db.names.force_name(ea, "func")  # Creates func_2 if func exists
db.names.delete(ea)              # Remove name
```

### Name Properties

```python
db.names.is_valid_name("my_name")   # Check if valid
db.names.is_public_name(ea)         # Is public?
db.names.is_weak_name(ea)           # Is weak?

db.names.make_name_public(ea)
db.names.make_name_non_public(ea)
db.names.make_name_weak(ea)
db.names.make_name_non_weak(ea)
```

### Demangling

```python
from ida_domain.names import DemangleFlags

demangled = db.names.get_demangled_name(ea)
demangled = db.names.get_demangled_name(ea, DemangleFlags.NORETTYPE)
demangled = db.names.demangle_name("?main@@YAXXZ")
```

---

## Types

### Getting Types

```python
# By name
tinfo = db.types.get_by_name("MyStruct")

# At address
tinfo = db.types.get_at(ea)

# Iterate all types
for tinfo in db.types:
    print(tinfo)
```

### Parsing Types

```python
# Parse declarations from string
errors = db.types.parse_declarations(None, "struct Point { int x; int y; };")

# Parse single declaration
tinfo = db.types.parse_one_declaration(None, "int (*callback)(void*)", "callback_t")

# Parse header file
errors = db.types.parse_header_file(library, Path("header.h"))
```

### Applying Types

```python
from ida_domain.types import TypeApplyFlags

db.types.apply_at(tinfo, ea, flags=TypeApplyFlags.DEFINITE)
```

### Type Details

```python
details = db.types.get_details(tinfo)
print(details.name)
print(details.size)
print(details.attributes)

# For structs/unions
if details.udt:
    print(details.udt.num_members)
    print(details.udt.attributes)

# For functions
if details.func:
    print(details.func.attributes)
```

### Type Libraries

```python
# Load/create libraries
lib = db.types.load_library(Path("types.til"))
lib = db.types.create_library(Path("new.til"), "My Types")

# Import/export types
db.types.import_type(source_lib, "MyStruct")
db.types.export_type(dest_lib, "MyStruct")

# Save library
db.types.save_library(lib, Path("output.til"))
db.types.unload_library(lib)
```

---

## Bytes

### Reading Values

```python
byte = db.bytes.get_byte_at(ea)
word = db.bytes.get_word_at(ea)
dword = db.bytes.get_dword_at(ea)
qword = db.bytes.get_qword_at(ea)
float_val = db.bytes.get_float_at(ea)
double_val = db.bytes.get_double_at(ea)

# Read multiple bytes
data = db.bytes.get_bytes_at(ea, size=16)
original = db.bytes.get_original_bytes_at(ea, size=16)

# Read strings
string = db.bytes.get_string_at(ea)
cstring = db.bytes.get_cstring_at(ea, max_length=256)
```

### Writing Values

```python
db.bytes.set_byte_at(ea, 0x90)
db.bytes.set_word_at(ea, 0x1234)
db.bytes.set_dword_at(ea, 0x12345678)
db.bytes.set_qword_at(ea, 0x123456789ABCDEF0)
db.bytes.set_bytes_at(ea, b"\x90\x90\x90")
```

### Patching (with History)

```python
db.bytes.patch_byte_at(ea, 0x90)     # Saves original
db.bytes.patch_bytes_at(ea, data)
db.bytes.revert_byte_at(ea)          # Restore original

# Get original values
orig = db.bytes.get_original_byte_at(ea)
```

### Searching

```python
from ida_domain.bytes import SearchFlags

# Find bytes
ea = db.bytes.find_bytes_between(b"\x55\x89\xe5", start_ea, end_ea)

# Find all occurrences
addresses = db.bytes.find_binary_sequence(b"\x90\x90")

# Find text
ea = db.bytes.find_text_between("error", flags=SearchFlags.DOWN)

# Find immediate value
ea = db.bytes.find_immediate_between(0x1234)
```

### Creating Data Items

```python
from ida_domain.strings import StringType

db.bytes.create_byte_at(ea, count=4)
db.bytes.create_word_at(ea)
db.bytes.create_dword_at(ea, count=10)  # Array of 10 dwords
db.bytes.create_qword_at(ea)
db.bytes.create_float_at(ea)
db.bytes.create_double_at(ea)
db.bytes.create_string_at(ea, string_type=StringType.C)
db.bytes.create_struct_at(ea, count=1, tid=struct_tid)
```

### Querying Properties

```python
size = db.bytes.get_data_size_at(ea)
db.bytes.is_value_initialized_at(ea)
db.bytes.is_code_at(ea)
db.bytes.is_data_at(ea)
db.bytes.is_head_at(ea)
db.bytes.is_tail_at(ea)
db.bytes.is_unknown_at(ea)

# Get disassembly at address
disasm = db.bytes.get_disassembly_at(ea)
```

### Navigation

```python
next_head = db.bytes.get_next_head(ea)
prev_head = db.bytes.get_previous_head(ea)
next_addr = db.bytes.get_next_address(ea)
prev_addr = db.bytes.get_previous_address(ea)
```

---

## Comments

### Regular Comments

```python
from ida_domain.comments import CommentKind

# Get comment
info = db.comments.get_at(ea, CommentKind.REGULAR)
if info:
    print(info.comment)

# Set comment
db.comments.set_at(ea, "This is important", CommentKind.REGULAR)
db.comments.set_at(ea, "Shows everywhere", CommentKind.REPEATABLE)

# Delete comment
db.comments.delete_at(ea, CommentKind.ALL)
```

### Iterating Comments

```python
for comment_info in db.comments:
    print(f"{comment_info.ea:#x}: {comment_info.comment}")

# All comment types
for info in db.comments.get_all(CommentKind.ALL):
    print(f"{info.ea:#x} (repeatable={info.repeatable}): {info.comment}")
```

### Extra Comments (Anterior/Posterior)

```python
from ida_domain.comments import ExtraCommentKind

# Set extra comment
db.comments.set_extra_at(ea, index=0, comment="Before line", kind=ExtraCommentKind.ANTERIOR)
db.comments.set_extra_at(ea, index=0, comment="After line", kind=ExtraCommentKind.POSTERIOR)

# Get extra comments
comment = db.comments.get_extra_at(ea, index=0, kind=ExtraCommentKind.ANTERIOR)
for comment in db.comments.get_all_extra_at(ea, ExtraCommentKind.ANTERIOR):
    print(comment)

# Delete
db.comments.delete_extra_at(ea, index=0, kind=ExtraCommentKind.ANTERIOR)
```

---

## Entries

### Iterating Entry Points

```python
for entry in db.entries:
    print(f"{entry.ordinal}: {entry.name} at {entry.address:#x}")

count = len(db.entries)
first = db.entries[0]
```

### Finding Entries

```python
entry = db.entries.get_at(ea)              # By address
entry = db.entries.get_by_ordinal(1)       # By ordinal
entry = db.entries.get_by_name("main")     # By name
entry = db.entries.get_at_index(0)         # By index
```

### Entry Properties

```python
print(entry.ordinal)
print(entry.address)
print(entry.name)
print(entry.forwarder_name)
entry.has_forwarder()
```

### Modifying Entries

```python
db.entries.add(address=ea, name="new_entry", ordinal=10)
db.entries.rename(ordinal=10, new_name="renamed_entry")
db.entries.set_forwarder(ordinal=10, forwarder_name="other.dll!func")
db.entries.exists(ordinal=10)
```

### Utility Iterators

```python
for ordinal in db.entries.get_ordinals():
    print(ordinal)

for addr in db.entries.get_addresses():
    print(f"{addr:#x}")

for name in db.entries.get_names():
    print(name)

for fwd in db.entries.get_forwarders():
    print(f"{fwd.ordinal}: {fwd.name}")
```

---

## Heads

### Iterating Heads

```python
for ea in db.heads:
    print(f"Head at {ea:#x}")

# In range
for ea in db.heads.get_between(start_ea, end_ea):
    print(ea)
```

### Navigation

```python
next_ea = db.heads.get_next(ea)
prev_ea = db.heads.get_previous(ea)
```

### Head Properties

```python
db.heads.is_head(ea)      # Is start of item?
db.heads.is_tail(ea)      # Is part of multi-byte item?
db.heads.is_code(ea)      # Is instruction?
db.heads.is_data(ea)      # Is data?
db.heads.is_unknown(ea)   # Is unclassified?

size = db.heads.size(ea)
start, end = db.heads.bounds(ea)
```

---

## Flowchart

### Creating Flowcharts

```python
from ida_domain.flowchart import FlowChart, FlowChartFlags

# From function
flowchart = FlowChart(db, func=my_func)

# From address range
flowchart = FlowChart(db, bounds=(start_ea, end_ea))

# With predecessor info
flowchart = FlowChart(db, func=my_func, flags=FlowChartFlags.PREDS)
```

### Iterating Basic Blocks

```python
for block in flowchart:
    print(f"Block {block.id}: {block.start_ea:#x} - {block.end_ea:#x}")

# By index
block = flowchart[0]
count = len(flowchart)
```

### Block Navigation

```python
for succ in block.get_successors():
    print(f"Successor: {succ.id}")

for pred in block.get_predecessors():
    print(f"Predecessor: {pred.id}")

succ_count = block.count_successors()
pred_count = block.count_predecessors()
```

### Block Instructions

```python
for insn in block.get_instructions():
    print(f"{insn.ea:#x}")
```

---

## Enums Reference

### XrefType

```python
from ida_domain.xrefs import XrefType

XrefType.OFFSET       # Offset reference
XrefType.WRITE        # Write access
XrefType.READ         # Read access
XrefType.CALL_FAR     # Far call
XrefType.CALL_NEAR    # Near call
XrefType.JUMP_FAR     # Far jump
XrefType.JUMP_NEAR    # Near jump
XrefType.ORDINARY_FLOW  # Sequential flow

xref_type.is_code_ref()  # Check if code ref
xref_type.is_data_ref()  # Check if data ref
```

### FunctionFlags

```python
from ida_domain.functions import FunctionFlags

FunctionFlags.NORET      # Doesn't return
FunctionFlags.LIB        # Library function
FunctionFlags.THUNK      # Thunk function
FunctionFlags.HIDDEN     # Hidden chunk
FunctionFlags.LUMINA     # From Lumina
FunctionFlags.FAR        # Far function
FunctionFlags.FRAME      # Uses frame pointer
```

### LocalVariableAccessType

```python
from ida_domain.functions import LocalVariableAccessType

LocalVariableAccessType.READ     # Variable is read
LocalVariableAccessType.WRITE    # Variable is written
LocalVariableAccessType.ADDRESS  # Address taken (&var)
```

### LocalVariableContext

```python
from ida_domain.functions import LocalVariableContext

LocalVariableContext.ASSIGNMENT    # var = expr
LocalVariableContext.CONDITION     # if (var)
LocalVariableContext.CALL_ARG      # func(var)
LocalVariableContext.RETURN        # return var
LocalVariableContext.ARITHMETIC    # var + 1
LocalVariableContext.COMPARISON    # var == x
LocalVariableContext.ARRAY_INDEX   # arr[var]
LocalVariableContext.POINTER_DEREF # *var
LocalVariableContext.CAST          # (type)var
```

### OperandType

```python
from ida_domain.operands import OperandType

OperandType.REGISTER      # Register
OperandType.MEMORY        # Direct memory
OperandType.PHRASE        # Register addressing
OperandType.DISPLACEMENT  # Reg + displacement
OperandType.IMMEDIATE     # Immediate value
OperandType.FAR_ADDRESS   # Far address
OperandType.NEAR_ADDRESS  # Near address
```

### StringType

```python
from ida_domain.strings import StringType

StringType.C        # C-style null-terminated
StringType.C_16     # C-style 16-bit
StringType.C_32     # C-style 32-bit
StringType.PASCAL   # Pascal-style
StringType.LEN2     # 2-byte length prefix
StringType.LEN4     # 4-byte length prefix
```

### SegmentPermissions

```python
from ida_domain.segments import SegmentPermissions

SegmentPermissions.READ
SegmentPermissions.WRITE
SegmentPermissions.EXEC
SegmentPermissions.ALL
```

### AddressingMode

```python
from ida_domain.segments import AddressingMode

AddressingMode.BIT16  # 16-bit segment
AddressingMode.BIT32  # 32-bit segment
AddressingMode.BIT64  # 64-bit segment
```

### PredefinedClass

```python
from ida_domain.segments import PredefinedClass

PredefinedClass.CODE
PredefinedClass.DATA
PredefinedClass.CONST
PredefinedClass.STACK
PredefinedClass.BSS
PredefinedClass.XTRN
```

### CommentKind

```python
from ida_domain.comments import CommentKind

CommentKind.REGULAR     # Normal comment
CommentKind.REPEATABLE  # Shows at all refs
CommentKind.ALL         # Both types
```

### ExtraCommentKind

```python
from ida_domain.comments import ExtraCommentKind

ExtraCommentKind.ANTERIOR   # Before the line
ExtraCommentKind.POSTERIOR  # After the line
```

### TypeAttr

```python
from ida_domain.types import TypeAttr

TypeAttr.INT, TypeAttr.UINT
TypeAttr.FLOAT, TypeAttr.DOUBLE
TypeAttr.PTR, TypeAttr.ARRAY
TypeAttr.FUNC, TypeAttr.STRUCT
TypeAttr.UNION, TypeAttr.ENUM
TypeAttr.CONST, TypeAttr.VOLATILE
```

### FlowChartFlags

```python
from ida_domain.flowchart import FlowChartFlags

FlowChartFlags.NONE   # Default
FlowChartFlags.NOEXT  # Don't compute external blocks
FlowChartFlags.PREDS  # Compute predecessors
```

---

## Common Patterns

### Find All Calls to a Function

```python
func = db.functions.get_function_by_name("malloc")
if func:
    for caller in db.xrefs.get_callers(func.start_ea):
        print(f"Called from {caller.name} at {caller.ea:#x}")
```

### Rename Functions Based on Strings

```python
for func in db.functions:
    for insn in db.functions.get_instructions(func):
        for xref in db.xrefs.from_ea(insn.ea):
            string = db.strings.get_at(xref.to_ea)
            if string and "error" in str(string).lower():
                db.functions.set_name(func, f"func_with_error_{func.start_ea:x}")
                break
```

### Analyze Function Complexity

```python
func = db.functions.get_at(ea)
flowchart = db.functions.get_flowchart(func)
print(f"Basic blocks: {len(flowchart)}")

total_edges = sum(block.count_successors() for block in flowchart)
print(f"Cyclomatic complexity: {total_edges - len(flowchart) + 2}")
```

### Export Function Pseudocode

```python
for func in db.functions:
    name = db.functions.get_name(func)
    try:
        pseudocode = db.functions.get_pseudocode(func)
        print(f"// {name}")
        for line in pseudocode:
            print(line)
    except RuntimeError:
        print(f"// Could not decompile {name}")
```

### Find Cross-References to Strings

```python
for string in db.strings:
    refs = list(db.xrefs.to_ea(string.address))
    if refs:
        print(f'"{string}" referenced from:')
        for xref in refs:
            print(f"  {xref.from_ea:#x}")
```

## Legacy API (Avoid)

The legacy `idc`, `idautils`, `ida_funcs` APIs still work but are harder to use. **Prefer the Domain API** for new analysis scripts. Only use legacy APIs when Domain API doesn't expose needed functionality.
