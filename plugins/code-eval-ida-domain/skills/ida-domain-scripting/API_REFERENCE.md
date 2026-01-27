# IDA Domain Quick Reference

Quick reference for the IDA Domain API. For basic usage, see [SKILL.md](SKILL.md).

## Table of Contents

- [Database](#database)
- [Functions](#functions)
- [Instructions](#instructions)
- [Segments](#segments)
- [Strings](#strings)
- [Xrefs](#xrefs)
- [Names](#names)
- [Types](#types)
- [Bytes](#bytes)
- [Comments](#comments)
- [Entries](#entries)
- [Heads](#heads)
- [Flowchart](#flowchart)
- [Signature Files](#signature-files)
- [Enums Reference](#enums-reference)

---

## Database

The `Database` class is your entry point. Use `db` in auto-wrapped scripts.

### Opening a Database

```python
# Library mode: Open and automatically close
with Database.open("path/to/file.exe", save_on_close=True) as db:
    print(f"Loaded: {db.module}")

# IDA GUI mode: Get handle to current database
db = Database.open()
```

### Database Properties

| Property | Type | Description |
|----------|------|-------------|
| `db.path` | `str` | Input file path |
| `db.module` | `str` | Module name |
| `db.base_address` | `ea_t` | Image base address |
| `db.minimum_ea` | `ea_t` | Minimum effective address |
| `db.maximum_ea` | `ea_t` | Maximum effective address |
| `db.filesize` | `int` | Input file size |
| `db.md5` | `str` | MD5 hash of input file |
| `db.sha256` | `str` | SHA256 hash of input file |
| `db.architecture` | `str` | Processor architecture |
| `db.bitness` | `int` | Application bitness (32/64) |
| `db.format` | `str` | File format type |
| `db.execution_mode` | `ExecutionMode` | User or Kernel mode |
| `db.current_ea` | `ea_t` | Current screen EA (readable/writable) |
| `db.start_ip` | `ea_t` | Start instruction pointer |

### Database Methods

```python
db.is_valid_ea(ea, strict_check=True)  # Check if address is valid
db.is_open()                            # Check if database is loaded
db.execute_script(file_path)            # Execute a Python script
db.close(save=True)                     # Close database (library mode only)
```

### Entity Handlers

Access all IDA data through these handlers:

```python
db.functions      # Function operations
db.instructions   # Instruction operations
db.segments       # Segment operations
db.strings        # String operations
db.xrefs          # Cross-reference operations
db.names          # Name/symbol operations
db.types          # Type information operations
db.bytes          # Raw byte operations
db.comments       # Comment operations
db.entries        # Entry point operations
db.heads          # Head (item) operations
db.signature_files # FLIRT signature operations
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

## Signature Files

### Applying Signatures

```python
from pathlib import Path

# Apply single file
results = db.signature_files.apply(Path("/path/to/file.sig"))

# Apply all in directory
results = db.signature_files.apply(Path("/path/to/sigs/"))

# Probe only (don't persist)
results = db.signature_files.apply(Path("file.sig"), probe_only=True)

for result in results:
    print(f"{result.path}: {result.matches} matches")
    for func in result.functions:
        print(f"  {func.addr:#x}: {func.name}")
```

### Finding Signature Files

```python
# Default IDA sig directories
sig_files = db.signature_files.get_files()

# Include custom directories
sig_files = db.signature_files.get_files([Path("/custom/sigs")])
```

### Creating Signatures

```python
# Create .sig and .pat files from current database
files = db.signature_files.create()

# Create only .pat file
files = db.signature_files.create(pat_only=True)
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
