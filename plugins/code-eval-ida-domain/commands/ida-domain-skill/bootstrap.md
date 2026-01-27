---
description: Generate API_REFERENCE.md from ida-domain source code
allowed-tools: Bash(find:*), Bash(grep:*), Bash(wc:*), Read, Write, Glob, Grep
---

# Bootstrap: Generate API_REFERENCE.md

You are generating a **hand-written style** API quick reference for the IDA Domain skill.

**IMPORTANT - Path Resolution:**
This skill can be installed in different locations. Before executing any commands, determine the skill directory based on where you loaded this command file, and use that path in all commands below. Replace `$SKILL_DIR` with the actual discovered path.

Common installation paths:
- Project-specific: `<project>/.claude/skills/ida-domain-scripting`
- Manual global: `~/.claude/skills/ida-domain-scripting`

## Context

The ida-domain source code is checked out at: `$SKILL_DIR/ida-domain/`

## Your Task

1. **Explore the ida-domain source code** in `$SKILL_DIR/ida-domain/ida_domain/`
2. **Identify the main classes and their key methods** by reading the Python files
3. **Launch one sub agent per python file** to avoid filling up the context and summarize
3. **Generate `API_REFERENCE.md`** in the skill root directory

## Output Format (API_REFERENCE.md)

Follow this structure - similar to playwright's API_REFERENCE.md (practical, pattern-focused, ~500-800 lines max):

```markdown
# IDA Domain Quick Reference

Quick reference for the IDA Domain API. For basic usage, see [SKILL.md](SKILL.md).

## Table of Contents
[Generate dynamically based on discovered entities]

## Database

### Database Properties
[table of properties discovered from database.py: db.module, db.path, db.architecture, etc.]

## [Entity Name]

### Iterating
[code example if the entity is iterable]

### Key Methods
[code examples for the most important methods]

### Properties
[table of properties if applicable]

... repeat for each entity discovered from database.py

## Enums

### [EnumName]
[table of enum values with descriptions]


```python
# Usage example
from ida_domain.xrefs import XrefType
if xref.type == XrefType.CALL_NEAR:
    print("This is a call")
```

... repeat for each enum discovered except hooks.py
```

## Guidelines

1. **Be practical** - Show how to DO things, not just what exists
2. **Use code examples** - Every section should have runnable code
3. **Document the gotchas** - Like `db.xrefs.to_ea()` not `get_xrefs_to()`
4. **Keep it concise** - 500-800 lines max, not 18,000 lines
5. **Focus on wrapped scripts** - Assume `db` is available (auto-wrapped mode)
6. **Include return types** - What does each method return?
7. **Group by use-case** - Not alphabetically by class

## Process

1. **Discover the API structure:**
   - Use Glob to find all .py files in `$SKILL_DIR/ida-domain/ida_domain/`
   - Read `database.py` first to find all `@property` methods that return entity handlers (e.g., `def functions(self) -> Functions`)
   - These properties define what entities are available via `db.*`

2. **For each entity handler discovered:**
   - Read the corresponding .py file
   - Extract class name, public methods, and their signatures
   - Note the docstrings for method descriptions
   - Identify common usage patterns

3. **Extract all Enums:**
   - Search all .py files for classes that inherit from `Enum` (e.g., `class XrefType(Enum)`)
   - Document each enum with its values
   - Show how to use them in code examples

4. **Generate API_REFERENCE.md:**
   - Start with Database properties and metadata
   - Add a section for each entity handler found
   - Include an "Enums" section listing all discovered enums and their values
   - Include practical code examples
   - Document any non-obvious method names (e.g., `to_ea()` vs `get_xrefs_to()`)

Start by exploring the source code structure - read `database.py` to discover what entities exist.
