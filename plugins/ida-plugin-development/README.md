# IDA Plugin Development Skill for Claude Code

Develop plugins for IDA Pro in Python, using idiomatic patterns, lessons, and tricks, including the Python Domain API (ida-domain). Use when creating both GUI (Qt) and background plugins for inspecting and rendering things program structure, functions, disassembly, cross-references, and strings.

A [Claude Skill](https://docs.claude.com/en/docs/claude-code/skills) that enables Claude to autonomously create, package, and install IDAPython plugins with proper HCLI-compatible packaging.

Claude handles plugin infrastructure (Qt widgets, menus, actions, hooks, settings) so you can focus on what your plugin should do.

## Requirements

- [uv](https://docs.astral.sh/uv/) package manager

## Installation

```bash
/plugin marketplace add HexRaysSA/ida-claude-plugins
/plugin install ida-plugin-development@ida-claude-plugins
```

## Scope

**In Scope:**
- Plugin infrastructure (lifecycle, registration)
- Qt6 widgets (forms, dialogs, choosers)
- Actions, menus, hotkeys
- UI_Hooks for event handling
- Settings descriptors
- HCLI packaging and validation

**Out of Scope:**
- IDA scripting/analysis logic (use ida-domain-skill for that)
- IDA 7.x/8.x compatibility
- C++ SDK plugins

## Related

- [HCLI Documentation](https://hcli.docs.hex-rays.com/)
- [IDAPython Documentation](https://python.docs.hex-rays.com/)
- [ida-domain Documentation](https://ida-domain.docs.hex-rays.com/)


## License

MIT License - see [LICENSE](LICENSE) file for details.
