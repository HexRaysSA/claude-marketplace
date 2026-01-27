# Claude Code Resources for IDA Pro

Claude Code plugins and skills for IDA Pro reverse engineering workflows. These plugins enable Claude to autonomously create IDA Pro plugins and execute binary analysis scripts.

## Plugins

### ida-plugin-development

Develop plugins for IDA Pro in Python, using idiomatic patterns, lessons, and tricks.

See [plugins/ida-plugin-development/README.md](plugins/ida-plugin-development/README.md) for detailed documentation.

### (unsafe) reverse-engineering-with-code-eval-and-ida-domain

(Unsafe) Skills, knowledge, and scripts for reverse engineering with IDA Pro. Autonomously writes and executes IDA Domain scripts to analyze binaries, extract functions, decompile code, and automate any reverse engineering task.

> warning: this plugin generates and evaluates code on the current system, so it should only be used in a sandboxed environment.

See [plugins/code-eval-ida-domain/](plugins/code-eval-ida-domain/) for detailed documentation.

## Installation

```bash
/plugin marketplace add HexRaysSA/ida-claude-plugins
/plugin install ida-plugin-development@ida-claude-plugins
# unsafe: /plugin install reverse-engineering-with-code-eval-and-ida-domain@ida-claude-plugins
```

## Requirements

- IDA Pro 9.x
- `uv` package manager

## License

MIT License - Copyright 2026 Hex-Rays SA
