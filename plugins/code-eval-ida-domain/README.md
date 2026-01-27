# (unsafe) Reverse Engineering with Code Evaluation and the IDA Domain API

> warning: this plugin generates and evaluates code on the current system, so it should only be used in a sandboxed environment.

Analyze binaries using IDA Pro's Python Domain API (ida-domain) in headless mode (idalib). Use when examining program structure, functions, disassembly, cross-references, or strings without the GUI.

Provides:
- agent `ida-domain-expert`: Senior IDA Domain Python developer and IDA Pro reverse engineer. Use proactively when writing IDA Domain scripts, debugging IDA API issues, analyzing binary analysis problems, or when the user needs expert guidance on reverse engineering tasks with IDA Pro.
- skill `ida-domain-scripting`: Write and execute Python scripts using the IDA Domain API for reverse engineering. Analyze binaries, extract functions, strings, cross-references, decompile code, work with IDA Pro databases (.i64/.idb). Use when user wants to analyze binaries, reverse engineer executables, or automate IDA Pro tasks.

## Installation

```bash
/plugin marketplace add HexRaysSA/ida-claude-plugins
/plugin install reverse-engineering-with-code-eval-and-ida-domain@ida-claude-plugins
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
