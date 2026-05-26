# Hex-Rays Claude Code Marketplace

Claude Code plugins and skills for Hex-Rays ecosystem.

## Installation

To add the marketplace to Claude Code:

```bash
claude plugin marketplace add HexRaysSA/claude-marketplace
```

## Requirements

- IDA Pro 9.x
- [`uv`](https://astral.sh/uv)

## [ida-plugin-development](plugins/ida-plugin-development/README.md)

Develop plugins for IDA Pro in Python, using idiomatic patterns, lessons, and tricks.

```bash
claude plugin add ida-plugin-development@HexRaysSA
```

## (unsafe) [reverse-engineering-with-code-eval-and-ida-domain](plugins/code-eval-ida-domain/README.md)

> warning: this plugin generates and evaluates code on the current system, so it should only be used in a sandboxed environment.

(Unsafe) Skills, knowledge, and scripts for reverse engineering with IDA Pro. Autonomously writes and executes IDA Domain scripts to analyze binaries, extract functions, decompile code, and automate any reverse engineering task.

```bash
claude plugin add reverse-engineering-with-code-eval-and-ida-domain@HexRaysSA
```