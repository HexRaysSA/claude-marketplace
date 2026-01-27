---
name: package-ida-plugin
description: Package IDA Pro plugins for the IDA Plugin Manager and plugins.hex-rays.com repository
---

# Packaging IDA Pro Plugins

This skill helps package IDA Pro plugins for distribution via the IDA Plugin Manager and the plugins.hex-rays.com repository. It covers creating and updating the `ida-plugin.json` manifest, packaging archives, and publishing via GitHub Releases.

## Overview

The IDA Plugin Manager is a self-service ecosystem for discovering, installing, and sharing IDA plugins:

- **Discovery**: A daily indexer scans GitHub for repositories containing `ida-plugin.json`
- **Repository**: Published at [plugins.hex-rays.com](https://plugins.hex-rays.com/) and [github.com/HexRaysSA/plugin-repository](https://github.com/HexRaysSA/plugin-repository)
- **Client**: HCLI command-line tool (`hcli plugin install <name>`)
- **Compatibility**: IDA Pro 9.0+ (full support)

## Critical: Understanding Plugin Root Directory

**The `ida-plugin.json` file defines the root of the plugin.** When a plugin is installed, only the directory containing `ida-plugin.json` (and its subdirectories) is copied to `$IDAUSR/plugins/`. Nothing outside this directory is included.

### Assessing Directory Structure Compatibility

Before packaging, verify that your plugin's structure is self-contained:

```
# GOOD: All plugin code is in the same directory as ida-plugin.json
my-repo/
├── ida-plugin.json        # Plugin root
├── my_plugin.py           # Entry point - INCLUDED
├── my_plugin_lib/         # Supporting code - INCLUDED
│   └── helpers.py
├── README.md              # Plugin README - INCLUDED (shown on web)
└── assets/
    └── logo.png           # Logo - INCLUDED

# BAD: Plugin code outside the ida-plugin.json directory
my-repo/
├── plugin/
│   └── ida-plugin.json    # Plugin root is here
├── src/                   # NOT INCLUDED - outside plugin root!
│   └── my_plugin.py       # This file won't be installed!
└── README.md              # NOT INCLUDED - wrong directory!
```

### Compatibility Checklist

When assessing an existing plugin, verify:

1. [ ] **Entry point location**: Is `entryPoint` in the same directory as `ida-plugin.json`?
2. [ ] **All imports resolvable**: Are all Python imports within the plugin root or in `pythonDependencies`?
3. [ ] **No parent directory references**: Does the code use `../` to access files outside the plugin root?
4. [ ] **Assets included**: Are logos, data files, or resources inside the plugin root?
5. [ ] **README placement**: Is `README.md` in the plugin root (not repo root) for web display?

### Common Restructuring Patterns

**Pattern 1: Plugin in subdirectory**

If your plugin code is in a subdirectory like `src/` or `plugin/`, move `ida-plugin.json` into that directory:

```
# Before                          # After
my-repo/                          my-repo/
├── ida-plugin.json               └── src/
└── src/                              ├── ida-plugin.json  # Moved here
    └── my_plugin.py                  ├── my_plugin.py
                                      └── README.md        # Add for web
```

**Pattern 2: Monorepo with IDA plugin**

For projects where IDA plugin is one component (e.g., capa), place `ida-plugin.json` at the plugin code's location:

```
capa/
├── capa/
│   ├── ida/
│   │   └── plugin/
│   │       ├── ida-plugin.json   # Plugin root
│   │       ├── capa_explorer.py  # Entry point
│   │       └── README.md         # Plugin-specific docs
│   └── main.py                   # Not included in IDA plugin
└── README.md                     # Repo README - not the plugin README
```

### README in Plugin Root

Place a `README.md` file in the same directory as `ida-plugin.json` to have it displayed on the [plugins.hex-rays.com](https://plugins.hex-rays.com/) web interface. This is separate from your repository's root README:

```
my-plugin/
├── ida-plugin.json
├── my_plugin.py
└── README.md              # This README appears on plugins.hex-rays.com
```

The plugin README should focus on:
- What the plugin does
- How to use it within IDA
- Configuration options (if using settings)
- Screenshots or examples

It does **not** need installation instructions (the Plugin Manager handles that).

## The ida-plugin.json Manifest

Every plugin requires an `ida-plugin.json` file in its root directory. This is the **only required file** beyond the plugin code itself. Paths in the metadata file are relative to the metadata file, because the metadata file defines the root of the plugin, even if its nested within a ZIP archive.

### Complete Schema

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "my-plugin",
    "version": "1.0.0",
    "entryPoint": "my_plugin.py",
    "description": "A one-line description of what this plugin does",
    "license": "MIT",
    "urls": {
      "repository": "https://github.com/org/my-plugin",
      "homepage": "https://example.com/my-plugin"
    },
    "authors": [
      {"name": "Author Name", "email": "author@example.com"}
    ],
    "maintainers": [
      {"name": "Maintainer Name", "email": "maintainer@example.com"}
    ],
    "idaVersions": ["9.0", "9.1", "9.2"],
    "platforms": ["windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-aarch64"],
    "categories": ["malware-analysis"],
    "keywords": ["analysis", "automation"],
    "pythonDependencies": ["requests>=2.0", "pydantic>=2"],
    "logoPath": "assets/logo.png",
    "settings": []
  }
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `IDAMetadataDescriptorVersion` | `1` | Always set to `1` |
| `plugin.name` | string | Unique identifier. ASCII letters, digits, underscores, hyphens only. No leading/trailing `_` or `-`. Used to derive the IDA namespace: `__plugins__my_plugin` |
| `plugin.version` | string | Semantic version `x.y.z` format. No leading `v` |
| `plugin.entryPoint` | string | Entry point filename (e.g., `my_plugin.py`) or bare name for native plugins |
| `plugin.urls.repository` | string | GitHub URL: `https://github.com/org/project` |
| `plugin.authors` OR `plugin.maintainers` | array | At least one contact with `email` field required |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `plugin.description` | string | none | One-line description shown in search results |
| `plugin.license` | string | none | License identifier (e.g., `MIT`, `Apache-2.0`, `GPL-3.0`) |
| `plugin.urls.homepage` | string | none | Homepage URL if different from repository |
| `plugin.idaVersions` | array or string | all versions | Supported IDA versions. Can be explicit list `["9.0", "9.1"]` or spec `">=7.4"` |
| `plugin.platforms` | array | all platforms | Supported platforms: `windows-x86_64`, `linux-x86_64`, `macos-x86_64`, `macos-aarch64` |
| `plugin.categories` | array | `[]` | See Categories section below |
| `plugin.keywords` | array | `[]` | Search terms for discoverability |
| `plugin.pythonDependencies` | array or `"inline"` | `[]` | PyPI packages. Use `"inline"` for PEP 723 metadata |
| `plugin.logoPath` | string | none | Relative path to logo image (16:9 aspect ratio recommended) |
| `plugin.settings` | array | `[]` | Plugin configuration options. See Settings section |

### Valid Categories

```
disassembly-and-processor-modules
file-parsers-and-loaders
decompilation
debugging-and-tracing
deobfuscation
collaboration-and-productivity
integration-with-third-parties-interoperability
api-scripting-and-automation
ui-ux-and-visualization
malware-analysis
vulnerability-research-and-exploit-development
other
```

### Valid IDA Versions

Current/supported: `9.2`, `9.1`, `9.0sp1`, `9.0`,  ...

Use a version specifier like `">=9.0"` to match multiple versions automatically.

## Packaging Pure Python Plugins

For simple Python plugins, the directory structure is minimal:

```
my-plugin/
├── ida-plugin.json
├── README.md             # Displayed on plugins.hex-rays.com
├── my_plugin.py          # entryPoint
└── my_plugin_lib/        # optional supporting modules
    ├── __init__.py
    └── helpers.py
```

### Minimal Example

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "my-simple-plugin",
    "version": "1.0.0",
    "entryPoint": "my_plugin.py",
    "urls": {
      "repository": "https://github.com/username/my-simple-plugin"
    },
    "authors": [
      {"name": "Your Name", "email": "you@example.com"}
    ]
  }
}
```

### With Dependencies

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "capa",
    "version": "9.3.1",
    "entryPoint": "capa_explorer.py",
    "description": "Identify capabilities in executable files using FLARE's capa framework",
    "license": "Apache-2.0",
    "idaVersions": ">=7.4",
    "categories": ["malware-analysis", "api-scripting-and-automation", "ui-ux-and-visualization"],
    "pythonDependencies": ["flare-capa==9.3.1"],
    "urls": {
      "repository": "https://github.com/mandiant/capa"
    },
    "authors": [
      {"name": "Willi Ballenthin", "email": "wballenthin@hex-rays.com"},
      {"name": "Moritz Raabe", "email": "moritzraabe@google.com"}
    ],
    "keywords": ["capability-detection", "malware-analysis", "att&ck", "static-analysis"]
  }
}
```

### PEP 723 Inline Dependencies

If your plugin uses PEP 723 inline script metadata, set `pythonDependencies` to `"inline"`:

```json
{
  "pythonDependencies": "inline"
}
```

Then in your entry point Python file:

```python
# /// script
# dependencies = [
#     "requests>=2.0",
#     "pydantic>=2"
# ]
# ///

import ida_kernwin
# ... rest of plugin
```

## Packaging Native Plugins

Native plugins require compiled binaries (.dll, .so, .dylib) for each target platform.

### Directory Structure

```
my-native-plugin/
├── ida-plugin.json
├── README.md              # Displayed on plugins.hex-rays.com
├── my_plugin.dll          # Windows
├── my_plugin.so           # Linux
└── my_plugin.dylib        # macOS (universal or architecture-specific)
```

### Entry Point Convention

For native plugins, use a **bare name** without extension:

```json
{
  "plugin": {
    "entryPoint": "my_plugin",
    "platforms": ["windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-aarch64"]
  }
}
```

IDA will automatically append the correct extension (`.dll`, `.so`, `.dylib`) for the current platform.

### Fat Binary Archives

Include all platform binaries in a single archive. The entry point uses the bare name, and the correct binary is selected at install time.

### Platform-Specific Archives

Alternatively, create separate archives per platform with explicit extensions:

**Windows archive:**
```json
{
  "plugin": {
    "entryPoint": "my_plugin.dll",
    "platforms": ["windows-x86_64"]
  }
}
```

**Linux archive:**
```json
{
  "plugin": {
    "entryPoint": "my_plugin.so",
    "platforms": ["linux-x86_64"]
  }
}
```

## Plugin Settings

For plugins requiring user configuration, declare settings in the manifest. Users configure these via `hcli plugin config` or the IDA GUI.

### Settings Schema

```json
{
  "settings": [
    {
      "key": "api_key",
      "name": "API Key",
      "type": "string",
      "required": true,
      "documentation": "Your API key for the service"
    },
    {
      "key": "endpoint",
      "name": "API Endpoint",
      "type": "string",
      "required": false,
      "default": "https://api.example.com",
      "validation_pattern": "^https://.*$"
    },
    {
      "key": "log_level",
      "name": "Log Level",
      "type": "string",
      "required": false,
      "choices": ["debug", "info", "warning", "error"],
      "default": "info"
    },
    {
      "key": "enable_telemetry",
      "name": "Enable Telemetry",
      "type": "boolean",
      "required": false,
      "default": false
    }
  ]
}
```

### Setting Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | string | yes | Code-level identifier (e.g., `api_key`) |
| `name` | string | yes | Human-readable label (e.g., `API Key`) |
| `type` | `"string"` or `"boolean"` | yes | Value type |
| `required` | boolean | yes | Whether user must provide a value |
| `documentation` | string | no | Help text for users |
| `default` | string or boolean | no | Default value if not configured |
| `validation_pattern` | string | no | Regex for validating string values |
| `choices` | array of strings | no | Allowed values (mutually exclusive with `validation_pattern`) |

### Accessing Settings in Plugin Code

Use the `ida-settings` library:

```python
from ida_settings import get_current_plugin_setting

api_key = get_current_plugin_setting("api_key")
log_level = get_current_plugin_setting("log_level")
```

## Validation

Always validate before publishing:

```bash
# Validate a directory
hcli plugin lint /path/to/my-plugin

# Validate a ZIP archive
hcli plugin lint /path/to/my-plugin.zip
```

The linter checks:
- JSON syntax and schema compliance
- Required fields present
- Entry point file exists
- Logo file exists (if declared)
- Platform/binary consistency
- Path safety (no traversals)

## Publishing to the Repository

### Step 1: Create a GitHub Release

1. Tag your commit: `git tag v1.0.0 && git push --tags`
2. Create a GitHub Release from the tag
3. Attach your plugin archive (ZIP)

### Step 2: Automatic Indexing

The indexer runs daily and automatically discovers:
- Repositories with `ida-plugin.json` in the root
- GitHub Releases with valid plugin archives

No manual registration required. Your plugin appears within 24 hours.

### Step 3: Explicit Registration (Optional)

To expedite indexing, add your repository to `known-repositories.txt`:

1. Fork [HexRaysSA/plugin-repository](https://github.com/HexRaysSA/plugin-repository)
2. Add your repo URL to `known-repositories.txt` (one per line)
3. Submit a pull request

### Troubleshooting Indexing

Check the [indexer log report](https://hexrayssa.github.io/plugin-repository/logs/indexer.html) for errors.

Common issues:
- Invalid JSON syntax
- Missing required fields (especially author email)
- Repository URL doesn't match GitHub pattern
- Entry point file not found in archive

## Multi-Plugin Archives

A single archive can contain multiple plugins, each in its own subdirectory:

```
multi-plugin.zip
├── plugin-a/
│   ├── ida-plugin.json
│   └── plugin_a.py
└── plugin-b/
    ├── ida-plugin.json
    └── plugin_b.py
```

Each subdirectory must have its own `ida-plugin.json`.

## Version Updates

To release a new version:

1. Update `plugin.version` in `ida-plugin.json`
2. Create a new git tag matching the version
3. Create a GitHub Release with the new archive
4. The indexer will pick up the new version automatically

Users upgrade via: `hcli plugin upgrade <name>`

## Common Patterns

### Minimal Python Plugin Checklist

1. [ ] Create `ida-plugin.json` with required fields
2. [ ] Ensure entry point file exists
3. [ ] Add author with email
4. [ ] Run `hcli plugin lint`
5. [ ] Create GitHub Release with source archive

### Adding Settings to Existing Plugin

1. [ ] Define settings array in `ida-plugin.json`
2. [ ] Add `ida-settings` to `pythonDependencies` if using the library
3. [ ] Update plugin code to use `get_current_plugin_setting()`
4. [ ] Document settings in README

### Converting Legacy Plugin

1. [ ] **Assess directory structure**: Verify all plugin code is self-contained
   - Entry point and all imports within one directory
   - No `../` references to parent directories
   - Data files and assets colocated with code
2. [ ] **Restructure if needed**: Move `ida-plugin.json` to where the plugin code lives
3. [ ] Create `ida-plugin.json` with required fields
4. [ ] Set correct `entryPoint` (relative to `ida-plugin.json`)
5. [ ] Add appropriate `idaVersions` (test compatibility!)
6. [ ] Declare `pythonDependencies` from requirements.txt
7. [ ] Add `README.md` in plugin root for web display
8. [ ] Validate and test locally: `hcli plugin lint`
9. [ ] Create GitHub Release

## HCLI Commands Reference

```bash
# List available plugins
hcli plugin list

# Search plugins
hcli plugin search <query>

# Install a plugin
hcli plugin install <name>
hcli plugin install <name>==1.0.0

# Upgrade a plugin
hcli plugin upgrade <name>

# Uninstall a plugin
hcli plugin uninstall <name>

# List installed plugins
hcli plugin list --installed

# Configure plugin settings
hcli plugin config <name> set <key> <value>
hcli plugin config <name> get <key>

# Validate plugin
hcli plugin lint /path/to/plugin
```

## Resources

- **Plugin Repository**: [plugins.hex-rays.com](https://plugins.hex-rays.com/)
- **Documentation**: [hcli.docs.hex-rays.com](https://hcli.docs.hex-rays.com/)
- **Repository Source**: [github.com/HexRaysSA/plugin-repository](https://github.com/HexRaysSA/plugin-repository)
- **HCLI Source**: [github.com/HexRaysSA/ida-hcli](https://github.com/HexRaysSA/ida-hcli)
- **IDA Settings Library**: [github.com/williballenthin/ida-settings](https://github.com/williballenthin/ida-settings)
- **Support**: [github.com/HexRaysSA/ida-hcli/issues](https://github.com/HexRaysSA/ida-hcli/issues)

