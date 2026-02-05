---
name: ida-plugin-development
description: Develop plugins for IDA Pro in Python, using idiomatic patterns, lessons, and tricks, including the Python Domain API (ida-domain). Use when creating both GUI (Qt) and background plugins for inspecting and rendering things program structure, functions, disassembly, cross-references, and strings.
---

# Developing IDA Pro plugins

Use this skill when developing plugins for IDA Pro using Python.

IDA's UI and analysis passes can be almost completely replaced through plugins.
There's a lot of power (and a lot of complexity), so its important to follow known patterns.
This document lists tips and tricks for creating new plugins for modern versions of IDA.

Key concepts covered in this document:
- [Use the IDA Domain API](#use-the-ida-domain-api) - prefer the high-level Pythonic interface
- [Plugin Manager Integration](#plugin-manager-integration) - packaging and distribution
- [Plugin Entry Point](#plugin-entry-point) - version checking and conditional loading
- [Hook Registration](#hook-registration) - pairwise register/unregister pattern
- [Cross-Plugin Communication via IDC Functions](#cross-plugin-communication-via-idc-functions) - invoke plugin functionality from scripts/other plugins
- [Save/Load state from netnodes](#saveload-state-from-netnodes) - persist plugin data in IDB
- [Respond to current address and selection change](#respond-to-current-address-and-selection-change) - UI location hooks
- [Find widgets by prefix](#find-widgets-by-prefix) - managing multiple widget instances
- [Context Menu Entries](#context-menu-entries-send-to-foo-and-send-to-foo-a) - "Send to Foo" patterns
- [User Defined Prefix](#user-defined-prefix) - add contextual markers in disassembly
- [Viewer Hints](#viewer-hints) - hover popups with context
- [Overriding rendering](#overriding-rendering) - custom colors and mnemonics
- [Custom Viewers](#custom-viewers) - tagged lines with clickable addresses


## Use the IDA Domain API

Always prefer the IDA Domain API over the legacy low-level IDA Python SDK. The Domain API provides a clean, Pythonic interface that is easier to use and understand.
However, there will be some things that the Domain API doesn't cover, especially around plugin registration and GUI handling.

Right now: read this intro guide: https://ida-domain.docs.hex-rays.com/getting_started/index.md 

Always refer to the documentation rather than doing introspection, because the documentation explains concepts, not just symbol names.
To fetch specific API documentation, use URLs like:
- `https://ida-domain.docs.hex-rays.com/ref/functions/index.md` - Function analysis API
- `https://ida-domain.docs.hex-rays.com/ref/xrefs/index.md` - Cross-reference API
- `https://ida-domain.docs.hex-rays.com/ref/strings/index.md` - String analysis API

Available API modules: `bytes`, `comments`, `database`, `entries`, `flowchart`, `functions`, `heads`, `hooks`, `instructions`, `names`, `operands`, `segments`, `signature_files`, `strings`, `types`, `xrefs`
URL pattern: https://ida-domain.docs.hex-rays.com/ref/{module}/index.md

You can always ask a subagent to answer a question by exploring the documentation and summarizing its findings.

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

### Common Analysis Tasks

#### List Functions

```python
func: func_t
for func in db.functions:
    name = db.functions.get_name(func)
    print(f"{hex(func.start_ea)}: {name} ({func.size} bytes)")
```

Interesting `func_t` properties:
```python
class func_t:
    name: str
    flags: int
    start_ea: int
    end_ea: int
    size: int
    does_return: bool
    referers: list[int]  # function start addresses
    addresses: list[int]
    frame_object: tinfo_t
    prototype: tinfo_t
```


#### Cross-references
```python
for xref in db.xrefs.to_ea(target_addr):
    print(f"Referenced from {hex(xref.from_ea)} (type: {xref.type.name})")

for xref in db.xrefs.from_ea(source_addr):
    print(f"References {hex(xref.to_ea)}")

for xref in db.xrefs.calls_to_ea(func_addr):
    print(f"Called from {hex(xref.from_ea)}")
```

`XrefInfo` type:
```python
XrefInfo(
    from_ea: int,
    to_ea: int,
    is_code: bool,
    type: XrefType,
    user: bool,
)
```

#### Read data
```python
db.bytes.get_byte_at(addr)
db.bytes.get_bytes_at(addr)
db.bytes.get_cstring_at(addr)
db.bytes.get_word_at(addr)
db.bytes.get_dword_at(addr)
db.bytes.get_qword_at(addr)
db.bytes.get_disassembly_at(addr)
db.bytes.get_flags_at(addr)
```


## Plugin Manager Integration

Plugins must be compatible with the Hex-Rays Plugin Manager.

Making your plugin available via Plugin Manager offers several benefits:

- simplified plugin installation
- improved plugin discoverability through the central index
- easy Python dependency management

The key points to make your IDA plugin available via Plugin Manager are:

- Add `ida-plugin.json`
- Package your plugin into a ZIP archive (via source archives or GitHub Actions)
- Publish releases on GitHub

A complete `ida-plugin.json` example:

```json
{
  "IDAMetadataDescriptorVersion": 1,
  "plugin": {
    "name": "ida-terminal-plugin",
    "entryPoint": "index.py",
    "version": "1.0.0",
    "idaVersions": ">=9.2",
    "platforms": [
      "windows-x86_64",
      "linux-x86_64",
      "macos-x86_64",
      "macos-aarch64",
    ],
    "description": "A lightweight terminal integration for IDA Pro that lets you open a fully functional terminal within the IDA GUI.\nQuickly access shell commands, scripts, or tooling without leaving your reversing environment.",
    "license": "MIT",
    "logoPath": "ida-plugin.png",
    "categories": [
      "ui-ux-and-visualization"
    ],
    "keywords": [
      "terminal",
      "shell",
      "cli",
    ],
    "pythonDependencies": [
      "pydantic>=2.12"
    ],
    "urls": {
      "repository": "https://github.com/williballenthin/idawilli"
    },
    "authors": [{
      "name": "Willi Ballenthin",
      "email": "wballenthin@hex-rays.com"
    }],
    "settings": [
      {
        "key": "theme",
        "type": "string",
        "required": true,
        "default": "darcula",
        "name": "color theme",
        "documentation": "the color theme name, picked from https://windowsterminalthemes.dev/",
      }
    ]
  }
}
```

Before completing your work, review the following resources for packaging hints:

- https://hcli.docs.hex-rays.com/reference/plugin-repository-architecture/
- https://hcli.docs.hex-rays.com/reference/plugin-packaging-and-format/
- https://hcli.docs.hex-rays.com/reference/packaging-your-existing-plugin/

Use the script `./scripts/hcli-package.py` to invoke HCLI in a consistent way and lint the current plugin.

## Use ida-settings for configuration values

ida-settings is a Python library used by IDA Pro plugins to fetch configuration values from the shared settings infrastructure.

During plugin installation, the plugin manager prompts users for the configuration values and stores them in `ida-config.json`.
Subsequently, users can invoke HCLI (or later, the IDA Pro GUI) to update their configuration.
ida-settings is the library that plugins use to fetch the configuration values.

For example:

```python
import ida_settings
api_key = ida_settings.get_current_plugin_setting("openai_key")
```

Note that this must be called from within the plugin (`plugin_t` or `plugmod_t`), not a callback or hook;
capture an instance of the plugin settings and pass it around as necessary:

```python
class Hooks(idaapi.IDP_Hooks):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        
    def ev_get_bg_color(self, color, ea):
        mnem = ida_ua.print_insn_mnem(ea)

        if mnem == "call" or mnem == "CALL":
            bgcolor = ctypes.cast(int(color), ctypes.POINTER(ctypes.c_int))
            bgcolor[0] = int(settings.get_setting("bg_color"))
            return 1

        else:
            return 0

class FooPluginMod(ida_idaapi.plugmod_t):
    def run(self, arg):
        settings = ida_settings.get_current_plugin_settings()
        self.hooks = Hooks(settings)
        self.hooks.hook()

```

Available APIs are:
 - `del(_current)_plugin_setting`
 - `get(_current)_plugin_setting`
 - `has(_current)_plugin_setting`
 - `set(_current)_plugin_setting`
 - `list(_current)_plugin_settings`


## Use standard logging module

Don't use `print` for status messages - use `logging.*` routines.
Do not configure logging from within a plugin - its up to the user to
 configure which levels and sources they want to see in their output window.


## Plugin Entry Point

The entrypoint of the plugin should be `foo_entry.py`
which imports from `foo.py` only if the environment is correct.

If the plugin runs in all IDA environments (assuming dependencies are present, which is reasonable),
then you don't need a special wrapper like this.

For example, if the plugin requires Qt and/or IDA to be running graphically, you could do something like:

`foo_entry.py`:
```python
import logging
import os

import ida_kernwin

logger = logging.getLogger(__name__)

def should_load():
    """Returns True if IDA 9.2+ is running interactively."""
    if not ida_kernwin.is_idaq():
        # https://community.hex-rays.com/t/how-to-check-if-idapythonrc-py-is-running-in-ida-pro-or-idalib/297/4
        return False

    if os.environ.get("IDA_IS_INTERACTIVE") != "1":
        # https://community.hex-rays.com/t/how-to-check-if-idapythonrc-py-is-running-in-ida-pro-or-idalib/297/2
        return False

    kernel_version: tuple[int, ...] = tuple(
        int(part) for part in ida_kernwin.get_kernel_version().split(".") if part.isdigit()
    ) or (0,)
    if kernel_version < (9, 2):  # type: ignore
        logger.warning("IDA too old (must be 9.2+): %s", ida_kernwin.get_kernel_version())
        return False

    return True


if should_load():
    # only attempt to import the plugin once we know the required dependencies are present.
    # otherwise we'll hit ImportError and other problems
    from foo import foo_plugin_t

    def PLUGIN_ENTRY():
        return foo_plugin_t()

else:
    try:
        import ida_idaapi
    except ImportError:
        import idaapi as ida_idaapi

    class foo_nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "foo disabled"
        comment = "foo is disabled for this IDA version"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP
    
    # we have to define this symbol, or IDA logs a message
    def PLUGIN_ENTRY():
        # we have to return something here, or IDA logs a message
        return foo_nop_plugin_t()
```

`foo.py`:
```python
class foo_plugmod_t(ida_idaapi.plugmod_t):
    def __init__(self):
        # IDA doesn't invoke this for plugmod_t, only plugin_t
        self.init()

    def init(self):
        # do things here that will always run,
        #  and don't require the menu entry (edit > plugins > ...) being selected.
        #
        # note: IDA doesn't call init, we do in __init__

        if not ida_auto.auto_is_ok():
            # don't capture events before auto-analysis is done, or we get all the system events.
            #
            # note:
            # - when we first load a program, this plugin will be run before auto-analysis is complete
            #   (actually, before auto-analysis even starts).
            #   so auto_is_ok() returns False
            # - when we load an existing IDB, auto_is_ok() return True.
            # so we can safely use this to wait until auto-analysis is complete for the first time.
            logger.debug("waiting for auto-analysis to complete before subscribing to events")
            ida_auto.auto_wait()
            logger.debug("auto-analysis complete, now subscribing to events")

        ...

    def run(self, arg):
        # do things here that users invoke via the menu entry (edit > plugins > ...)
        ...

    def term(self):
        # cleanup resources, unhook handlers, etc.
        ...

class foo_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "Do some foo"
    comment = ""
    wanted_name = "Foo"
    wanted_hotkey = ""

    def init(self):
        return foo_plugmod_t()
```


## Hook Registration

Create pairwise helper functions for registering/unregistering hooks,
and call these from `init`/`term`

```python
class oplog_plugmod_t(ida_idaapi.plugmod_t):
    def __init__(self):
        self.idb_hooks: IDBChangedHook | None = None
        self.location_hooks: UILocationHook | None = None
        ...

    def register_idb_hooks(self):
        assert self.events is not None
        self.idb_hooks = IDBChangedHook(self.events)
        self.idb_hooks.hook()

    def unregister_idb_hooks(self):
        if self.idb_hooks:
            self.idb_hooks.unhook()

    def register_location_hooks(self):
        assert self.events is not None
        self.location_hooks = UILocationHook(self.events)
        self.location_hooks.hook()

    def unregister_location_hooks(self):
        if self.location_hooks:
            self.location_hooks.unhook()

    def init(self):
        ...
        self.register_idb_hooks()
        self.register_location_hooks()

    def run(self, arg):
        ...

    def term(self):
        # cleanup in reverse order
        self.unregister_location_hooks()
        self.unregister_idb_hooks()
        ...
```


## Cross-Plugin Communication via IDC Functions

Python plugins can import shared libraries, and two plugins may even have the same dependencies. One plugin can import code from another plugin's module. However, to invoke functionality on a specific *instance* of a running plugin (accessing its state, calling methods that depend on instance data), you need a different mechanism.

Use `ida_expr.add_idc_func` to register a callable with a well-known name, and `idc.eval_idc` to invoke it from scripts or other plugins.

Key constraints:
- The function name must be globally unique - only one plugin should register a given name
- There's only a single provider for that name (no multiple instances registering the same name)
- The registering plugin must unregister the function during `term()`

```python
import ida_expr

class foo_plugmod_t(ida_idaapi.plugmod_t):
    def __init__(self):
        self.data: list[str] = []
        self.init()

    def register_idc_func(self):
        data = self.data

        def foo_get_data(index: int) -> str:
            if 0 <= index < len(data):
                return data[index]
            return ""

        def foo_add_data(value: str) -> int:
            data.append(value)
            return len(data)

        if ida_expr.add_idc_func("foo_get_data", foo_get_data, (ida_expr.VT_LONG,)):
            logger.debug("registered foo_get_data IDC function")
        else:
            logger.warning("failed to register foo_get_data IDC function")

        if ida_expr.add_idc_func("foo_add_data", foo_add_data, (ida_expr.VT_STR,)):
            logger.debug("registered foo_add_data IDC function")
        else:
            logger.warning("failed to register foo_add_data IDC function")

    def unregister_idc_func(self):
        ida_expr.del_idc_func("foo_get_data")
        ida_expr.del_idc_func("foo_add_data")

    def init(self):
        self.register_idc_func()

    def term(self):
        self.unregister_idc_func()
```

Callers invoke the function via `idc.eval_idc`:

```python
import idc

idc.eval_idc('foo_add_data("hello")')
result = idc.eval_idc('foo_get_data(0)')
```

Parameter types for `add_idc_func`:
- `ida_expr.VT_STR` - string parameter
- `ida_expr.VT_LONG` - integer parameter
- `ida_expr.VT_FLOAT` - floating point parameter

This pattern is useful for:
- Exporting plugin data to external scripts (headless testing, automation)
- Allowing one plugin to trigger actions in another
- Providing a stable API for plugin functionality that doesn't depend on Python imports


## Save/Load state from netnodes

Use netnodes to store data within the IDB.
Serialize the current plugin state during shutdown, saving it to a netnode.
Reload the state upon startup.


```python
import pydantic

OUR_NETNODE = "$ com.williballenthin.idawilli.foo"


class State(pydantic.BaseModel):
    ...

    def to_json(self):
        return self.model_dump_json()

    @classmethod
    def from_json(cls, json_str: str):
        return cls(State.model_validate_json(json_str))


def save_state(state: State):
    buf = zlib.compress(state.to_json().encode("utf-8"))

    node = ida_netnode.netnode(OUR_NETNODE)
    node.setblob(buf, 0, "I")

    logger.info("saved state")


def load_state() -> State:
    node = ida_netnode.netnode(OUR_NETNODE)
    if not node:
        logger.info("no existing state")
        return State()

    buf = node.getblob(0, "I")
    if not buf:
        logger.info("no existing state (no data)")
        return State()

    state = State.from_json(zlib.decompress(buf).decode("utf-8"))
    logger.info("loaded state")
    return state


class UI_Closing_Hooks(ida_kernwin.UI_Hooks):
    """Respond to UI events and save the events into the database."""

    # we could also use IDB_Hooks, but I found it less reliable:
    # - closebase: "the database will be closed now", however, I couldn't figure out when its actually triggered.
    # - savebase: notified during File -> Save, but not File -> Close.
    # easier to keep all the hooks in one place.

    def __init__(self, events: Events, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    def preprocess_action(self, action: str):
        if action == "CloseBase":
            # File -> Close
            save_events(self.events)
            return 0
        elif action == "QuitIDA":
            # File -> Quit
            save_events(self.events)
            return 0
        elif action == "SaveBase":
            # File -> Save
            save_events(self.events)
            return 0
        else:
            return 0
```

## Respond to current address and selection change

```python
class UILocationHook(ida_kernwin.UI_Hooks):
    def handle_current_address_change(self, ea: int):
        ...

    def handle_current_selection_change(self, start: int, end: int):
        ...

    def screen_ea_changed(self, ea: ida_idaapi.ea_t, prev_ea: ida_idaapi.ea_t) -> None:
        if ea == prev_ea:
            return

        v = ida_kernwin.get_current_viewer()

        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW,
            ida_kernwin.BWN_DISASM,
            # BWN_PSEUDOCODE
            # BWN_CUSTVIEW
            # BWN_OUTPUT the text area, in the output window
            # BWN_CLI the command-line, in the output window
            # BWN_STRINGS
            # ...
        ):
            return

        if ida_kernwin.get_viewer_place_type(v) != ida_kernwin.TCCPT_IDAPLACE:
            # other viewers might have other place types, when not address-oriented
            return

        has_range, start, end = ida_kernwin.read_range_selection(v)
        if not has_range:
            return self.handle_current_address_change(ea)

        if ida_idaapi.BADADDR in (start, end):
            return

        return self.handle_current_selection_change(start, end)
```

## Find widgets by prefix

```python
def list_widgets(prefix: str) -> list[str]:
    """Probe A-Z for existing widgets, return found captions.

    Args:
        prefix: Caption prefix to search for

    Returns: List of found widget captions (e.g., ["Foo-A", "Foo-C"])
    """
    if not prefix.endswith("-"):
        raise ValueError("prefix must end with dash")
    found = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        caption = f"{prefix}{letter}"
        if ida_kernwin.find_widget(caption) is not None:
            found.append(caption)
    return found


def find_next_available_caption(prefix: str) -> str:
    """Find first gap or next letter for widget caption.

    Args:
        prefix: Caption prefix to use

    Returns: First available caption (e.g., "Foo-B")

    Raises:
        RuntimeError: If all 26 instances are in use
    """
    if not prefix.endswith("-"):
        raise ValueError("prefix must end with dash")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        caption = f"{prefix}{letter}"
        if ida_kernwin.find_widget(caption) is None:
            return caption
    raise RuntimeError("All 26 instances in use")
```

## Context Menu Entries, "Send to Foo" and "Send to Foo-A"

When creating custom views, especially when there might be more than one,
 name them like "Foo-A", "Foo-B", etc.
And, as appropriate, add context menu items for "sending" addresses/selections
 to the new views.

The new view is an instance of `ida_kernwin.PluginForm` and may have arbitrary Qt widgets.
The plugin instance maintains a registry of created views, and registers the action
handlers for opening new views, as well as notifying the views of events from a central place.
Action handlers encapsulate the code that's invoked during an event.


```python
class FooForm(ida_kernwin.PluginForm):
    def __init__(
        self,
        caption: str = "Foo-A",
        form_registry: dict[str, "FooForm"] | None = None,
    ) -> None:
        super().__init__()
        self.TITLE = caption
        self.form_registry = form_registry

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.w = FooWidget(parent=self.parent, show_ida_buttons=True)

        ... # other Qt stuff here

        if self.form_registry is not None:
            self.form_registry[self.TITLE] = self

    def OnClose(self, form):
        if self.form_registry is not None:
            self.form_registry.pop(self.TITLE, None)


class create_foo_widget_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, plugmod: "foo_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def activate(self, ctx):
        self.plugmod.create_viewer()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class send_to_foo_action_handler_t(ida_kernwin.action_handler_t):
    """Action handler for 'Send to Foo' context menu item."""

    def __init__(self, plugmod: "foo_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def activate(self, ctx):
        """Handle 'Send to Foo' action - always creates new instance."""
        v = ida_kernwin.get_current_viewer()

        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW,
            ida_kernwin.BWN_DISASM,
        ):
            # for example: only allow sending from hexview or disassembly view
            return 0

        form = self.plugmod.create_viewer()

        if form and form.w:
            ... # do initialization

        return 1

    def update(self, ctx):
        """Enable action when there's a valid selection."""
        v = ida_kernwin.get_current_viewer()

        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW,
            ida_kernwin.BWN_DISASM,
        ):
            # for example: only allow sending from hexview or disassembly view
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class send_to_specific_widget_action_handler_t(ida_kernwin.action_handler_t):
    """Action handler for sending to a specific Foo instance."""

    def __init__(
        self,
        form_registry: dict[str, FooForm],
        caption: str,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.form_registry = form_registry
        self.caption = caption

    def activate(self, ctx):
        """Send selection to specific Foo instance."""
        v = ida_kernwin.get_current_viewer()

        widget = ida_kernwin.find_widget(self.caption)
        if widget is None:
            logger.warning(f"Widget {self.caption} not found")
            return 0

        ida_kernwin.activate_widget(widget, True)

        form = self.form_registry.get(self.caption)
        if form and hasattr(form, "w"):
            # access some specific model methods on the form
            ...
        else:
            logger.warning(f"Cannot populate {self.caption} - unable to access form")

        return 1

    def update(self, ctx):
        """Enable action when there's a valid selection."""
        v = ida_kernwin.get_current_viewer()

        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW,
            ida_kernwin.BWN_DISASM,
        ):
            # for example: only allow sending from hexview or disassembly view
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class foo_plugmod_t(ida_idaapi.plugmod_t):
    ACTION_NAME = "foo:create"
    SEND_ACTION_NAME = "foo:send_selection"
    MENU_PATH = "View/Open subviews/Foo"

    def __init__(self):
        super().__init__()
        self.form_registry: dict[str, FooForm] = {}
        ...

    def register_instance_actions(self):
        """Register actions for all existing widget instances."""
        existing = list_widgets("Foo-")

        for caption in existing:
            action_name = f"foo:send_to_{caption.replace('-', '_').lower()}"

            if ida_kernwin.unregister_action(action_name):
                pass

            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    action_name,
                    f"Send to {caption}",
                    send_to_specific_widget_action_handler_t(
                        self.form_registry, caption
                    ),
                    None,
                    f"Send selected bytes to {caption}",
                    -1,
                )
            )

    def create_viewer(self, caption: str | None = None) -> FooForm:
        if caption is None:
            caption = find_next_available_caption()
        form = FooForm(caption, self.form_registry)
        form.Show(form.TITLE)
        return form

    def register_open_action(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.ACTION_NAME,
                "Foo",
                create_foo_widget_action_handler_t(self),
            )
        )

        # TODO: add icon
        ida_kernwin.attach_action_to_menu(
            self.MENU_PATH, self.ACTION_NAME, ida_kernwin.SETMENU_APP
        )

    def unregister_open_action(self):
        ida_kernwin.unregister_action(self.ACTION_NAME)
        ida_kernwin.detach_action_from_menu(self.MENU_PATH, self.ACTION_NAME)


    def init(self):
        self.register_open_action()
        ...

    def run(self, arg):
        self.create_viewer()

    def term(self):
        ...
        self.unregister_open_action()
```

## User Defined Prefix

A user defined prefix is a great way to add some contextual data before each disassembly line.
Put symbols or numbers here to indicate there's more context available somewhere.


```python
def refresh_disassembly():
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)

class FooPrefix(ida_lines.user_defined_prefix_t):
    ICON = " β "

    def __init__(self, marks: set[int]):
        super().__init__(len(self.ICON))
        self.marks = marks

    def get_user_defined_prefix(self, ea, insn, lnnum, indent, line):
        if ea in self.marks:
            # wrap the icon in color tags so its easy to identify.
            # otherwise, the icon may merge with other spans, which
            # makes checking for equality more difficult.
            return ida_lines.COLSTR(self.ICON, ida_lines.SCOLOR_SYMBOL)

        return " " * len(self.ICON)

class FooPrefixPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.marks: set[int] = {1, 2, 3}
        self.prefixer: FooPrefix | None = None

    def run(self, arg):
        # self.prefixer is installed simply by constructing it
        self.prefixer = FooPrefix(self.marks)

        # since we're updating the disassembly listing by adding the line prefix,
        # we need to re-render all the lines.
        refresh_disassembly()

    def term(self):
        # gc will clean up prefixer and uninstall it (during plugin termination)
        self.prefixer = None

        # refresh and remove the prefix entries
        refresh_disassembly()
```

## Viewer Hints

A view hint is a really good way to display complex information in a popup hover pane
that displays when mousing over particular regions of an IDA view.
Use this to show context about a symbol or address, for example: MSDN documentation for API functions.

Use this in combination with User Defined Prefixes that indicate context *is* available and
show the context *in* the viewer hint (possibly when hovering over the prefix).

```python
class FooHints(ida_kernwin.UI_Hooks):
    def __init__(self, notes: dict[int, str], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.notes = notes

    def get_custom_viewer_hint(self, viewer, place):
        if not place:
            return

        ea = place.toea()
        if not ea:
            return

        if ea not in self.notes:
            return

        curline = ida_kernwin.get_custom_viewer_curline(viewer, True)
        curline = ida_lines.tag_remove(curline)
        _, x, _ = ida_kernwin.get_custom_viewer_place(viewer, True)

        # example: show on first column
        # more advanced: inspect the symbol, and if it matches a query, then show some data
        if x == 1:
            note = self.notes.get(ea)
            if not note:
                return

            return (f"note: {note}", 1)


class FooHintsPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.notes: dict[int, str] = {}
        self.hinter: FooHints | None = None

    def run(self, arg):
        self.hinter = FooHints(self.notes)
        self.hinter.hook()

    def term(self):
        if self.hinter is not None:
            self.hinter.unhook()

        self.hinter = None
```

## Overriding rendering



```python
class ColorHooks(idaapi.IDP_Hooks):
    def ev_get_bg_color(self, color, ea):
        """
        Get item background color.
        Plugins can hook this callback to color disassembly lines dynamically

            // background color in RGB
            typedef uint32 bgcolor_t;

        ref: https://hex-rays.com/products/ida/support/sdkdoc/pro_8h.html#a3df5040891132e50157aee66affdf1de

        args:
            color: (bgcolor_t *), out
            ea: (::ea_t)

        returns:
            retval 0: not implemented
            retval 1: color set
        """
        mnem = ida_ua.print_insn_mnem(ea)

        if mnem == "call" or mnem == "CALL":
            bgcolor = ctypes.cast(int(color), ctypes.POINTER(ctypes.c_int))
            bgcolor[0] = 0xDDDDDD
            return 1

        else:
            return 0

    def ev_out_mnem(self, ctx) -> int:
        """
        Generate instruction mnemonics.
        This callback should append the colored mnemonics to ctx.outbuf 
        Optional notification, if absent, out_mnem will be called.

        args:
            ctx: (outctx_t *)

        returns:
            retval 1: if appended the mnemonics
            retval 0: not implemented
        """
        mnem = ctx.insn.get_canon_mnem()
        if mnem == "call":
            # you can manipulate this, but note that it affects `ida_ua.print_insn_mnem` which is inconvenient for formatting.
            # also, you only have access to theme colors, like COLOR_PREFIX, not arbitrary control.
            ctx.out_custom_mnem("CALL")
            return 1

        else:
            return 0


class ColoringPluginMod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.hooks: ColorHooks | None = None

    def run(self, arg):
        self.hooks = ColorHooks()
        self.hooks.hook()

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()

        self.hooks = None
```


## Custom Viewers

Use a custom viewer to show text data, optionally with tags, and respond to basic events (clicks).
Use the tagged line concepts to embed and parse metadata about the symbols in a line,
such as which address it refers to.

```python
def addr_from_tag(raw: bytes) -> int:
    assert raw[0] == 0x01  # ida_lines.COLOR_ON
    assert raw[1] == ida_lines.COLOR_ADDR
    addr_hex = raw[2 : 2 + ida_lines.COLOR_ADDR_SIZE].decode("ascii")

    try:
        # Parse as hex address (IDA uses qsscanf with "%a" format)
        return int(addr_hex, 16)
    except ValueError:
        raise


def get_tagged_line_section_byte_offsets(section: ida_kernwin.tagged_line_section_t) -> tuple[int, int]:
    # tagged_line_section_t.byte_offsets is not exposed by swig
    # so we parse directly from the string representation (puke)
    s = str(section)
    text_start_index = s.index("text_start=")
    text_end_index = s.index("text_end=")

    text_start_s = s[text_start_index + len("text_start=") :].partition(",")[0]
    text_end_s = s[text_end_index + len("text_end=") :].partition("}")[0]

    return int(text_start_s), int(text_end_s)


@dataclass
class TaggedLineSection:
    tag: int
    string: str
    # valid when the found tag section starts with an embedded address
    address: int | None


def get_current_tag(line: str, x: int) -> TaggedLineSection:
    ret = TaggedLineSection(ida_lines.COLOR_DEFAULT, line, None)

    tls = ida_kernwin.tagged_line_sections_t()
    if not ida_kernwin.parse_tagged_line_sections(tls, line):
        return ret

    # find any section at the X coordinate
    current_section = tls.nearest_at(x, 0)  # 0 = any tag
    if not current_section:
        # TODO: we only want the section that isn't tagged
        # while there might be a section totally before or totally after x.
        return ret

    ret.tag = current_section.tag
    boring_line = ida_lines.tag_remove(line)
    ret.string = boring_line[current_section.start : current_section.start + current_section.length]

    # try to find an embedded address at the start of the current segment
    current_section_start, _ = get_tagged_line_section_byte_offsets(current_section)
    addr_section = tls.nearest_before(current_section, x, ida_lines.COLOR_ADDR)
    if addr_section:
        addr_section_start, _ = get_tagged_line_section_byte_offsets(addr_section)
        # addr_section_start initially points just after the address data (ON ADDR 001122...FF)
        # so rewind to the start of the tag (16 bytes of hex integer, 2 bytes of tags "ON ADDR")
        addr_tag_start = addr_section_start - (ida_lines.COLOR_ADDR_SIZE + 2)
        assert addr_tag_start >= 0

        # and this should match current_section_start, since that points just after the tag "ON SYMBOL"
        # if it doesn't, we're dealing with an edge case we didn't prepare for
        # maybe like multiple ADDR tags or something.
        # skip those and stick to things we know.
        if current_section_start == addr_tag_start:
            raw = line.encode("utf-8")
            addr = addr_from_tag(raw[addr_tag_start : addr_tag_start + ida_lines.COLOR_ADDR_SIZE + 2])
            ret.address = addr

    return ret


class foo_viewer_t(ida_kernwin.simplecustviewer_t):
    TITLE = "foo"

    def __init__(self):
        super().__init__()

        self.timer: QtCore.QTimer = QtCore.QTimer()
        self.timer.timeout.connect(self.on_timer_timeout)

    def Create(self):
        if not super().Create(self.TITLE):
            return False

        self.render()

        return True

    def Show(self, *args):
        if not super().Show(*args):
            return False

        ida_kernwin.attach_action_to_popup(self.GetWidget(), None, some_action_handler_t.ACTION_NAME)
        return True

    def on_timer_timeout(self):
        self.render()

    def OnClose(self):
        self.timer.stop()

    def render(self):
        self.ClearLines()
        self.AddLine(datetime.datetime.now.isoformat())
        self.AddLine(ida_lines.COLSTR(ida_lines.tag_addr(0x401000) + "sub_401000", ida_lines.SCOLOR_CNAME))

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if not line:
            return False

        _linen, x, _y = self.GetPos()

        section = get_current_tag(line, x)
        if section.address is not None:
            ida_kernwin.jumpto(section.address)

        item_address = ida_name.get_name_ea(0, section.string)
        if item_address != ida_idaapi.BADADDR:
            logger.debug(f"found address for '{section.string}': {item_address:x}")
            ida_kernwin.jumpto(item_address)

        return True  # handled
```
