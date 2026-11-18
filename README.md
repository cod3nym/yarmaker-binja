# YarMaker - create YARA signatures from selection

Binary Ninja plugin with no dependencies to easily create fine grained YARA
signatures by selecting a set of x86 instructions and choosing a wildcard mask.
Just select a chunk and press `Ctrl+Y` to create a YARA hex pattern.

Port of the [YarMaker IDA plugin](https://github.com/cod3nym/yarmaker).

### Features
- Make a rule from any entities (instructions, strings, raw bytes) in the selection
  of the **Linear**, **Graph** and **IL / Pseudo-C** views (`Ctrl+Y`); without a
  selection the item under the cursor is used
- Make a rule from strings picked in a searchable, multi-select **strings list**
- Make a "hunting" ruleset from functions picked in a searchable, multi-select
  **functions list**, or for the current function. Rules contain the basic blocks
  and the content of referenced data (strings, constants, etc...)
- Make a hunting ruleset for all non-library functions (`Ctrl+Alt+Y`), in a
  cancellable background task
- Fine-grained wildcarding of instructions: offsets, displacements, registers, constants
- YARA syntax highlighting (light and dark themes)
- Easy customization (see "[Customization](#customization)" section)

All commands are in the **Plugins > YarMaker** menu, the right-click menu
(**Plugins > YarMaker**) and the command palette (`Ctrl+P`).

| Command | Default key | IDA counterpart |
|---|---|---|
| Generate Rule from Selection | `Ctrl+Y` | Disassembly / Pseudocode action |
| Generate Rule from Strings... | | Strings window action |
| Generate Ruleset from Functions... | | Functions window action |
| Generate Ruleset for Current Function | | Functions window action (one function) |
| Generate Ruleset for All Functions | `Ctrl+Alt+Y` | plugin run (`Ctrl+Alt+Y`) |

Key bindings can be changed in **Edit > Preferences > Keybindings** (search "YarMaker").

### Wildcarding

| Mask | Wildcarded bytes (x86 / x86-64) |
|---|---|
| Offsets | branch targets, absolute / RIP-relative addresses, `moffs`, far pointers |
| Displacements | `[reg + disp]` displacements |
| Registers | ModRM and SIB bytes (only when the instruction has register / memory operands) |
| Constants | immediate values |

Binary Ninja does not expose where operand data is stored inside an
instruction encoding, so YarMaker decodes the x86 instruction layout itself
([yarmaker/x86.py](yarmaker/x86.py): prefixes, REX, VEX, EVEX, XOP, 3DNow!,
ModRM, SIB, displacement and immediate sizes). Binary Ninja's disassembly is
still used for the instruction boundaries, the operand tokens and the comments;
if the decoded length ever disagrees with Binary Ninja the instruction falls
back to the behavior below.

Other architectures have no byte level operand information: with the
**Offsets** mask, instructions that Binary Ninja's
[WARP](https://docs.binary.ninja/dev/annotation.html) analysis reports as
*variant* (location dependent: calls, branches, address references) are
wildcarded entirely (Binary Ninja 5.0+). Other masks are x86-only, like in the
IDA version.

### Installation

Copy this folder into your Binary Ninja user plugins directory
(**Plugins > Open Plugin Folder...**):
- **Windows**: `%APPDATA%\Binary Ninja\plugins\`
- **macOS**: `~/Library/Application Support/Binary Ninja/plugins/`
- **Linux**: `~/.binaryninja/plugins/`

Requires Binary Ninja 4.0 or newer (WARP based wildcarding for non-x86
architectures requires 5.0).

### Customization
You can customize the rules format to suit your needs.
To do this, edit the parameters in [yarmaker/config.py](yarmaker/config.py)
and restart Binary Ninja.

Rule style parameters:
- `WRAP_CURLY_BRACE` - wrap curly brace on a new line (default: `False`)
- `INDENT_HEADERS` - indent `meta`, `strings`, `condition` (default: `False`)

Rule editor default parameters (also editable in the editor window):
- `DEFAULT_SHOW_COMMENTS` - show comments (default: `True`)
- `DEFAULT_WILDCARD` - instruction parts replaced with `??`, any combination of
  `Wildcard.OFFSETS`, `Wildcard.DISPLACEMENTS`, `Wildcard.REGISTERS`, `Wildcard.CONSTANTS`
  (default: `Wildcard.OFFSETS | Wildcard.DISPLACEMENTS`). Selectable in the editor window
  via dropdown, entries are defined by `WILDCARD_MODES`
- `DEFAULT_ONELINER` - single line patterns without comments (default: `False`)
- `DEFAULT_INDENT` - rule indentation (default: `3`)
- `DEFAULT_NAMED_VARIABLES` - use names for strings (default: `True`)
- `DEFAULT_SHOW_TEMPLATE` - show the full rule (`meta`, `condition`) instead of
  only the generated strings (default: `False`)

Hunting ruleset parameters:
- `FUNCTIONS_MIN_SIZE`, `FUNCTIONS_NAME_PREFIX`, `FUNCTIONS_SKIP_MATCHED` (skip
  functions identified by WARP signatures), `FUNCTION_BLOCK_MIN_SIZE`

Default key bindings: `HOTKEY_RULE`, `HOTKEY_ALL_FUNCTIONS`.

Default fields in `meta` section. Values can be strings or callables; a callable
receives the current `BinaryView` if it has a `bv` argument:
```python
DEFAULT_META_FIELDS = {
    'company': 'Security Inc.',
    'date': lambda: str(date.today()),
    'hash': lambda bv: utils.get_file_sha256(bv),
}
```

Default fields in `condition` section. Values can be strings or callables with
the optional arguments `bv` (current `BinaryView`) and `count` (strings count):
```python
DEFAULT_CONDITIONS = [
    lambda bv: bv.view_type == 'PE' and 'uint16(0) == 0x5A4D',
    lambda count: f'{2 * count // 3} of them' if count > 2 else 'all of them',
]
```

> Note: installing or updating through the plugin manager overwrites
> `config.py`; keep a copy of your changes.

### License
YarMaker is licensed under the [GNU General Public License v3.0](LICENSE).

This project is a port of my IDA plugin [yarmaker](https://github.com/cod3nym/yarmaker) for Binary Ninja.

- Copyright (C) 2026 Jonathan Peters
