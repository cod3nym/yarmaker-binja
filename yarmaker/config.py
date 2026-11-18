"""YarMaker customization (counterpart of the globals in the IDA ``yarmaker.py``).

Meta and condition values can be strings or callables. Callables receive
arguments by name:

- ``bv``: the current ``BinaryView``
- ``count``: number of strings in the rule (conditions only); a single
  argument with any other name also receives the strings count
"""
from .types import Wildcard
from . import binja as utils


# rule parameters
WRAP_CURLY_BRACE = False        # wrap curly brace on a new line
INDENT_HEADERS = False          # indent for 'meta', 'strings', 'condition'

# editor default settings
DEFAULT_SHOW_COMMENTS = True    # show comments (checkbox)
DEFAULT_WILDCARD = (            # wildcarded instruction parts (dropdown)
    Wildcard.OFFSETS | Wildcard.DISPLACEMENTS
)
DEFAULT_ONELINER = False        # single line patterns without comments (checkbox)
DEFAULT_INDENT = 3              # default indent
DEFAULT_NAMED_VARIABLES = True  # use names for strings (variables)
DEFAULT_SHOW_TEMPLATE = False   # show full rule instead of strings only (checkbox)

# wildcard dropdown entries (label, mask), the default must be one of them
WILDCARD_MODES = [
    (
        'Exclude offsets + displacements + registers + constants',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS | Wildcard.REGISTERS | Wildcard.CONSTANTS,
    ),
    (
        'Exclude offsets + displacements + constants',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS | Wildcard.CONSTANTS,
    ),
    (
        'Exclude offsets + displacements + registers',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS | Wildcard.REGISTERS,
    ),
    (
        'Exclude offsets + displacements',
        Wildcard.OFFSETS | Wildcard.DISPLACEMENTS,
    ),
    ('Exclude offsets', Wildcard.OFFSETS),
    ('Exclude nothing (strict)', Wildcard.NONE),
]

# values can be string or callable (optional argument: bv)
DEFAULT_META_FIELDS = {
    'description': '',
    'source': 'Internal research',
    'date': lambda: utils.get_current_time('%Y-%m-%d'),
    'hash': lambda bv: utils.get_file_md5(bv),
    # 'hash': lambda bv: utils.get_file_sha256(bv),
}

# values can be string or callable (optional arguments: bv, count)
DEFAULT_CONDITIONS = [
    lambda bv: utils.get_file_type(bv) == 'PE' and 'uint16(0) == 0x5a4d',
    lambda bv: utils.get_file_type(bv) == 'ELF' and 'uint32(0) == 0x464c457f',
    lambda count: f'{count // 2} of them' if count > 2 else 'all of them',
]

# hunting ruleset ("Generate Ruleset for All Functions") filters
FUNCTIONS_MIN_SIZE = 40             # skip functions smaller than this (bytes)
FUNCTIONS_NAME_PREFIX = ''          # only functions whose name starts with this
FUNCTIONS_SKIP_MATCHED = False      # skip functions identified by WARP signatures
FUNCTION_BLOCK_MIN_SIZE = 16        # basic blocks smaller than this are not used

# default key bindings (can be changed in Edit > Preferences > Keybindings)
HOTKEY_RULE = 'Ctrl+Y'                  # rule from selection
HOTKEY_ALL_FUNCTIONS = 'Ctrl+Alt+Y'     # ruleset for all functions
