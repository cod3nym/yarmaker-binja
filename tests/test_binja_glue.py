"""Smoke tests of the Binary Ninja glue against a fake BinaryView.

See ``fake_binaryninja.py``: checks the extraction / generation logic, not
the fidelity to Binary Ninja's analysis.
"""
import os
import sys

import pytest

pytest.importorskip('capstone')

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..'))

import fake_binaryninja  # noqa: E402

_saved = {k: sys.modules.get(k) for k in ('binaryninja', 'binaryninja.mainthread', 'binaryninja.plugin')}
bn = fake_binaryninja.install()

from yarmaker import binja as utils  # noqa: E402
from yarmaker import plugin  # noqa: E402
from yarmaker.types import Instruction, String, Wildcard  # noqa: E402

for _name, _module in _saved.items():   # do not leak the fake into other tests
    if _module is None:
        sys.modules.pop(_name, None)
    else:
        sys.modules[_name] = _module

BASE = 0x401000

CODE = bytes.fromhex(
    '55'            # 401000 push ebp
    '8bec'          # 401001 mov ebp, esp
    '6800204000'    # 401003 push 0x402000 (string)
    'e811000000'    # 401008 call 0x40101e
    '83c404'        # 40100d add esp, 4
    '8b4508'        # 401010 mov eax, [ebp+8]
    'a110204000'    # 401013 mov eax, [0x402010] (pointer to string)
    '5d'            # 401018 pop ebp
    'c3'            # 401019 ret
    '90909090'      # 40101a padding
    'c3'            # 40101e ret (small function)
)


def make_view():
    data = bytearray(0x2000)
    data[0:len(CODE)] = CODE
    data[0x1000:0x1000 + 15] = b'Hello YarMaker\x00'
    data[0x1010:0x1014] = (0x402020).to_bytes(4, 'little')         # pointer
    data[0x1020:0x1020 + 22] = 'wide text'.encode('utf-16le') + b'\x00' * 4
    bv = bn.BinaryView(BASE, data)
    bv.add_function(BASE, BASE + 0x1a, 'sub_401000')
    bv.add_function(BASE + 0x1e, BASE + 0x1f, 'sub_40101e')
    bv.add_string(0x402000, 14)
    bv.add_string(0x402020, 18, bn.StringType.Utf16String)
    bv.data_vars[0x402010] = bn.DataVariable(0x402010, bn.Type(bn.TypeClass.PointerTypeClass, 4))
    return bv


@pytest.fixture
def bv():
    return make_view()


def test_range_extractor(bv):
    entities = list(utils.RangeExtractor(bv, BASE, BASE + 0x1f))
    insns = [e for e in entities if isinstance(e, Instruction)]
    assert [i.address for i in insns][:3] == [0x401000, 0x401001, 0x401003]
    assert all(i.bits == 32 for i in insns)
    # padding is outside of the basic blocks: raw bytes
    assert [e for e in entities if isinstance(e, int)] == [0x90] * 4

    mov = next(i for i in insns if i.address == 0x401010)
    assert mov.escape(Wildcard.DISPLACEMENTS | Wildcard.REGISTERS) == '8b ?? ??'
    assert mov.comment() == 'mov eax, dword ptr [ebp + 8]'


def test_range_extractor_mid_instruction_and_strings(bv):
    entities = list(utils.RangeExtractor(bv, 0x401002, 0x401008))
    assert entities[0] == 0xec     # tail of mov ebp, esp
    assert isinstance(entities[1], Instruction) and entities[1].address == 0x401003

    entities = list(utils.RangeExtractor(bv, 0x402000, 0x402040))
    strings = [e for e in entities if isinstance(e, String)]
    assert [str(s) for s in strings] == ['Hello YarMaker', 'wide text']
    assert strings[1].bytes_per_char == 2


def test_item_range(bv):
    assert utils.get_item_range(bv, 0x401004) == (0x401003, 0x401008)
    assert utils.get_item_range(bv, 0x402003) == (0x402000, 0x40200e)
    assert utils.get_item_range(bv, 0x401f00) == (0x401f00, 0x401f01)


def test_function_extractor_follows_data_refs(bv):
    entities = list(utils.FunctionExtractor(bv, BASE))
    strings = [str(e) for e in entities if isinstance(e, String)]
    # direct reference and reference through a pointer
    assert strings == ['Hello YarMaker', 'wide text']
    # call target is code: no data
    assert not any(isinstance(e, int) for e in entities[:20] if e == 0xc3)


def test_rule_from_selection(bv):
    rule = plugin.rule_for_range(bv, BASE, BASE + 0x1a)
    rule.show_template = True
    text = rule.build()
    assert text.startswith('rule sample_exe_0x00401000 {')
    assert 'e8 ?? ?? ?? ??' in text and '8b 45 ??' in text
    assert 'a1 ?? ?? ?? ??' in text            # absolute address = offset
    assert 'uint16(0) == 0x5a4d' in text and 'ELF' not in text
    assert f'hash = "{utils.get_file_md5(bv)}"' in text


def test_ruleset_for_functions(bv):
    ruleset = plugin.ruleset_for_functions(bv, bv.functions)
    assert len(ruleset) == 1        # small function has no large block nor data
    ruleset.show_template = True
    text = ruleset.build()
    assert 'rule sub_401000' in text
    assert '"Hello YarMaker" fullword' in text and '"wide text" wide fullword' in text


def test_custom_functions_filters(bv):
    bv.add_function(0x401a00, 0x401a80, 'memcpy', symbol_type=bn.SymbolType.LibraryFunctionSymbol)
    bv.add_function(0x401b00, 0x401b80, 'big')
    names = [f.name for f in utils.get_custom_functions(bv, min_size=20)]
    assert names == ['sub_401000', 'big']


def test_commands_run_tasks(bv, monkeypatch):
    shown = []
    monkeypatch.setattr(plugin, 'show_rule', lambda rule: shown.append(rule))

    plugin.cmd_rule_from_selection(bv, 0x401004, 0)     # no selection: current item
    plugin.cmd_ruleset_for_function(bv, bv.functions[0])
    plugin.cmd_ruleset_for_all_functions(bv)
    assert len(shown) == 3
    assert '68 00 20 40 00' in shown[0].build().replace('?? ?? ?? ??', '00 20 40 00')
    assert all(not r.is_empty() for r in shown[1])
    assert plugin.rule_for_strings(bv, bv.strings).build().count('$op') == 2


def test_register_commands():
    plugin.register()
    names = [name for _, name, _ in bn.PluginCommand.commands]
    assert names == [
        plugin.CMD_RULE, plugin.CMD_STRINGS, plugin.CMD_FUNCTIONS,
        plugin.CMD_FUNCTION, plugin.CMD_ALL_FUNCTIONS,
    ]
