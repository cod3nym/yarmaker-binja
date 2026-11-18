"""Rule builder tests (pure Python, no Binary Ninja needed)"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from yarmaker.adapter import YaraExtractor  # noqa: E402
from yarmaker.types import Instruction, String, Wildcard  # noqa: E402
from yarmaker.wrappers import YaraBytes, YaraInstructions, YaraString  # noqa: E402
from yarmaker.yara import RuleBuilder, RulesetBuilder  # noqa: E402


def insn(hexdata, text, bits=32, address=0x1000):
    return Instruction(address, bytes.fromhex(hexdata), text, bits=bits)


ENTITIES = [
    insn('55', 'push ebp'),
    insn('8bec', 'mov ebp, esp'),
    insn('8b4508', 'mov eax, dword [ebp+0x8]'),
    String(0x2000, 'Hello, world', 1),
    String(0x3000, 'wide string', 2),
    *b'\x00\x01\x02\x03\x04\x05',
    insn('e878563412', 'call sub_401000'),
]


def test_extractor_groups_entities():
    entities = list(YaraExtractor(ENTITIES))
    assert [type(e) for e in entities] == [
        YaraInstructions, YaraString, YaraString, YaraBytes, YaraInstructions]
    assert entities[2].modifiers == ['wide', 'fullword']


def test_short_byte_runs_and_strings_are_dropped():
    entities = list(YaraExtractor([String(0, 'abc'), *b'\x00\x00\x01\x02\x00']))
    assert entities == []


def build_rule(**kwargs):
    rule = RuleBuilder('sample.exe_0x00401000', context={'bv': 'BV'}, **kwargs)
    rule.add_meta('description', '')
    rule.add_meta('view', lambda bv: f'view={bv}')
    rule.add_meta('date', lambda: '2026-01-01')
    for i, entity in enumerate(YaraExtractor(ENTITIES), start=1):
        rule.add_string(f'op{i}', entity)
    rule.add_condition(lambda bv: bv == 'BV' and 'uint16(0) == 0x5a4d')
    rule.add_condition(lambda bv: bv == 'other' and 'never')
    rule.add_condition(lambda count: f'{count // 2} of them' if count > 2 else 'all of them')
    rule.add_condition(lambda bv, count: f'#{count}')
    return rule


def test_full_rule():
    rule = build_rule(show_template=True, indent=2, indent_headers=False)
    text = rule.build()
    assert text.startswith('rule sample_exe_0x00401000 {\n')
    assert '  view = "view=BV"' in text
    assert '  date = "2026-01-01"' in text
    assert '$op1 = {\n' in text
    assert '8b 45 ??' in text and '// mov eax, dword [ebp+0x8]' in text
    assert '$op2 = "Hello, world" fullword' in text
    assert '$op3 = "wide string" wide fullword' in text
    assert '{ 00 01 02 03 04 05 }' in text
    assert '{ e8 ?? ?? ?? ?? }' in text
    assert 'uint16(0) == 0x5a4d\n  and 2 of them\n  and #5\n' in text
    assert 'never' not in text


def test_options():
    rule = build_rule(show_template=False)
    rule.wildcard = Wildcard.NONE
    rule.show_comments = False
    rule.use_named_variables = False
    text = rule.build()
    assert 'rule ' not in text
    assert '8b 45 08' in text and '//' not in text
    assert '$op' not in text and '$ = "Hello, world"' in text

    rule.oneliner = True
    assert '$ = { 55 8b ec 8b 45 08 }' in rule.build()


def test_ruleset_propagates_options():
    ruleset = RulesetBuilder([build_rule(), build_rule()])
    ruleset.use_named_variables = False
    ruleset.wildcard = Wildcard.NONE
    assert all(not r.use_named_variables and r.wildcard == Wildcard.NONE for r in ruleset)
    assert ruleset.build().count('$ = "Hello, world"') == 2
    assert 'no rules' in RulesetBuilder().build()


def test_invalid_callables():
    rule = RuleBuilder('name', context={'bv': None})
    with pytest.raises(TypeError):
        rule.add_meta('x', lambda unknown: '')
    with pytest.raises(TypeError):
        rule.add_condition(lambda a, b: '')
