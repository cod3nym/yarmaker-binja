"""Tests for the x86 layout decoder and instruction wildcarding.

Pure Python, runs without Binary Ninja:

    python3 -m pytest tests/

The differential test compares the decoded layout against capstone
(``pip install capstone``) and is skipped when it is not installed.
"""
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from yarmaker import x86  # noqa: E402
from yarmaker.types import Instruction  # noqa: E402

from vectors import VECTORS, N, OFF, DEFAULT, REG, CONST  # noqa: E402


@pytest.mark.parametrize('bits,hexdata,wildcard,expected,has_operands', VECTORS)
def test_vectors(bits, hexdata, wildcard, expected, has_operands):
    insn = Instruction(0x1000, bytes.fromhex(hexdata), 'insn', bits=bits,
                       has_operands=has_operands)
    assert insn.layout is not None, 'layout not decoded'
    assert insn.escape(wildcard) == expected


def test_length_mismatch_falls_back_to_variant():
    # truncated data / disagreeing disassembler: no partial wildcarding
    insn = Instruction(0, bytes.fromhex('e8785634'), 'call', bits=32, variant=True)
    assert insn.layout is None
    assert insn.escape(OFF) == '?? ?? ?? ??'
    assert insn.escape(CONST) == 'e8 78 56 34'


def test_non_x86_variant():
    insn = Instruction(0, bytes.fromhex('94000010'), 'bl 0x40', bits=None, variant=True)
    assert insn.escape(OFF) == '?? ?? ?? ??'
    assert insn.escape(N) == '94 00 00 10'
    insn = Instruction(0, bytes.fromhex('d503201f'), 'nop', bits=None, variant=False)
    assert insn.escape(DEFAULT | REG | CONST) == 'd5 03 20 1f'


# --- differential test against capstone ---

def _capstone():
    try:
        import capstone
    except ImportError:
        return None
    modes = {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32, 64: capstone.CS_MODE_64}
    result = {}
    for bits, mode in modes.items():
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        md.detail = True
        result[bits] = md
    return result


def _expected_fields(insn):
    """Offsets of displacement and immediate fields according to capstone.

    Sizes are not compared: capstone derives disp_size from the operand size
    override (66 prefix); field sizes are covered by the length check
    """
    fields = set()
    if insn.disp_size:
        fields.add(insn.disp_offset)
    if insn.imm_size:
        fields.add(insn.imm_offset)
    return fields


def _random_instructions(rng, count):
    """Instruction-like byte strings biased towards common encodings"""
    prefixes = [b'', b'', b'', b'\x66', b'\x67', b'\xf3', b'\xf2', b'\x48', b'\x4c', b'\x66\x48']
    for _ in range(count):
        kind = rng.random()
        body = bytes(rng.randrange(256) for _ in range(14))
        if kind < 0.5:
            data = rng.choice(prefixes) + body
        elif kind < 0.8:
            data = rng.choice(prefixes) + b'\x0f' + body
        elif kind < 0.9:
            data = rng.choice(prefixes) + b'\x0f' + rng.choice([b'\x38', b'\x3a']) + body
        else:
            data = rng.choice([b'\xc5', b'\xc4', b'\x62', b'\x8f']) + body
        yield data[:15]


# capstone decodes some opcodes differently from the manuals (or Binary
# Ninja); these are excluded from the comparison
def _skip(insn, bits) -> bool:
    data = bytes(insn.bytes)
    i = 0
    while data[i] in x86.LEGACY_PREFIXES or (bits == 64 and 0x40 <= data[i] <= 0x4f):
        i += 1
    op = data[i:]
    if op[:1] in (b'\x62', b'\x8f', b'\xc4', b'\xc5') and op[:1] != data[:1]:
        return True     # VEX-like after prefixes is #UD
    if op[:2] in (b'\x0f\x0f',):
        return True     # 3DNow!: capstone reports the suffix as imm
    if op[:2] in (b'\x0f\x78', b'\x0f\x79'):
        return True     # extrq/insertq vs vmread/vmwrite
    if op[:2] in (b'\x0f\xb9', b'\x0f\xff'):
        return True     # ud1/ud0: capstone ignores their ModRM byte
    if bits == 64 and b'\x66' in data[:i] and (
            op[:1] in (b'\xe8', b'\xe9', b'\xc2') or (op[:1] == b'\x0f' and 0x80 <= op[1] <= 0x8f)):
        return True     # capstone: AMD rel16 branches / broken ret imm16 with 66+REX
    return False


@pytest.mark.parametrize('bits', [16, 32, 64])
def test_against_capstone(bits):
    disassemblers = _capstone()
    if disassemblers is None:
        pytest.skip('capstone not installed')
    md = disassemblers[bits]

    rng = random.Random(1337 + bits)
    checked = mismatches = 0
    failures = []
    for data in _random_instructions(rng, 40000):
        insn = next(md.disasm(data, 0x1000, 1), None)
        if insn is None or _skip(insn, bits):
            continue

        layout = x86.decode(data, bits)
        checked += 1
        problem = None
        if layout is None:
            problem = 'not decoded'
        elif layout.length != insn.size:
            problem = f'length {layout.length} != {insn.size}'
        else:
            actual = {f.offset for f in layout.fields}
            # capstone merges multiple immediates (enter, extrq) and
            # reports far pointers as two operands
            expected = _expected_fields(insn)
            if actual != expected and not (
                    len(actual) > 1 or insn.mnemonic.startswith(('ljmp', 'lcall'))):
                problem = f'fields {sorted(actual)} != {sorted(expected)}'
            elif insn.modrm_offset and layout.modrm is None and insn.size > insn.modrm_offset:
                problem = f'modrm missing (capstone {insn.modrm_offset})'

        if problem:
            mismatches += 1
            if len(failures) < 25:
                failures.append(f'{bytes(insn.bytes).hex()} {insn.mnemonic} {insn.op_str}: {problem}')

    assert checked > 10000
    assert not failures, f'{mismatches}/{checked} mismatches:\n' + '\n'.join(failures)
