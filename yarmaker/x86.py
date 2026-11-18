"""Minimal x86 / x86-64 instruction layout decoder.

Binary Ninja does not expose where operand data (displacement, immediate,
ModRM/SIB) sits inside an encoded instruction (IDA's ``op_t.offb``), so the
layout is recovered here. Only the encoding structure is decoded (prefixes,
opcode maps, ModRM, SIB, displacement and immediate sizes), not the semantics.

Pure Python, no Binary Ninja dependency (unit-testable outside of Binja).
"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .types import Wildcard


MAX_LENGTH = 15

LEGACY_PREFIXES = frozenset(
    {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
)

# immediate kinds
_B = 'b'            # imm8
_W = 'w'            # imm16
_Z = 'z'            # imm16/32 (operand size)
_V = 'v'            # imm16/32/64 (mov reg, imm)
_JB = 'jb'          # rel8 branch target
_JZ = 'jz'          # rel16/32 branch target
_AP = 'ap'          # far pointer seg:offset
_O = 'o'            # moffs (address size)
_ENTER = 'enter'    # imm16 + imm8
_GRP3 = 'grp3'      # F6/F7: immediate only for /0 and /1 (test)


def _one_byte_map():
    table = {}
    # ALU rows: add, or, adc, sbb, and, sub, xor, cmp
    for base in range(0x00, 0x40, 0x08):
        for i in range(4):
            table[base + i] = (True, None)
        table[base + 4] = (False, _B)
        table[base + 5] = (False, _Z)

    table.update({
        0x62: (True, None),     # bound (EVEX handled before the lookup)
        0x63: (True, None),     # arpl / movsxd
        0x68: (False, _Z),
        0x69: (True, _Z),
        0x6A: (False, _B),
        0x6B: (True, _B),
        0x80: (True, _B),
        0x81: (True, _Z),
        0x82: (True, _B),
        0x83: (True, _B),
        0x9A: (False, _AP),
        0xA8: (False, _B),
        0xA9: (False, _Z),
        0xC0: (True, _B),
        0xC1: (True, _B),
        0xC2: (False, _W),
        0xC4: (True, None),     # les (VEX handled before the lookup)
        0xC5: (True, None),     # lds (VEX handled before the lookup)
        0xC6: (True, _B),
        0xC7: (True, _Z),
        0xC8: (False, _ENTER),
        0xCA: (False, _W),
        0xCD: (False, _B),
        0xD4: (False, _B),
        0xD5: (False, _B),
        0xE8: (False, _JZ),
        0xE9: (False, _JZ),
        0xEA: (False, _AP),
        0xEB: (False, _JB),
        0xF6: (True, _GRP3),
        0xF7: (True, _GRP3),
        0xFE: (True, None),
        0xFF: (True, None),
    })
    for op in range(0x70, 0x80):
        table[op] = (False, _JB)
    for op in range(0x84, 0x90):
        table[op] = (True, None)
    for op in range(0xA0, 0xA4):
        table[op] = (False, _O)
    for op in range(0xB0, 0xB8):
        table[op] = (False, _B)
    for op in range(0xB8, 0xC0):
        table[op] = (False, _V)
    for op in (0xD0, 0xD1, 0xD2, 0xD3):
        table[op] = (True, None)
    for op in range(0xD8, 0xE0):
        table[op] = (True, None)    # x87
    for op in range(0xE0, 0xE4):
        table[op] = (False, _JB)    # loop*, jcxz
    for op in range(0xE4, 0xE8):
        table[op] = (False, _B)     # in/out imm8
    return table


def _two_byte_map():
    no_modrm = (
        set(range(0x04, 0x0D)) | {0x0E}
        | set(range(0x30, 0x40))
        | {0x77}
        | set(range(0x80, 0x90))
        | {0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA}
        | set(range(0xC8, 0xD0))
    )
    table = {op: (op not in no_modrm, None) for op in range(0x100)}
    for op in range(0x80, 0x90):
        table[op] = (False, _JZ)    # jcc rel16/32
    for op in (0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6):
        table[op] = (True, _B)
    return table


ONE_BYTE = _one_byte_map()
TWO_BYTE = _two_byte_map()

# opcodes of VEX/EVEX map 0F taking an imm8
VEX_0F_IMM8 = frozenset({0x70, 0x71, 0x72, 0x73, 0xC2, 0xC4, 0xC5, 0xC6})


@dataclass
class Field(object):
    """Operand data stored in the instruction bytes"""
    offset: int
    size: int
    kind: Wildcard

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass
class Layout(object):
    length: int
    modrm: Optional[int] = None         # ModRM byte offset
    sib: Optional[int] = None           # SIB byte offset
    fields: List[Field] = field(default_factory=list)

    def register_range(self) -> Optional[Tuple[int, int]]:
        """ModRM (and SIB) bytes, where x86 encodes operand registers"""
        if self.modrm is None:
            return None
        return self.modrm, self.modrm + 1 + (self.sib is not None)


class _Reader(object):
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def peek(self, offset: int = 0) -> int:
        index = self.pos + offset
        if index >= len(self.data) or index >= MAX_LENGTH:
            raise IndexError
        return self.data[index]

    def take(self) -> int:
        value = self.peek()
        self.pos += 1
        return value

    def skip(self, count: int) -> int:
        start = self.pos
        self.pos += count
        if self.pos > min(len(self.data), MAX_LENGTH):
            raise IndexError
        return start


def decode(data: bytes, bits: int) -> Optional[Layout]:
    """Decode the layout of the instruction at the start of ``data``.

    ``bits`` is the processor mode (16, 32 or 64). Returns None when the
    encoding is not understood or the data is truncated.
    """
    try:
        return _decode(_Reader(bytes(data)), bits)
    except IndexError:
        return None


def _decode(r: _Reader, bits: int) -> Optional[Layout]:
    prefixes = set()
    rex_w = False
    while True:
        byte = r.peek()
        if byte in LEGACY_PREFIXES:
            prefixes.add(byte)
            rex_w = False   # REX only counts right before the opcode
            r.take()
        elif bits == 64 and 0x40 <= byte <= 0x4F:
            rex_w = bool(byte & 0x08)
            r.take()
        else:
            break

    p66 = 0x66 in prefixes
    p67 = 0x67 in prefixes

    if bits == 64:
        opsize = 64 if rex_w else (16 if p66 else 32)
        addrsize = 32 if p67 else 64
    elif bits == 32:
        opsize = 16 if p66 else 32
        addrsize = 16 if p67 else 32
    else:
        opsize = 32 if p66 else 16
        addrsize = 32 if p67 else 16

    immz = 2 if opsize == 16 else 4
    layout = Layout(length=0)

    op = r.take()
    imm = None
    has_modrm = False
    force_register = False   # ModRM always encodes registers (mov cr/dr)
    suffix = 0               # 3DNow! opcode byte after the operand data

    def is_vex_like() -> bool:
        # outside 64-bit mode C4/C5/62 are les/lds/bound unless ModRM.mod == 3
        return bits == 64 or (r.peek() >> 6) == 3

    if op == 0x0F:
        op = r.take()
        if op == 0x38:
            r.take()
            has_modrm = True
        elif op == 0x3A:
            r.take()
            has_modrm, imm = True, _B
        elif op == 0x0F:
            has_modrm, suffix = True, 1
        else:
            has_modrm, imm = TWO_BYTE[op]
            if op in (0x20, 0x21, 0x22, 0x23, 0x24, 0x26):
                force_register = True
            elif op == 0x78 and (p66 or 0xF2 in prefixes):
                imm = 'extrq'   # extrq/insertq imm8, imm8

    elif op in (0xC4, 0xC5) and is_vex_like():
        if op == 0xC5:
            r.take()
            vex_map = 1
        else:
            vex_map = r.take() & 0x1F
            r.take()
        if vex_map not in (1, 2, 3):
            return None
        op = r.take()
        has_modrm = not (vex_map == 1 and op == 0x77)   # vzeroupper/all
        if vex_map == 3 or (vex_map == 1 and op in VEX_0F_IMM8):
            imm = _B

    elif op == 0x62 and is_vex_like():
        evex_map = r.take() & 0x07
        r.take()
        r.take()
        if evex_map not in (1, 2, 3, 5, 6):
            return None     # APX promoted legacy map (4) is not supported
        op = r.take()
        has_modrm = True
        if evex_map == 3 or (evex_map == 1 and op in VEX_0F_IMM8):
            imm = _B

    elif op == 0x8F and (r.peek() & 0x1F) >= 8:     # XOP, pop r/m otherwise
        xop_map = r.take() & 0x1F
        r.take()
        if xop_map not in (8, 9, 10):
            return None
        r.take()
        has_modrm = True
        imm = {8: _B, 9: None, 10: 'imm32'}[xop_map]

    else:
        has_modrm, imm = ONE_BYTE.get(op, (False, None))

    if has_modrm:
        modrm = r.take()
        layout.modrm = r.pos - 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7

        if mod != 3 and not force_register:
            if addrsize == 16:
                if mod == 0 and rm == 6:
                    layout.fields.append(Field(r.skip(2), 2, Wildcard.OFFSETS))
                elif mod == 1:
                    layout.fields.append(Field(r.skip(1), 1, Wildcard.DISPLACEMENTS))
                elif mod == 2:
                    layout.fields.append(Field(r.skip(2), 2, Wildcard.DISPLACEMENTS))
            else:
                base = rm
                if rm == 4:
                    base = r.take() & 7
                    layout.sib = r.pos - 1

                if mod == 0 and base == 5:
                    # absolute, RIP-relative or index-only address
                    layout.fields.append(Field(r.skip(4), 4, Wildcard.OFFSETS))
                elif mod == 1:
                    layout.fields.append(Field(r.skip(1), 1, Wildcard.DISPLACEMENTS))
                elif mod == 2:
                    layout.fields.append(Field(r.skip(4), 4, Wildcard.DISPLACEMENTS))

        if imm == _GRP3:
            imm = (_B if op == 0xF6 else _Z) if reg in (0, 1) else None
        elif op == 0xC7 and imm == _Z and modrm == 0xF8:
            imm = _JZ   # xbegin rel16/32 (only the one-byte map C7 takes imm z)

    _append_immediate(r, layout, imm, immz, opsize, addrsize, bits)

    if suffix:
        r.skip(suffix)

    layout.length = r.pos
    return layout


def _append_immediate(r, layout, imm, immz, opsize, addrsize, bits):
    if imm is None:
        return

    def add(size, kind):
        layout.fields.append(Field(r.skip(size), size, kind))

    if imm == _B:
        add(1, Wildcard.CONSTANTS)
    elif imm == _W:
        add(2, Wildcard.CONSTANTS)
    elif imm == _Z:
        add(immz, Wildcard.CONSTANTS)
    elif imm == _V:
        add(8 if opsize == 64 else immz, Wildcard.CONSTANTS)
    elif imm == 'imm32':
        add(4, Wildcard.CONSTANTS)
    elif imm == 'extrq':
        add(1, Wildcard.CONSTANTS)
        add(1, Wildcard.CONSTANTS)
    elif imm == _ENTER:
        add(2, Wildcard.CONSTANTS)
        add(1, Wildcard.CONSTANTS)
    elif imm == _JB:
        add(1, Wildcard.OFFSETS)
    elif imm == _JZ:
        # operand size override is ignored by near branches in 64-bit mode
        add(4 if bits == 64 else immz, Wildcard.OFFSETS)
    elif imm == _AP:
        add(immz + 2, Wildcard.OFFSETS)
    elif imm == _O:
        add(addrsize // 8, Wildcard.OFFSETS)
    else:
        raise ValueError(f'unknown immediate kind {imm}')
