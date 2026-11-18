"""Plain data types for instructions and strings.

No Binary Ninja dependency: objects are built by ``yarmaker.binja`` and only
carry the data needed to generate patterns, so rules can be (re)built from
any thread without touching the analysis database.
"""
from enum import IntFlag
from typing import List, Optional, Tuple


class Wildcard(IntFlag):
    """Kinds of instruction parts replaced by wildcards in a pattern"""
    NONE = 0
    OFFSETS = 1         # branch targets and absolute/relative memory addresses
    DISPLACEMENTS = 2   # [reg + disp] displacements
    REGISTERS = 4       # register encoding (x86 only: ModRM/SIB bytes)
    CONSTANTS = 8       # immediate values


DEFAULT_WILDCARD = Wildcard.OFFSETS | Wildcard.DISPLACEMENTS

# Binary Ninja architecture names handled by the x86 layout decoder
X86_ARCHITECTURES = {
    'x86_16': 16,
    'x86': 32,
    'x86_64': 64,
}


class Instruction(object):
    def __init__(
            self,
            address: int,
            data: bytes,
            text: str,
            mnemonic: str = '',
            bits: Optional[int] = None,
            has_operands: bool = True,
            variant: bool = False):
        """
        :param address: instruction address
        :param data: instruction bytes
        :param text: disassembly line, used as comment
        :param mnemonic: instruction mnemonic
        :param bits: x86 processor mode (16/32/64), None for other architectures
        :param has_operands: instruction has register or memory operands
            (in the disassembly), guards ModRM bytes that only extend the opcode
        :param variant: instruction depends on its location (WARP analysis),
            used to wildcard whole instructions when no x86 layout is available
        """
        self.address = address
        self.data = bytes(data)
        self.text = text
        self.mnemonic = mnemonic or (text.split()[0] if text.split() else '')
        self.bits = bits
        self.has_operands = has_operands
        self.variant = variant
        self._layout = None
        self._layout_decoded = False

    def __eq__(self, other: "Instruction") -> bool:
        return str(self) == str(other)

    def __hash__(self) -> int:
        return hash(str(self))

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def bytes(self) -> bytes:
        return self.data

    @property
    def layout(self):
        """x86 encoding layout, None if unknown or not x86"""
        if not self._layout_decoded:
            self._layout_decoded = True
            if self.bits:
                from . import x86
                layout = x86.decode(self.data, self.bits)
                # never trust a layout disagreeing with the disassembler
                if layout is not None and layout.length == self.size:
                    self._layout = layout
        return self._layout

    def _ranges(self, wildcard: Wildcard) -> List[Tuple[int, int]]:
        layout = self.layout
        if layout is None:
            # no byte level information: wildcard the whole instruction
            # if its encoding depends on its location
            if wildcard & Wildcard.OFFSETS and self.variant:
                return [(0, self.size)]
            return []

        ranges = [(f.offset, f.end) for f in layout.fields if f.kind & wildcard]
        if wildcard & Wildcard.REGISTERS and self.has_operands:
            register_range = layout.register_range()
            if register_range:
                ranges.append(register_range)
        return ranges

    def escape(self, wildcard: Wildcard = DEFAULT_WILDCARD) -> str:
        data = self.data.hex(' ').split()
        for start, end in self._ranges(wildcard):
            data[start:end] = ['??'] * (end - start)
        return ' '.join(data)

    def comment(self, max_length: int = 48) -> str:
        comment = ' '.join(self.text.split())
        if len(comment) <= max_length:
            return comment

        return f'{comment[:max_length]}...'

    def __str__(self) -> str:
        return self.comment()

    def __repr__(self) -> str:
        return f'<Insn "{self}">'


class String(object):
    def __init__(self, ea: int, string: str, bytes_per_char: int = 1, size: Optional[int] = None):
        self.ea = ea
        self.string = string.decode() if hasattr(string, 'decode') else string
        self.bytes_per_char = bytes_per_char
        self._size = size

    def __eq__(self, other: "String") -> bool:
        return str(self) == str(other)

    def __hash__(self) -> int:
        return hash(str(self))

    def __str__(self) -> str:
        return self.string

    def __repr__(self) -> str:
        return f'<String "{str(self)}">'

    def __len__(self) -> int:
        return len(str(self))

    def __bool__(self) -> bool:
        return bool(self.string)

    @property
    def size(self) -> int:
        if self._size is not None:
            return self._size
        return len(self) * self.bytes_per_char

    @property
    def address(self) -> int:
        return self.ea
