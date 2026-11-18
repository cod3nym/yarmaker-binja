"""Binary Ninja data access: instructions, strings, functions, file info.

Port of ``extractor.py`` and ``utils.py`` of the IDA plugin.
"""
import hashlib
import os
from datetime import datetime
from typing import Dict, Generator, Iterable, List, Optional, Set, Union

import binaryninja as bn
from binaryninja import BinaryView, Function

from .types import Instruction, String, X86_ARCHITECTURES


def _warp_is_variant():
    """WARP ``is_instruction_variant`` (Binary Ninja 5.0+), None if unavailable.

    Imported lazily: WARP is a bundled plugin and may load after YarMaker
    """
    try:
        from binaryninja.warp import is_instruction_variant
        return is_instruction_variant
    except Exception:
        return None


# operand tokens: an instruction with any of these has register/memory operands
_OPERAND_TOKENS = {'RegisterToken', 'BeginMemoryOperandToken'}

_BYTES_PER_CHAR = {
    'AsciiString': 1,
    'Utf8String': 1,
    'Utf16String': 2,
    'Utf32String': 4,
}

_LIBRARY_SYMBOLS = {'LibraryFunctionSymbol', 'ImportedFunctionSymbol', 'ExternalSymbol'}


# --- file information ---

_hash_cache: Dict[tuple, str] = {}


def _file_hash(bv: BinaryView, algorithm: str) -> str:
    raw = bv.file.raw or bv
    key = (algorithm, bv.file.original_filename, raw.length)
    if key not in _hash_cache:
        digest = hashlib.new(algorithm)
        chunk = 0x100000
        for offset in range(raw.start, raw.start + raw.length, chunk):
            digest.update(raw.read(offset, chunk))
        _hash_cache[key] = digest.hexdigest()
    return _hash_cache[key]


def get_file_md5(bv: BinaryView) -> str:
    return _file_hash(bv, 'md5')


def get_file_sha256(bv: BinaryView) -> str:
    return _file_hash(bv, 'sha256')


def get_file_name(bv: BinaryView) -> str:
    project_file = getattr(bv, 'project_file', None)
    if project_file is not None:
        return project_file.name
    return os.path.basename(bv.file.original_filename or bv.file.filename)


def get_file_type(bv: BinaryView) -> str:
    """View type name: 'PE', 'ELF', 'Mach-O', 'Raw'..."""
    return bv.view_type


def get_current_time(format: str = '%Y-%m-%d') -> str:
    return datetime.now().strftime(format)


# --- address helpers ---

def is_loaded(bv: BinaryView, ea: int) -> bool:
    """Address is mapped and backed by data (not .bss-like)"""
    if not bv.is_valid_offset(ea):
        return False
    segment = bv.get_segment_at(ea)
    if segment is not None and ea >= segment.start + segment.data_length:
        return False
    return True


def get_item_range(bv: BinaryView, ea: int) -> tuple:
    """Range of the item (instruction, string, data variable, byte) at ``ea``"""
    for block in bv.get_basic_blocks_at(ea):
        found, start = block.get_instruction_containing_address(ea)
        if found:
            length = bv.get_instruction_length(start, block.arch) or 1
            return start, start + length

    string = bv.get_string_at(ea)
    if string is not None:
        return string.start, string.start + string.length

    var = bv.get_data_var_at(ea)
    if var is not None and var.type is not None and len(var.type) > 0:
        return var.address, var.address + len(var.type)

    return ea, ea + 1


def resolve_ptr_until_data(bv: BinaryView, ptr: int, max_depth: int = 3) -> int:
    """Follow data variables typed as pointers"""
    current = ptr
    for _ in range(max_depth):
        var = bv.get_data_var_at(current)
        if var is None or var.address != current or var.type is None:
            break
        if var.type.type_class != bn.TypeClass.PointerTypeClass:
            break
        try:
            current = bv.read_pointer(current)
        except Exception:
            break
    return current


def is_code(bv: BinaryView, ea: int) -> bool:
    return bool(bv.get_basic_blocks_at(ea)) or bv.get_function_at(ea) is not None


# --- entities ---

class _VariantCache(object):
    """Per function cache of instructions WARP considers location dependent"""

    def __init__(self):
        self._functions: Dict[int, Set[int]] = {}

    def is_variant(self, function: Optional[Function], address: int) -> bool:
        if function is None:
            return False

        if function.start not in self._functions:
            self._functions[function.start] = self._compute(function)
        return address in self._functions[function.start]

    @staticmethod
    def _compute(function: Function) -> Set[int]:
        variant = set()
        is_instruction_variant = _warp_is_variant()
        if is_instruction_variant is None:
            return variant
        try:
            il = function.lifted_il
            if il is None:
                return variant
            for insn in il.instructions:
                if insn.address not in variant and is_instruction_variant(il, insn):
                    variant.add(insn.address)
        except Exception as e:
            bn.log_debug(f'[YarMaker] WARP variant analysis failed: {e}')
        return variant


def instruction_from_bytes(
        arch: bn.Architecture,
        ea: int,
        data: bytes,
        text: Optional[str] = None,
        variant: bool = False) -> Optional[Instruction]:
    """Build an Instruction from raw bytes (``data`` may be longer than it)"""
    decoded = arch.get_instruction_text(data, ea)
    if not decoded or not decoded[1]:
        return None

    tokens, length = decoded
    data = bytes(data[:length])
    if len(data) != length:
        return None

    mnemonic = tokens[0].text.strip() if tokens else ''
    has_operands = any(token.type.name in _OPERAND_TOKENS for token in tokens)

    return Instruction(
        address=ea,
        data=data,
        text=text or ''.join(t.text for t in tokens),
        mnemonic=mnemonic,
        bits=X86_ARCHITECTURES.get(arch.name),
        has_operands=has_operands,
        variant=variant,
    )


def make_instruction(
        bv: BinaryView,
        ea: int,
        arch: Optional[bn.Architecture] = None,
        function: Optional[Function] = None,
        variants: Optional[_VariantCache] = None) -> Optional[Instruction]:
    arch = arch or bv.arch
    if arch is None:
        return None

    length = bv.get_instruction_length(ea, arch)
    if not length:
        return None

    data = bv.read(ea, length)
    variant = False
    if arch.name not in X86_ARCHITECTURES and variants is not None:
        variant = variants.is_variant(function, ea)

    return instruction_from_bytes(
        arch, ea, data, text=bv.get_disassembly(ea, arch), variant=variant)


def make_string(bv: BinaryView, ref: 'bn.StringReference') -> Optional[String]:
    try:
        value = ref.value
    except Exception:
        return None
    if not value:
        return None

    # discovered strings may include the terminator
    value = value.rstrip('\x00')
    bytes_per_char = _BYTES_PER_CHAR.get(ref.type.name, 1)
    return String(ref.start, value, bytes_per_char, size=ref.length)


def string_from_ea(bv: BinaryView, ea: int) -> Optional[String]:
    ref = bv.get_string_at(ea)
    if ref is None or ref.start != ea:
        return None
    return make_string(bv, ref)


# --- extractors ---

Entity = Union[int, String, Instruction]


class RangeExtractor(object):
    """Instructions, strings and raw bytes of an address range"""

    def __init__(self, bv: BinaryView, start: int, end: int, variants: Optional[_VariantCache] = None):
        self.bv = bv
        self.ea = start
        self.end = end
        self.variants = variants or _VariantCache()

    def _process_insn(self) -> Optional[Instruction]:
        for block in self.bv.get_basic_blocks_at(self.ea):
            found, start = block.get_instruction_containing_address(self.ea)
            if not found or start != self.ea:
                continue    # instruction tail: handled as raw byte

            entity = make_instruction(
                self.bv, self.ea, block.arch, block.function, self.variants)
            if entity is not None:
                self.ea += entity.size
                return entity
        return None

    def _process_string(self) -> Optional[String]:
        entity = string_from_ea(self.bv, self.ea)
        if entity is None:
            return None

        self.ea += max(entity.size, 1)
        return entity

    def _process_byte(self) -> Optional[int]:
        data = self.bv.read(self.ea, 1)
        self.ea += 1
        return data[0] if data else None

    def __iter__(self) -> Generator[Entity, None, None]:
        while self.ea < self.end:
            if not is_loaded(self.bv, self.ea):
                self.ea += 1
                continue

            insn = self._process_insn()
            if insn:
                yield insn
                continue

            string = self._process_string()
            if string:
                yield string
                continue

            byte = self._process_byte()
            if byte is not None:
                yield byte


class DataRefsExtractor(object):
    """Content of data referenced by an instruction (strings, constants...)"""

    def __init__(self, bv: BinaryView, ea: int, function: Optional[Function] = None,
                 arch: Optional[bn.Architecture] = None):
        self.bv = bv
        self.ea = ea
        self.function = function
        self.arch = arch

    @staticmethod
    def get_ref_data(bv: BinaryView, ea: int) -> Generator[Union[int, String], None, None]:
        _ea = resolve_ptr_until_data(bv, ea)

        entity = string_from_ea(bv, _ea)
        if entity:
            yield entity
        elif is_loaded(bv, _ea):
            yield from bv.read(_ea, 8)

    def refs(self) -> List[int]:
        try:
            refs = self.bv.get_code_refs_from(self.ea, self.function, self.arch)
        except Exception:
            refs = []
        # keep data references only (IDA DataRefsFrom)
        return [ref for ref in refs if not is_code(self.bv, ref)]

    def __iter__(self) -> Generator[Union[int, String], None, None]:
        for ref in self.refs():
            yield from self.get_ref_data(self.bv, ref)


class FunctionExtractor(object):
    """Instructions of large basic blocks and data referenced by a function"""

    def __init__(self, bv: BinaryView, function: Union[Function, int], block_min_size: int = 16):
        self.bv = bv
        if isinstance(function, int):
            function = bv.get_function_at(function)
        if function is None:
            raise ValueError('No function at given address')

        self.function = function
        self.block_min_size = block_min_size
        self.variants = _VariantCache()

    def __iter__(self) -> Generator[Entity, None, None]:
        blocks = sorted(self.function.basic_blocks, key=lambda b: b.start)

        for block in blocks:
            if block.length >= self.block_min_size:
                extractor = RangeExtractor(self.bv, block.start, block.end, self.variants)
                for entity in extractor:
                    if isinstance(entity, Instruction):
                        yield entity

            ea = block.start
            while ea < block.end:
                yield from DataRefsExtractor(self.bv, ea, self.function, block.arch)
                ea += self.bv.get_instruction_length(ea, block.arch) or 1


def get_custom_functions(
        bv: BinaryView,
        min_size: int = 40,
        prefix: str = '',
        skip_matched_functions: bool = False,
) -> Generator[Function, None, None]:
    """Functions worth a rule: no library, imported or thunk functions.

    ``skip_matched_functions`` also skips functions identified by WARP
    signatures (counterpart of IDA's Lumina functions)
    """
    for function in bv.functions:
        symbol = function.symbol
        if symbol is not None and symbol.type.name in _LIBRARY_SYMBOLS:
            continue

        try:
            if function.is_thunk:
                continue
        except Exception:
            pass

        if skip_matched_functions and is_warp_matched(function):
            continue

        if function.total_bytes < min_size:
            continue

        if prefix and not function.name.startswith(prefix):
            continue

        yield function


def is_warp_matched(function: Function) -> bool:
    try:
        from binaryninja.warp import WarpFunction
        return WarpFunction.get_matched(function) is not None
    except Exception:
        return False


def iter_strings(bv: BinaryView) -> Iterable['bn.StringReference']:
    return bv.get_strings()
