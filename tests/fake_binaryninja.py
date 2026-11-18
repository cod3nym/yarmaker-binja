"""Very small stand-in for the ``binaryninja`` module (x86 via capstone).

Only covers the API surface used by ``yarmaker.binja`` / ``yarmaker.plugin``
so their logic can be smoke tested without Binary Ninja. It mirrors the real
API signatures but obviously not its analysis: it is no substitute for
``tests/binja_test_x86_wildcard.py`` run inside Binja.
"""
import enum
import sys
import types

import capstone


class TypeClass(enum.Enum):
    IntegerTypeClass = 2
    ArrayTypeClass = 7
    PointerTypeClass = 8


class StringType(enum.Enum):
    AsciiString = 0
    Utf16String = 1
    Utf32String = 2
    Utf8String = 3


class TokenType(enum.Enum):
    TextToken = 0
    InstructionToken = 1
    RegisterToken = 5
    BeginMemoryOperandToken = 8
    PossibleAddressToken = 9


class SymbolType(enum.Enum):
    FunctionSymbol = 0
    ImportedFunctionSymbol = 2
    LibraryFunctionSymbol = 7


class MessageBoxIcon(enum.Enum):
    ErrorIcon = 3


class Token(object):
    def __init__(self, text, type):
        self.text = text
        self.type = type


class Architecture(object):
    def __init__(self, name, mode):
        self.name = name
        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.md.detail = True

    def decode(self, data, addr):
        return next(self.md.disasm(bytes(data), addr, 1), None)

    def get_instruction_text(self, data, addr):
        insn = self.decode(data, addr)
        if insn is None:
            return None
        tokens = [Token(insn.mnemonic, TokenType.InstructionToken)]
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_REG:
                tokens.append(Token(insn.reg_name(op.reg), TokenType.RegisterToken))
            elif op.type == capstone.x86.X86_OP_MEM:
                tokens.append(Token('[', TokenType.BeginMemoryOperandToken))
            else:
                tokens.append(Token(hex(op.imm), TokenType.PossibleAddressToken))
        return tokens, insn.size


class Symbol(object):
    def __init__(self, name, type=SymbolType.FunctionSymbol):
        self.name = name
        self.type = type


class Type(object):
    def __init__(self, type_class, width):
        self.type_class = type_class
        self.width = width

    def __len__(self):
        return self.width


class DataVariable(object):
    def __init__(self, address, type):
        self.address = address
        self.type = type


class StringReference(object):
    def __init__(self, view, type, start, length):
        self._view = view
        self.type = type
        self.start = start
        self.length = length

    @property
    def value(self):
        encoding = {StringType.Utf16String: 'utf-16le'}.get(self.type, 'utf-8')
        return self._view.read(self.start, self.length).decode(encoding)


class BasicBlock(object):
    def __init__(self, function, start, end):
        self.function = function
        self.start = start
        self.end = end
        self.arch = function.arch

    @property
    def length(self):
        return self.end - self.start

    def get_instruction_containing_address(self, addr):
        ea = self.start
        while ea < self.end:
            size = self.function.view.get_instruction_length(ea, self.arch)
            if ea <= addr < ea + size:
                return True, ea
            ea += size
        return False, 0


class Function(object):
    def __init__(self, view, start, end, name, symbol_type=SymbolType.FunctionSymbol):
        self.view = view
        self.start = start
        self.arch = view.arch
        self.name = name
        self.symbol = Symbol(name, symbol_type)
        self.basic_blocks = [BasicBlock(self, start, end)]
        self.is_thunk = False
        self.lifted_il = None

    @property
    def total_bytes(self):
        return sum(b.length for b in self.basic_blocks)


class FileMetadata(object):
    def __init__(self, view, filename):
        self.raw = view
        self.original_filename = filename
        self.filename = filename


class BinaryView(object):
    def __init__(self, base, data, view_type='PE', arch='x86'):
        self.start = base
        self.data = bytes(data)
        self.view_type = view_type
        modes = {'x86': capstone.CS_MODE_32, 'x86_64': capstone.CS_MODE_64}
        self.arch = Architecture(arch, modes[arch])
        self.file = FileMetadata(self, '/samples/sample.exe')
        self.functions = []
        self.strings = []
        self.data_vars = {}
        self.project_file = None

    @property
    def length(self):
        return len(self.data)

    @property
    def end(self):
        return self.start + len(self.data)

    def add_function(self, start, end, name, **kwargs):
        function = Function(self, start, end, name, **kwargs)
        self.functions.append(function)
        return function

    def read(self, addr, length):
        if not self.is_valid_offset(addr):
            return b''
        return self.data[addr - self.start:addr - self.start + length]

    def read_pointer(self, addr, size=None):
        return int.from_bytes(self.read(addr, 4), 'little')

    def is_valid_offset(self, addr):
        return self.start <= addr < self.end

    def get_segment_at(self, addr):
        return None

    def get_basic_blocks_at(self, addr):
        return [b for f in self.functions for b in f.basic_blocks if b.start <= addr < b.end]

    def get_function_at(self, addr):
        return next((f for f in self.functions if f.start == addr), None)

    def get_instruction_length(self, addr, arch=None):
        insn = self.arch.decode(self.read(addr, 16), addr)
        return insn.size if insn else 0

    def get_disassembly(self, addr, arch=None):
        insn = self.arch.decode(self.read(addr, 16), addr)
        return f'{insn.mnemonic} {insn.op_str}'.strip() if insn else None

    def get_code_refs_from(self, addr, func=None, arch=None, length=None):
        insn = self.arch.decode(self.read(addr, 16), addr)
        refs = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM and self.is_valid_offset(op.imm):
                refs.append(op.imm)
            elif op.type == capstone.x86.X86_OP_MEM and not op.mem.base and self.is_valid_offset(op.mem.disp):
                refs.append(op.mem.disp)
        return refs

    def add_string(self, addr, length, type=StringType.AsciiString):
        self.strings.append(StringReference(self, type, addr, length))

    def get_string_at(self, addr, partial=False):
        return next((s for s in self.strings if s.start <= addr < s.start + s.length), None)

    def get_strings(self, start=None, length=None):
        return list(self.strings)

    def get_data_var_at(self, addr):
        return self.data_vars.get(addr)


class PluginCommand(object):
    commands = []

    @classmethod
    def _add(cls, kind, name, description, action, is_valid=None):
        cls.commands.append((kind, name, action))

    @classmethod
    def register(cls, *args):
        cls._add('view', *args)

    @classmethod
    def register_for_range(cls, *args):
        cls._add('range', *args)

    @classmethod
    def register_for_function(cls, *args):
        cls._add('function', *args)


class BackgroundTaskThread(object):
    def __init__(self, initial_progress_text='', can_cancel=False):
        self.progress = initial_progress_text
        self.cancelled = False

    def start(self):
        self.run()


logs = []


def install():
    """Register the fake modules in sys.modules"""
    module = types.ModuleType('binaryninja')
    for name, value in dict(
        TypeClass=TypeClass, StringType=StringType, BinaryView=BinaryView,
        Function=Function, Architecture=Architecture, PluginCommand=PluginCommand,
        DataVariable=DataVariable, Type=Type, SymbolType=SymbolType,
        StringReference=StringReference, MessageBoxIcon=MessageBoxIcon,
        log_info=lambda msg, *a: logs.append(('info', msg)),
        log_error=lambda msg, *a: logs.append(('error', msg)),
        log_debug=lambda msg, *a: logs.append(('debug', msg)),
        show_message_box=lambda *a, **k: logs.append(('box', a)),
    ).items():
        setattr(module, name, value)

    mainthread = types.ModuleType('binaryninja.mainthread')
    mainthread.is_main_thread = lambda: True
    mainthread.execute_on_main_thread = lambda func: func()
    plugin = types.ModuleType('binaryninja.plugin')
    plugin.BackgroundTaskThread = BackgroundTaskThread

    module.mainthread = mainthread
    module.plugin = plugin
    sys.modules['binaryninja'] = module
    sys.modules['binaryninja.mainthread'] = mainthread
    sys.modules['binaryninja.plugin'] = plugin
    return module
