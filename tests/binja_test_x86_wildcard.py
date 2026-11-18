"""YarMaker checks to run inside Binary Ninja (counterpart of the IDA test).

Run from the Binary Ninja UI with File > Run Script... (uses the current
``bv`` if one is open), or headless (needs a headless capable license):

    python3 tests/binja_test_x86_wildcard.py [x86 binary]

1. Wildcard vectors: each vector is decoded by Binary Ninja's x86/x86_64
   architecture and wildcarded by YarMaker.
2. Decoder cross-check: when a binary is available, every x86 instruction
   of every function is decoded by both Binary Ninja and the YarMaker x86
   layout decoder and the lengths are compared (a mismatch makes YarMaker
   fall back to whole instruction wildcarding for that instruction).
3. Rule generation for a few functions and the strings (end to end).
"""
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
for path in (HERE, os.path.join(HERE, '..')):
    if path not in sys.path:
        sys.path.insert(0, path)

# test this checkout, not a previously imported copy
for name in [m for m in sys.modules if m in ('yarmaker', 'vectors') or m.startswith('yarmaker.')]:
    del sys.modules[name]

import binaryninja as bn  # noqa: E402

from yarmaker import binja as utils  # noqa: E402
from yarmaker import x86  # noqa: E402
from yarmaker.types import X86_ARCHITECTURES  # noqa: E402
from vectors import VECTORS  # noqa: E402

ARCHITECTURES = {16: 'x86_16', 32: 'x86', 64: 'x86_64'}


def architecture(bits):
    try:
        return bn.Architecture[ARCHITECTURES[bits]]
    except (KeyError, Exception):
        return None


def test_vectors() -> int:
    failures = 0
    for bits, hexdata, wildcard, expected, has_operands in VECTORS:
        arch = architecture(bits)
        if arch is None:
            print(f'skip x{bits} {hexdata} (no {ARCHITECTURES[bits]} architecture)')
            continue

        data = bytes.fromhex(hexdata)
        try:
            insn = utils.instruction_from_bytes(arch, 0x1000, data + b'\x90' * 16)
            if insn is None:
                raise RuntimeError('Binary Ninja cannot decode it')
            if insn.size != len(data):
                raise RuntimeError(f'Binary Ninja length {insn.size} != {len(data)}')
            actual = insn.escape(wildcard)
        except Exception as e:
            actual = f'error: {e}'
            insn = None

        notes = []
        if insn is not None and insn.has_operands != has_operands:
            notes.append(f'operand tokens: {insn.has_operands} (expected {has_operands})')
        ok = actual == expected
        failures += not ok
        text = insn.text if insn is not None else ''
        print(f"{'ok  ' if ok else 'FAIL'} x{bits} {hexdata:<20} {wildcard!r:<40} -> {actual}"
              + ('' if ok else f'   (expected {expected})')
              + f'   [{text}]' + (f'   ({"; ".join(notes)})' if notes else ''))
    return failures


def check_decoder(bv, limit: int = 2_000_000) -> int:
    """Compare instruction lengths of Binary Ninja and the x86 layout decoder"""
    checked = 0
    mismatches = []
    for function in bv.functions:
        bits = X86_ARCHITECTURES.get(function.arch.name)
        if bits is None:
            continue
        for block in function.basic_blocks:
            ea = block.start
            while ea < block.end and checked < limit:
                length = bv.get_instruction_length(ea, block.arch)
                if not length:
                    break
                data = bv.read(ea, length)
                layout = x86.decode(data, bits)
                checked += 1
                if layout is None or layout.length != length:
                    mismatches.append((ea, data.hex(), bv.get_disassembly(ea, block.arch),
                                       None if layout is None else layout.length))
                ea += length

    print(f'\ndecoder cross-check: {checked} instructions, {len(mismatches)} length mismatches')
    for ea, data, text, length in mismatches[:30]:
        print(f'  0x{ea:x} {data:<30} {text!s:<40} yarmaker length: {length}')
    return len(mismatches)


def check_generation(bv) -> int:
    from yarmaker import plugin

    failures = 0
    try:
        functions = list(utils.get_custom_functions(bv))[:5]
        ruleset = plugin.ruleset_for_functions(bv, functions)
        ruleset.show_template = True
        text = ruleset.build()
        print(f'\nruleset for {len(functions)} functions ({len(ruleset)} rules):')
        print(text[:3000] + ('\n...' if len(text) > 3000 else ''))

        if functions:
            block = max(functions[0].basic_blocks, key=lambda b: b.length)
            rule = plugin.rule_for_range(bv, block.start, block.end)
            print(f'\nrule for 0x{block.start:x}-0x{block.end:x}:')
            print(rule.build())

        strings = list(utils.iter_strings(bv))[:5]
        print('\nrule for strings:')
        print(plugin.rule_for_strings(bv, strings).build())
    except Exception:
        traceback.print_exc()
        failures += 1
    return failures


def main(bv=None) -> int:
    failures = test_vectors()
    if bv is not None:
        mismatches = check_decoder(bv)
        failures += check_generation(bv)
        if mismatches:
            print(f'NOTE: {mismatches} decoder length mismatches '
                  '(those instructions fall back to whole instruction wildcarding)')
    print(f'\n{"all tests passed" if not failures else f"{failures} FAILED"}')
    return int(bool(failures))


if __name__ == '__main__' or 'bv' in globals():
    view = globals().get('bv')     # Binary Ninja UI: File > Run Script...
    if view is None and len(sys.argv) > 1:
        with bn.load(sys.argv[1]) as view:
            sys.exit(main(view))
    code = main(view)
    if view is None and len(sys.argv) > 1:
        sys.exit(code)
