"""x86 wildcard test vectors shared by the pytest suite and the Binja script"""
from yarmaker.types import Wildcard

N = Wildcard.NONE
OFF = Wildcard.OFFSETS
DISP = Wildcard.DISPLACEMENTS
REG = Wildcard.REGISTERS
CONST = Wildcard.CONSTANTS
DEFAULT = OFF | DISP

# (bits, hex bytes, wildcard, expected pattern, has register/memory operands)
# the first block is the IDA plugin test suite (tests/ida_test_x86_wildcard.py)
VECTORS = [
    # displacement / offset / constant wildcarding
    (32, '8b4508', DEFAULT, '8b 45 ??', True),                     # mov eax,[ebp+8]
    (32, '8b4508', N, '8b 45 08', True),
    (32, 'c745fc05000000', DEFAULT, 'c7 45 ?? 05 00 00 00', True),  # mov dword [ebp-4],5
    (32, 'c745fc05000000', DISP | CONST, 'c7 45 ?? ?? ?? ?? ??', True),
    (32, 'e878563412', DEFAULT, 'e8 ?? ?? ?? ??', False),          # call rel32
    (32, 'eb05', DEFAULT, 'eb ??', False),                         # jmp short
    (32, '8b048d78563412', DEFAULT, '8b 04 8d ?? ?? ?? ??', True),  # mov eax,[ecx*4+disp32]
    (64, '488b0510000000', DEFAULT, '48 8b 05 ?? ?? ?? ??', True),  # mov rax,[rip+0x10]

    # ModRM / SIB wildcarding
    (32, '89d8', DEFAULT | REG, '89 ??', True),                     # mov eax,ebx
    (32, '89d8', DEFAULT, '89 d8', True),
    (32, '8b4508', DISP | REG, '8b ?? ??', True),                   # mov eax,[ebp+8]
    (32, '8b048d78563412', DEFAULT | REG, '8b ?? ?? ?? ?? ?? ??', True),
    (64, '488b0510000000', DEFAULT | REG, '48 8b ?? ?? ?? ?? ??', True),

    # non-GPR register operands
    (32, '0f28c1', REG, '0f 28 ??', True),                          # movaps xmm0,xmm1
    (32, '0f2800', REG, '0f 28 ??', True),                          # movaps xmm0,[eax]
    (32, '0fefc1', REG, '0f ef ??', True),                          # pxor mm0,mm1
    (32, 'd9c9', REG, 'd9 ??', True),                               # fxch st(1)
    (32, '0f20c0', REG, '0f 20 ??', True),                          # mov eax,cr0

    # no ModRM: must stay untouched
    (32, '50', REG, '50', True),                                    # push eax
    (32, 'b878563412', DEFAULT | REG, 'b8 78 56 34 12', True),      # mov eax,imm32
    (32, 'f3a4', DEFAULT | REG, 'f3 a4', True),                     # rep movsb

    # 3DNow! suffix opcode byte must be kept
    (32, '0f0fc19e', REG, '0f 0f ?? 9e', True),                     # pfadd mm0,mm1
    (32, '0f0f40089e', DEFAULT, '0f 0f 40 ?? 9e', True),            # pfadd mm0,[eax+8]
    (32, '0f0f40089e', DISP | REG, '0f 0f ?? ?? 9e', True),

    # --- additional vectors ---
    # opcode-only ModRM (no register operand in the disassembly) is kept
    (64, 'f30f1efa', REG, 'f3 0f 1e fa', False),                    # endbr64
    (64, '0faee8', REG, '0f ae e8', False),                         # lfence
    (32, 'd9e8', REG, 'd9 e8', False),                              # fld1
    # absolute memory / moffs / far pointers are offsets
    (32, 'a178563412', OFF, 'a1 ?? ?? ?? ??', True),                # mov eax,[moffs32]
    (64, '48a1efcdab8967452301', OFF, '48 a1 ?? ?? ?? ?? ?? ?? ?? ??', True),
    (32, 'ff1578563412', OFF, 'ff 15 ?? ?? ?? ??', True),           # call [abs32]
    (32, 'ff1578563412', DISP, 'ff 15 78 56 34 12', True),
    (32, '9a785634120800', OFF, '9a ?? ?? ?? ?? ?? ??', False),     # call far
    # rel32 branches ignore 66 in 64-bit mode
    (64, '0f8410000000', OFF, '0f 84 ?? ?? ?? ??', False),          # jz rel32
    (64, '66e810000000', OFF, '66 e8 ?? ?? ?? ??', False),
    # immediates
    (64, '48b8efcdab8967452301', CONST, '48 b8 ?? ?? ?? ?? ?? ?? ?? ??', True),  # mov rax,imm64
    (32, '66b83412', CONST, '66 b8 ?? ??', True),                   # mov ax,imm16
    (32, '6878563412', CONST, '68 ?? ?? ?? ??', False),             # push imm32
    (32, 'c8100001', CONST, 'c8 ?? ?? ??', False),                  # enter 0x10,1
    (32, 'c21000', CONST, 'c2 ?? ??', False),                       # ret 0x10
    (32, 'f6c101', CONST, 'f6 c1 ??', True),                        # test cl,1
    (32, 'f6d1', CONST, 'f6 d1', True),                             # not cl
    (32, 'f7c178563412', CONST | REG, 'f7 ?? ?? ?? ?? ??', True),   # test ecx,imm32
    (32, '837d0805', DISP | CONST, '83 7d ?? ??', True),            # cmp [ebp+8],5
    (64, '4881ec88000000', CONST, '48 81 ec ?? ?? ?? ??', True),    # sub rsp,0x88
    # SIB with displacement
    (64, '488b4c2410', DISP | REG, '48 8b ?? ?? ??', True),         # mov rcx,[rsp+0x10]
    (64, '488b8c2410010000', DISP, '48 8b 8c 24 ?? ?? ?? ??', True),
    # 16-bit addressing
    (16, '8b4608', DISP, '8b 46 ??', True),                         # mov ax,[bp+8]
    (16, 'a13412', OFF, 'a1 ?? ??', True),                          # mov ax,[moffs16]
    (16, '8b1e3412', OFF, '8b 1e ?? ??', True),                     # mov bx,[0x1234]
    (16, 'e81000', OFF, 'e8 ?? ??', False),                         # call rel16
    # SSE / VEX / EVEX
    (64, '660f70c11b', CONST, '66 0f 70 c1 ??', True),              # pshufd xmm0,xmm1,0x1b
    (64, '660f3a0fc108', CONST, '66 0f 3a 0f c1 ??', True),         # palignr
    (64, 'c5f8104510', DISP | REG, 'c5 f8 10 ?? ??', True),         # vmovups xmm0,[rbp+0x10]
    (64, 'c4e37d18c101', CONST, 'c4 e3 7d 18 c1 ??', True),         # vinsertf128
    (64, 'c5f877', REG, 'c5 f8 77', False),                         # vzeroupper
    (64, '62f17c48104508', DISP, '62 f1 7c 48 10 45 ??', True),     # vmovups zmm0,[rbp+0x200]
    (32, 'c5f8104510', DISP, 'c5 f8 10 45 ??', True),               # VEX in 32-bit mode
    (32, 'c4450c', DISP, 'c4 45 ??', True),                         # les eax,[ebp+0xc]
]
