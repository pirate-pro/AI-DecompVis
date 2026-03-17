#!/usr/bin/env python3
from __future__ import annotations

import json
import struct
from pathlib import Path

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x140000000

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "samples" / "real_pe"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_x64_sample() -> bytes:
    headers_size = FILE_ALIGNMENT * 2
    # entry @ 0x1000, helper @ 0x1020
    code = bytes(
        [
            0x55,
            0x48,
            0x89,
            0xE5,
            0x48,
            0x83,
            0xEC,
            0x20,
            0x83,
            0xFF,
            0x00,
            0x74,
            0x07,
            0xE8,
            0x0E,
            0x00,
            0x00,
            0x00,
            0xEB,
            0x05,
            0xB8,
            0x00,
            0x00,
            0x00,
            0x00,
            0x48,
            0x83,
            0xC4,
            0x20,
            0x5D,
            0xC3,
            0x90,
            0x55,
            0x48,
            0x89,
            0xE5,
            0xB8,
            0x2A,
            0x00,
            0x00,
            0x00,
            0x5D,
            0xC3,
        ]
    )
    text_raw = code + b"\x90" * (FILE_ALIGNMENT - len(code))

    ascii_text = b"AI-DecompVis real PE sample\x00"
    utf16_text = "SampleUTF16".encode("utf-16le") + b"\x00\x00"
    rdata_raw = ascii_text + b"\x00" * 8 + utf16_text
    rdata_raw += b"\x00" * (FILE_ALIGNMENT - len(rdata_raw))

    headers = bytearray(headers_size)

    # DOS header
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)

    nt = 0x80
    headers[nt : nt + 4] = b"PE\x00\x00"

    file_header = nt + 4
    struct.pack_into("<H", headers, file_header + 0, 0x8664)  # Machine x64
    struct.pack_into("<H", headers, file_header + 2, 2)  # NumberOfSections
    struct.pack_into("<I", headers, file_header + 4, 0)
    struct.pack_into("<I", headers, file_header + 8, 0)
    struct.pack_into("<I", headers, file_header + 12, 0)
    struct.pack_into("<H", headers, file_header + 16, 0xF0)  # SizeOfOptionalHeader
    struct.pack_into("<H", headers, file_header + 18, 0x0022)  # Characteristics

    opt = file_header + 20
    struct.pack_into("<H", headers, opt + 0, 0x20B)  # PE32+
    struct.pack_into("<B", headers, opt + 2, 0)
    struct.pack_into("<B", headers, opt + 3, 0)
    struct.pack_into("<I", headers, opt + 4, align(len(code), FILE_ALIGNMENT))  # SizeOfCode
    struct.pack_into("<I", headers, opt + 8, align(len(rdata_raw), FILE_ALIGNMENT))  # SizeOfInitializedData
    struct.pack_into("<I", headers, opt + 12, 0)
    struct.pack_into("<I", headers, opt + 16, 0x1000)  # EntryPoint RVA
    struct.pack_into("<I", headers, opt + 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", headers, opt + 24, IMAGE_BASE)
    struct.pack_into("<I", headers, opt + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", headers, opt + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", headers, opt + 40, 6)
    struct.pack_into("<H", headers, opt + 42, 0)
    struct.pack_into("<H", headers, opt + 44, 0)
    struct.pack_into("<H", headers, opt + 46, 0)
    struct.pack_into("<H", headers, opt + 48, 6)
    struct.pack_into("<H", headers, opt + 50, 0)
    struct.pack_into("<I", headers, opt + 52, 0)
    struct.pack_into("<I", headers, opt + 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", headers, opt + 60, headers_size)  # SizeOfHeaders
    struct.pack_into("<I", headers, opt + 64, 0)
    struct.pack_into("<H", headers, opt + 68, 3)  # CUI
    struct.pack_into("<H", headers, opt + 70, 0)
    struct.pack_into("<Q", headers, opt + 72, 0x100000)
    struct.pack_into("<Q", headers, opt + 80, 0x1000)
    struct.pack_into("<Q", headers, opt + 88, 0x100000)
    struct.pack_into("<Q", headers, opt + 96, 0x1000)
    struct.pack_into("<I", headers, opt + 104, 0)
    struct.pack_into("<I", headers, opt + 108, 16)  # NumberOfRvaAndSizes
    # DataDirectory table remains zero => no imports/exports

    sect = opt + 0xF0
    # .text
    headers[sect : sect + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", headers, sect + 8, len(code))
    struct.pack_into("<I", headers, sect + 12, 0x1000)
    struct.pack_into("<I", headers, sect + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect + 20, headers_size)
    struct.pack_into("<I", headers, sect + 24, 0)
    struct.pack_into("<I", headers, sect + 28, 0)
    struct.pack_into("<H", headers, sect + 32, 0)
    struct.pack_into("<H", headers, sect + 34, 0)
    struct.pack_into("<I", headers, sect + 36, 0x60000020)

    # .rdata
    sect2 = sect + 40
    headers[sect2 : sect2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", headers, sect2 + 8, len(rdata_raw))
    struct.pack_into("<I", headers, sect2 + 12, 0x2000)
    struct.pack_into("<I", headers, sect2 + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect2 + 20, headers_size + FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect2 + 24, 0)
    struct.pack_into("<I", headers, sect2 + 28, 0)
    struct.pack_into("<H", headers, sect2 + 32, 0)
    struct.pack_into("<H", headers, sect2 + 34, 0)
    struct.pack_into("<I", headers, sect2 + 36, 0x40000040)

    return bytes(headers) + text_raw + rdata_raw


def build_switch_x64_sample() -> bytes:
    headers_size = FILE_ALIGNMENT * 2
    # entry @ 0x1000 with a jump-table-like indirect branch:
    # if (edi > 2) goto default;
    # goto table[edi];
    # default: return -1;
    table_target = IMAGE_BASE + 0x1016
    table = struct.pack("<QQQ", table_target, table_target, table_target)
    code = bytes(
        [
            0x55,  # push rbp
            0x48,
            0x89,
            0xE5,  # mov rbp, rsp
            0x83,
            0xFF,
            0x02,  # cmp edi, 2
            0x77,
            0x0D,  # ja 0x1016 (default)
            0x48,
            0x8D,
            0x05,
            0x0D,
            0x00,
            0x00,
            0x00,  # lea rax, [rip + 0x0d] -> table @ 0x101d
            0x48,
            0x63,
            0xFF,  # movsxd rdi, edi
            0xFF,
            0x24,
            0xF8,  # jmp qword ptr [rax + rdi*8]
            0xB8,
            0xFF,
            0xFF,
            0xFF,
            0xFF,  # default: mov eax, -1
            0x5D,  # pop rbp
            0xC3,  # ret
        ]
    ) + table
    text_raw = code + b"\x90" * (FILE_ALIGNMENT - len(code))

    ascii_text = b"switch-case-like sample\x00"
    utf16_text = "JumpTable".encode("utf-16le") + b"\x00\x00"
    rdata_raw = ascii_text + b"\x00" * 8 + utf16_text
    rdata_raw += b"\x00" * (FILE_ALIGNMENT - len(rdata_raw))

    headers = bytearray(headers_size)

    # DOS header
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)

    nt = 0x80
    headers[nt : nt + 4] = b"PE\x00\x00"

    file_header = nt + 4
    struct.pack_into("<H", headers, file_header + 0, 0x8664)  # Machine x64
    struct.pack_into("<H", headers, file_header + 2, 2)  # NumberOfSections
    struct.pack_into("<I", headers, file_header + 4, 0)
    struct.pack_into("<I", headers, file_header + 8, 0)
    struct.pack_into("<I", headers, file_header + 12, 0)
    struct.pack_into("<H", headers, file_header + 16, 0xF0)  # SizeOfOptionalHeader
    struct.pack_into("<H", headers, file_header + 18, 0x0022)  # Characteristics

    opt = file_header + 20
    struct.pack_into("<H", headers, opt + 0, 0x20B)  # PE32+
    struct.pack_into("<B", headers, opt + 2, 0)
    struct.pack_into("<B", headers, opt + 3, 0)
    struct.pack_into("<I", headers, opt + 4, align(len(code), FILE_ALIGNMENT))
    struct.pack_into("<I", headers, opt + 8, align(len(rdata_raw), FILE_ALIGNMENT))
    struct.pack_into("<I", headers, opt + 12, 0)
    struct.pack_into("<I", headers, opt + 16, 0x1000)  # EntryPoint RVA
    struct.pack_into("<I", headers, opt + 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", headers, opt + 24, IMAGE_BASE)
    struct.pack_into("<I", headers, opt + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", headers, opt + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", headers, opt + 40, 6)
    struct.pack_into("<H", headers, opt + 42, 0)
    struct.pack_into("<H", headers, opt + 44, 0)
    struct.pack_into("<H", headers, opt + 46, 0)
    struct.pack_into("<H", headers, opt + 48, 6)
    struct.pack_into("<H", headers, opt + 50, 0)
    struct.pack_into("<I", headers, opt + 52, 0)
    struct.pack_into("<I", headers, opt + 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", headers, opt + 60, headers_size)  # SizeOfHeaders
    struct.pack_into("<I", headers, opt + 64, 0)
    struct.pack_into("<H", headers, opt + 68, 3)  # CUI
    struct.pack_into("<H", headers, opt + 70, 0)
    struct.pack_into("<Q", headers, opt + 72, 0x100000)
    struct.pack_into("<Q", headers, opt + 80, 0x1000)
    struct.pack_into("<Q", headers, opt + 88, 0x100000)
    struct.pack_into("<Q", headers, opt + 96, 0x1000)
    struct.pack_into("<I", headers, opt + 104, 0)
    struct.pack_into("<I", headers, opt + 108, 16)  # NumberOfRvaAndSizes

    sect = opt + 0xF0
    # .text
    headers[sect : sect + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", headers, sect + 8, len(code))
    struct.pack_into("<I", headers, sect + 12, 0x1000)
    struct.pack_into("<I", headers, sect + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect + 20, headers_size)
    struct.pack_into("<I", headers, sect + 24, 0)
    struct.pack_into("<I", headers, sect + 28, 0)
    struct.pack_into("<H", headers, sect + 32, 0)
    struct.pack_into("<H", headers, sect + 34, 0)
    struct.pack_into("<I", headers, sect + 36, 0x60000020)

    # .rdata
    sect2 = sect + 40
    headers[sect2 : sect2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", headers, sect2 + 8, len(rdata_raw))
    struct.pack_into("<I", headers, sect2 + 12, 0x2000)
    struct.pack_into("<I", headers, sect2 + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect2 + 20, headers_size + FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect2 + 24, 0)
    struct.pack_into("<I", headers, sect2 + 28, 0)
    struct.pack_into("<H", headers, sect2 + 32, 0)
    struct.pack_into("<H", headers, sect2 + 34, 0)
    struct.pack_into("<I", headers, sect2 + 36, 0x40000040)

    return bytes(headers) + text_raw + rdata_raw


def build_unwind_x64_sample() -> bytes:
    code = bytes(
        [
            0x55,
            0x48,
            0x89,
            0xE5,
            0x48,
            0x83,
            0xEC,
            0x20,
            0x48,
            0x83,
            0xC4,
            0x20,
            0x5D,
            0xC3,
        ]
    )
    text_raw = code + b"\x90" * (FILE_ALIGNMENT - len(code))

    rdata_raw = b"unwind-aware sample\x00" + b"\x00" * (FILE_ALIGNMENT - len("unwind-aware sample\x00"))

    # IMAGE_RUNTIME_FUNCTION_ENTRY for one function
    pdata = struct.pack("<III", 0x1000, 0x1010, 0x4000) + b"\x00" * (FILE_ALIGNMENT - 12)

    # UNWIND_INFO: version=1 flags=0, prolog=4, unwind_codes=1
    xdata = bytes([0x01, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]) + b"\x00" * (FILE_ALIGNMENT - 8)

    headers = bytearray(FILE_ALIGNMENT * 2)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)

    nt = 0x80
    headers[nt : nt + 4] = b"PE\x00\x00"

    file_header = nt + 4
    struct.pack_into("<H", headers, file_header + 0, 0x8664)
    struct.pack_into("<H", headers, file_header + 2, 4)  # .text/.rdata/.pdata/.xdata
    struct.pack_into("<I", headers, file_header + 4, 0)
    struct.pack_into("<I", headers, file_header + 8, 0)
    struct.pack_into("<I", headers, file_header + 12, 0)
    struct.pack_into("<H", headers, file_header + 16, 0xF0)
    struct.pack_into("<H", headers, file_header + 18, 0x0022)

    opt = file_header + 20
    struct.pack_into("<H", headers, opt + 0, 0x20B)
    struct.pack_into("<B", headers, opt + 2, 0)
    struct.pack_into("<B", headers, opt + 3, 0)
    struct.pack_into("<I", headers, opt + 4, align(len(code), FILE_ALIGNMENT))
    struct.pack_into("<I", headers, opt + 8, align(len(rdata_raw), FILE_ALIGNMENT) + FILE_ALIGNMENT * 2)
    struct.pack_into("<I", headers, opt + 12, 0)
    struct.pack_into("<I", headers, opt + 16, 0x1000)
    struct.pack_into("<I", headers, opt + 20, 0x1000)
    struct.pack_into("<Q", headers, opt + 24, IMAGE_BASE)
    struct.pack_into("<I", headers, opt + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", headers, opt + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", headers, opt + 40, 6)
    struct.pack_into("<H", headers, opt + 42, 0)
    struct.pack_into("<H", headers, opt + 44, 0)
    struct.pack_into("<H", headers, opt + 46, 0)
    struct.pack_into("<H", headers, opt + 48, 6)
    struct.pack_into("<H", headers, opt + 50, 0)
    struct.pack_into("<I", headers, opt + 52, 0)
    struct.pack_into("<I", headers, opt + 56, 0x5000)
    struct.pack_into("<I", headers, opt + 60, FILE_ALIGNMENT * 2)
    struct.pack_into("<I", headers, opt + 64, 0)
    struct.pack_into("<H", headers, opt + 68, 3)
    struct.pack_into("<H", headers, opt + 70, 0)
    struct.pack_into("<Q", headers, opt + 72, 0x100000)
    struct.pack_into("<Q", headers, opt + 80, 0x1000)
    struct.pack_into("<Q", headers, opt + 88, 0x100000)
    struct.pack_into("<Q", headers, opt + 96, 0x1000)
    struct.pack_into("<I", headers, opt + 104, 0)
    struct.pack_into("<I", headers, opt + 108, 16)
    # Exception directory
    struct.pack_into("<I", headers, opt + 112 + 3 * 8, 0x3000)
    struct.pack_into("<I", headers, opt + 112 + 3 * 8 + 4, 12)

    sect = opt + 0xF0
    # .text
    headers[sect : sect + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", headers, sect + 8, len(code))
    struct.pack_into("<I", headers, sect + 12, 0x1000)
    struct.pack_into("<I", headers, sect + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect + 20, FILE_ALIGNMENT * 2)
    struct.pack_into("<I", headers, sect + 24, 0)
    struct.pack_into("<I", headers, sect + 28, 0)
    struct.pack_into("<H", headers, sect + 32, 0)
    struct.pack_into("<H", headers, sect + 34, 0)
    struct.pack_into("<I", headers, sect + 36, 0x60000020)

    # .rdata
    sect2 = sect + 40
    headers[sect2 : sect2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", headers, sect2 + 8, len(rdata_raw))
    struct.pack_into("<I", headers, sect2 + 12, 0x2000)
    struct.pack_into("<I", headers, sect2 + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect2 + 20, FILE_ALIGNMENT * 3)
    struct.pack_into("<I", headers, sect2 + 24, 0)
    struct.pack_into("<I", headers, sect2 + 28, 0)
    struct.pack_into("<H", headers, sect2 + 32, 0)
    struct.pack_into("<H", headers, sect2 + 34, 0)
    struct.pack_into("<I", headers, sect2 + 36, 0x40000040)

    # .pdata
    sect3 = sect2 + 40
    headers[sect3 : sect3 + 8] = b".pdata\x00\x00"
    struct.pack_into("<I", headers, sect3 + 8, 12)
    struct.pack_into("<I", headers, sect3 + 12, 0x3000)
    struct.pack_into("<I", headers, sect3 + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect3 + 20, FILE_ALIGNMENT * 4)
    struct.pack_into("<I", headers, sect3 + 24, 0)
    struct.pack_into("<I", headers, sect3 + 28, 0)
    struct.pack_into("<H", headers, sect3 + 32, 0)
    struct.pack_into("<H", headers, sect3 + 34, 0)
    struct.pack_into("<I", headers, sect3 + 36, 0x40000040)

    # .xdata
    sect4 = sect3 + 40
    headers[sect4 : sect4 + 8] = b".xdata\x00\x00"
    struct.pack_into("<I", headers, sect4 + 8, 8)
    struct.pack_into("<I", headers, sect4 + 12, 0x4000)
    struct.pack_into("<I", headers, sect4 + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect4 + 20, FILE_ALIGNMENT * 5)
    struct.pack_into("<I", headers, sect4 + 24, 0)
    struct.pack_into("<I", headers, sect4 + 28, 0)
    struct.pack_into("<H", headers, sect4 + 32, 0)
    struct.pack_into("<H", headers, sect4 + 34, 0)
    struct.pack_into("<I", headers, sect4 + 36, 0x40000040)

    return bytes(headers) + text_raw + rdata_raw + pdata + xdata


def build_cpp_like_x64_sample() -> bytes:
    code = bytes(
        [
            0x55,
            0x48,
            0x89,
            0xE5,  # push/mov frame
            0x48,
            0xC7,
            0x01,
            0x00,
            0x20,
            0x00,
            0x14,  # mov qword ptr [rcx], 0x14002000 (lower32)
            0xFF,
            0xD0,  # call rax (indirect)
            0x5D,
            0xC3,  # ret
        ]
    )
    text_raw = code + b"\x90" * (FILE_ALIGNMENT - len(code))

    vtable_entries = struct.pack("<QQQ", IMAGE_BASE + 0x1000, IMAGE_BASE + 0x1000, IMAGE_BASE + 0x1000)
    rdata_raw = b"cpp-like sample\x00" + b"\x00" * 8 + vtable_entries
    rdata_raw += b"\x00" * (FILE_ALIGNMENT - len(rdata_raw))

    headers = bytearray(FILE_ALIGNMENT * 2)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)

    nt = 0x80
    headers[nt : nt + 4] = b"PE\x00\x00"

    file_header = nt + 4
    struct.pack_into("<H", headers, file_header + 0, 0x8664)
    struct.pack_into("<H", headers, file_header + 2, 2)
    struct.pack_into("<I", headers, file_header + 4, 0)
    struct.pack_into("<I", headers, file_header + 8, 0)
    struct.pack_into("<I", headers, file_header + 12, 0)
    struct.pack_into("<H", headers, file_header + 16, 0xF0)
    struct.pack_into("<H", headers, file_header + 18, 0x0022)

    opt = file_header + 20
    struct.pack_into("<H", headers, opt + 0, 0x20B)
    struct.pack_into("<B", headers, opt + 2, 0)
    struct.pack_into("<B", headers, opt + 3, 0)
    struct.pack_into("<I", headers, opt + 4, align(len(code), FILE_ALIGNMENT))
    struct.pack_into("<I", headers, opt + 8, align(len(rdata_raw), FILE_ALIGNMENT))
    struct.pack_into("<I", headers, opt + 12, 0)
    struct.pack_into("<I", headers, opt + 16, 0x1000)
    struct.pack_into("<I", headers, opt + 20, 0x1000)
    struct.pack_into("<Q", headers, opt + 24, IMAGE_BASE)
    struct.pack_into("<I", headers, opt + 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", headers, opt + 36, FILE_ALIGNMENT)
    struct.pack_into("<H", headers, opt + 40, 6)
    struct.pack_into("<H", headers, opt + 42, 0)
    struct.pack_into("<H", headers, opt + 44, 0)
    struct.pack_into("<H", headers, opt + 46, 0)
    struct.pack_into("<H", headers, opt + 48, 6)
    struct.pack_into("<H", headers, opt + 50, 0)
    struct.pack_into("<I", headers, opt + 52, 0)
    struct.pack_into("<I", headers, opt + 56, 0x3000)
    struct.pack_into("<I", headers, opt + 60, FILE_ALIGNMENT * 2)
    struct.pack_into("<I", headers, opt + 64, 0)
    struct.pack_into("<H", headers, opt + 68, 3)
    struct.pack_into("<H", headers, opt + 70, 0)
    struct.pack_into("<Q", headers, opt + 72, 0x100000)
    struct.pack_into("<Q", headers, opt + 80, 0x1000)
    struct.pack_into("<Q", headers, opt + 88, 0x100000)
    struct.pack_into("<Q", headers, opt + 96, 0x1000)
    struct.pack_into("<I", headers, opt + 104, 0)
    struct.pack_into("<I", headers, opt + 108, 16)

    sect = opt + 0xF0
    headers[sect : sect + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", headers, sect + 8, len(code))
    struct.pack_into("<I", headers, sect + 12, 0x1000)
    struct.pack_into("<I", headers, sect + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect + 20, FILE_ALIGNMENT * 2)
    struct.pack_into("<I", headers, sect + 24, 0)
    struct.pack_into("<I", headers, sect + 28, 0)
    struct.pack_into("<H", headers, sect + 32, 0)
    struct.pack_into("<H", headers, sect + 34, 0)
    struct.pack_into("<I", headers, sect + 36, 0x60000020)

    sect2 = sect + 40
    headers[sect2 : sect2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", headers, sect2 + 8, len(rdata_raw))
    struct.pack_into("<I", headers, sect2 + 12, 0x2000)
    struct.pack_into("<I", headers, sect2 + 16, FILE_ALIGNMENT)
    struct.pack_into("<I", headers, sect2 + 20, FILE_ALIGNMENT * 3)
    struct.pack_into("<I", headers, sect2 + 24, 0)
    struct.pack_into("<I", headers, sect2 + 28, 0)
    struct.pack_into("<H", headers, sect2 + 32, 0)
    struct.pack_into("<H", headers, sect2 + 34, 0)
    struct.pack_into("<I", headers, sect2 + 36, 0x40000040)

    return bytes(headers) + text_raw + rdata_raw


if __name__ == "__main__":
    minimal_binary = build_x64_sample()
    minimal_path = OUT_DIR / "minimal_x64.exe"
    minimal_path.write_bytes(minimal_binary)

    minimal_meta = {
        "sample_id": "real_pe_minimal_x64",
        "arch": "x64",
        "kind": "real_pe",
        "file": "samples/real_pe/minimal_x64.exe",
        "description": "Public distributable minimal PE32+ sample generated for AI-DecompVis tests",
    }
    (OUT_DIR / "real_pe_minimal_x64.json").write_text(json.dumps(minimal_meta, indent=2), encoding="utf-8")

    switch_binary = build_switch_x64_sample()
    switch_path = OUT_DIR / "switch_x64.exe"
    switch_path.write_bytes(switch_binary)

    switch_meta = {
        "sample_id": "real_pe_switch_x64",
        "arch": "x64",
        "kind": "real_pe",
        "file": "samples/real_pe/switch_x64.exe",
        "description": "Public distributable PE32+ sample with an indirect jump-table-like dispatch",
    }
    (OUT_DIR / "real_pe_switch_x64.json").write_text(json.dumps(switch_meta, indent=2), encoding="utf-8")

    unwind_binary = build_unwind_x64_sample()
    unwind_path = OUT_DIR / "unwind_x64.exe"
    unwind_path.write_bytes(unwind_binary)
    unwind_meta = {
        "sample_id": "real_pe_unwind_x64",
        "arch": "x64",
        "kind": "real_pe",
        "file": "samples/real_pe/unwind_x64.exe",
        "description": "Public PE32+ sample with basic x64 unwind metadata (.pdata/.xdata)",
    }
    (OUT_DIR / "real_pe_unwind_x64.json").write_text(json.dumps(unwind_meta, indent=2), encoding="utf-8")

    cpp_binary = build_cpp_like_x64_sample()
    cpp_path = OUT_DIR / "cpp_like_x64.exe"
    cpp_path.write_bytes(cpp_binary)
    cpp_meta = {
        "sample_id": "real_pe_cpp_like_x64",
        "arch": "x64",
        "kind": "real_pe",
        "file": "samples/real_pe/cpp_like_x64.exe",
        "description": "Public PE32+ sample with this-pointer/object-like hints and vtable-like data",
    }
    (OUT_DIR / "real_pe_cpp_like_x64.json").write_text(json.dumps(cpp_meta, indent=2), encoding="utf-8")

    print(f"Generated: {minimal_path}")
    print(f"Generated: {switch_path}")
    print(f"Generated: {unwind_path}")
    print(f"Generated: {cpp_path}")
