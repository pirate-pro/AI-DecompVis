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

    headers = bytearray(FILE_ALIGNMENT)

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
    struct.pack_into("<I", headers, opt + 60, FILE_ALIGNMENT)  # SizeOfHeaders
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
    struct.pack_into("<I", headers, sect + 20, FILE_ALIGNMENT)
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
    struct.pack_into("<I", headers, sect2 + 20, FILE_ALIGNMENT * 2)
    struct.pack_into("<I", headers, sect2 + 24, 0)
    struct.pack_into("<I", headers, sect2 + 28, 0)
    struct.pack_into("<H", headers, sect2 + 32, 0)
    struct.pack_into("<H", headers, sect2 + 34, 0)
    struct.pack_into("<I", headers, sect2 + 36, 0x40000040)

    return bytes(headers) + text_raw + rdata_raw


if __name__ == "__main__":
    binary = build_x64_sample()
    exe_path = OUT_DIR / "minimal_x64.exe"
    exe_path.write_bytes(binary)

    metadata = {
        "sample_id": "real_pe_minimal_x64",
        "arch": "x64",
        "kind": "real_pe",
        "file": "samples/real_pe/minimal_x64.exe",
        "description": "Public distributable minimal PE32+ sample generated for AI-DecompVis tests",
    }
    (OUT_DIR / "real_pe_minimal_x64.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Generated: {exe_path}")
