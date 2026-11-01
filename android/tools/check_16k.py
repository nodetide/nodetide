#!/usr/bin/env python3
"""Google Play requires native libraries in apps that target Android 15+ to support 16 KB memory pages.

Checks every .so in an APK or AAB for the 64-bit ABIs: each loadable ELF segment must be aligned to at least 16 KB
(p_align >= 0x4000). Exits non-zero and names the offenders otherwise.

    python android/tools/check_16k.py app/build/outputs/apk/release/app-release-unsigned.apk
"""
import struct
import sys
import zipfile

PAGE = 0x4000
ABIS = ("arm64-v8a", "x86_64")


def aligned(data: bytes) -> bool:
    if data[:4] != b"\x7fELF" or data[4] != 2:       # only 64-bit ELF matters here
        return True
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type, = struct.unpack_from("<I", data, off)
        if p_type == 1:                                 # PT_LOAD
            p_align, = struct.unpack_from("<Q", data, off + 0x30)
            if p_align < PAGE:
                return False
    return True


def main(path: str) -> int:
    bad, seen = [], 0
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            parts = name.split("/")
            if name.endswith(".so") and any(a in parts for a in ABIS):
                seen += 1
                if not aligned(z.read(name)):
                    bad.append(name)
    print(f"{seen} native libraries checked in {path}")
    for name in bad:
        print(f"NOT 16 KB aligned: {name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
