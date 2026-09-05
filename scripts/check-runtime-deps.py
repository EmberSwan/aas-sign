#!/usr/bin/env python3
"""Reject release executables requiring libraries beyond the OS runtime."""
import pathlib
import re
import shutil
import subprocess
import sys

WINDOWS_SYSTEM = {
    "advapi32.dll", "bcrypt.dll", "cabinet.dll", "crypt32.dll", "cryptbase.dll",
    "gdi32.dll", "kernel32.dll", "msi.dll", "msvcrt.dll", "ntdll.dll", "ole32.dll",
    "oleaut32.dll", "rpcrt4.dll", "secur32.dll", "shell32.dll", "shlwapi.dll",
    "ucrtbase.dll", "user32.dll", "userenv.dll", "version.dll", "winhttp.dll", "ws2_32.dll",
}
for argument in sys.argv[1:]:
    binary = pathlib.Path(argument).resolve()
    if binary.suffix.lower() == ".exe":
        if shutil.which("dumpbin"):
            result = subprocess.check_output(["dumpbin", "/dependents", str(binary)], text=True)
            names = re.findall(r"^\s+([\w.-]+\.dll)\s*$", result, re.I | re.M)
        else:
            result = subprocess.check_output(["x86_64-w64-mingw32-objdump", "-p", str(binary)], text=True)
            names = re.findall(r"DLL Name:\s+(\S+)", result)
        unexpected = [name for name in names if name.lower() not in WINDOWS_SYSTEM and not name.lower().startswith(("api-ms-win-", "ext-ms-win-"))]
    else:
        result = subprocess.check_output(["ldd", str(binary)], text=True)
        names = re.findall(r"^\s*(\S+)\s+=>", result, re.M)
        unexpected = [name for name in names if not re.fullmatch(r"lib(c|m|pthread|dl|rt)\.so\.\d+", name)]
        if "not found" in result:
            unexpected.append("unresolved dependency")
    if not names:
        raise SystemExit(f"{binary}: could not inspect runtime dependencies")
    if unexpected:
        raise SystemExit(f"{binary}: unexpected runtime dependencies: {', '.join(unexpected)}")
    print(f"{binary.name}: system runtime only ({', '.join(names)})")
