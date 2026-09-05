#!/usr/bin/env python3
"""Regenerate recursive.msi with wixl (msitools); runtime tests need no wixl."""
import pathlib
import shutil
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="aas-msi-fixture-") as temporary:
    path = pathlib.Path(temporary)
    pe = root / "fuzz/corpus/pe/minimal-pe32.exe"
    if not pe.exists():
        pe = next((root / "fuzz/corpus/pe").glob("*32*"))
    shutil.copyfile(pe, path / "unsigned.exe")
    shutil.copyfile(pe, path / "preserved.dll")
    shutil.copyfile(root / "fuzz/corpus/msi/minimal-msi-v3.msi", path / "nested.msi")
    (path / "notes.txt").write_bytes(b"Unchanged non-PE payload\n")
    subprocess.run(["wixl", "-D", f"payload={path}", "-o", str(root / "tests/fixtures/recursive.msi"),
                    str(root / "tests/fixtures/recursive.wxs")], check=True)
    # wixl currently emits files on the first medium only. Replace its cabinets
    # with two valid cabinets, retaining its File table ordering and hash rows.
    for key, source in {"UnsignedExe": "unsigned.exe", "PreservedDll": "preserved.dll",
                        "TextFile": "notes.txt", "SecondExe": "unsigned.exe", "NestedMsi": "nested.msi"}.items():
        shutil.copyfile(path / source, path / key)
    subprocess.run(["gcab", "-cz", "first.cab", "UnsignedExe", "PreservedDll", "TextFile"], cwd=path, check=True)
    subprocess.run(["gcab", "-cz", "second.cab", "SecondExe", "NestedMsi"], cwd=path, check=True)
    subprocess.run(["msibuild", str(root / "tests/fixtures/recursive.msi"),
                    "-a", "first.cab", str(path / "first.cab"), "-a", "second.cab", str(path / "second.cab"),
                    "-q", "UPDATE `Media` SET `LastSequence` = 3 WHERE `DiskId` = 1"], check=True)
