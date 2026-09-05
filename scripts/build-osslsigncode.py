#!/usr/bin/env python3
"""Build the unmodified osslsigncode submodule with private static dependencies."""
import argparse
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=pathlib.Path, default=ROOT / "build-companion")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 8))
    args = parser.parse_args()
    build = args.build.resolve()
    module = ROOT / "modules/osslsigncode"
    if not (module / "CMakeLists.txt").exists():
        parser.error("initialize modules/osslsigncode with git submodule update --init")
    subprocess.run([sys.executable, ROOT / "scripts/build-dependencies.py", "companion", "--build", build / "dependencies", "--jobs", str(args.jobs)], check=True)
    prefix = build / "dependencies/prefix"
    command = ["cmake", "-S", str(module), "-B", str(build), "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
               "-DCMAKE_TOOLCHAIN_FILE=", "-DOPENSSL_USE_STATIC_LIBS=TRUE", "-DZLIB_USE_STATIC_LIBS=TRUE", f"-DOPENSSL_ROOT_DIR={prefix}",
               f"-DCMAKE_PREFIX_PATH={prefix}", "-DCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE"]
    if os.name == "nt":
        command += ["-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded", "-DOPENSSL_MSVC_STATIC_RT=TRUE",
                    f"-DZLIB_LIBRARY_RELEASE={prefix / 'lib/zs.lib'}", f"-DZLIB_INCLUDE_DIR={prefix / 'include'}"]
    subprocess.run(command, check=True)
    cache = {}
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        if ":" in line and "=" in line and not line.startswith(("//", "#")):
            key, value = line.split("=", 1)
            cache[key.split(":", 1)[0]] = value
    # FindOpenSSL caches the configuration-specific library paths on MSVC;
    # OPENSSL_{CRYPTO,SSL}_LIBRARY are non-cache result variables there.
    openssl_libraries = (("LIB_EAY_RELEASE", "SSL_EAY_RELEASE") if os.name == "nt" else
                         ("OPENSSL_CRYPTO_LIBRARY", "OPENSSL_SSL_LIBRARY"))
    for key in (*openssl_libraries, "OPENSSL_INCLUDE_DIR", "ZLIB_INCLUDE_DIR", "ZLIB_LIBRARY_RELEASE"):
        found = pathlib.Path(cache.get(key, "missing")).resolve()
        if not found.is_relative_to(prefix) or not found.exists():
            raise RuntimeError(f"{key} did not resolve to an existing path inside the private dependency prefix: {found}")
    subprocess.run(["cmake", "--build", str(build), "--parallel", str(args.jobs)], check=True)
    executable = build / ("osslsigncode.exe" if os.name == "nt" else "osslsigncode")
    subprocess.run([str(executable), "--version"], check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=module, text=True).strip()
    provenance = {"upstream": f"https://github.com/mtrojnar/osslsigncode/tree/{revision}", "revision": revision,
                  "dependencies": {name: spec for name, spec in json.loads((ROOT / "cmake/dependency-sources.json").read_text()).items()
                                   if name in ("openssl", "zlib")}}
    (build / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")


if __name__ == "__main__":
    main()
