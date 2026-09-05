#!/usr/bin/env python3
"""Fetch verified sources and build private static dependencies (no system installs)."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = json.loads((ROOT / "cmake/dependency-sources.json").read_text())
# Bundle only these named source trees, never the whole deps/ directory:
# developers may keep private credentials in deps/.env alongside them.
MSI_DEPS = ("zlib", "libffi", "pcre2", "glib", "libxml2", "libgsf", "gcab", "msitools")


def source(name, directory):
    dest = directory / name
    if dest.is_dir():
        return dest
    bundled = ROOT / "deps" / name
    if directory != ROOT / "deps" and bundled.is_dir():
        shutil.copytree(bundled, dest)
        return dest
    spec = SOURCES[name]
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / spec["url"].rsplit("/", 1)[1]
    if not archive.exists():
        print(f"Downloading {spec['url']}", flush=True)
        with urllib.request.urlopen(spec["url"], timeout=120) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec["sha256"]:
        archive.unlink()
        raise RuntimeError(f"{name}: source checksum mismatch")
    temporary = directory / (name + ".extracting")
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir()
    with tarfile.open(archive) as tar:
        # Reject traversal and links escaping the source archive on Python 3.12+.
        tar.extractall(temporary, filter="data")
    children = list(temporary.iterdir())
    if len(children) != 1 or not children[0].is_dir():
        raise RuntimeError(f"{name}: expected one source directory")
    children[0].rename(dest)
    temporary.rmdir()
    archive.unlink()
    return dest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=("companion", "msi", "bundle"))
    parser.add_argument("--build", type=pathlib.Path, default=ROOT / "build-dependencies")
    parser.add_argument("--sources", type=pathlib.Path, default=ROOT / "deps")
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 8))
    args = parser.parse_args()
    args.build = args.build.resolve()
    args.sources = args.sources.resolve()
    names = MSI_DEPS if args.group == "bundle" else (MSI_DEPS if args.group == "msi" else ("zlib", "openssl"))
    trees = {name: source(name, args.sources) for name in names}
    if args.group == "bundle":
        return
    prefix = args.build / "prefix"
    prefix.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["PKG_CONFIG_LIBDIR"] = str(prefix / "lib/pkgconfig")
    environment["PKG_CONFIG_PATH"] = str(prefix / "lib/pkgconfig")
    environment["PATH"] = str(prefix / "bin") + os.pathsep + environment["PATH"]
    environment.setdefault("CFLAGS", "-O2 -fPIC" if os.name != "nt" else "")
    if os.name != "nt":
        environment["CPPFLAGS"] = f"-I{prefix / 'include'}"
        environment["LDFLAGS"] = f"-L{prefix / 'lib'}"
    jobs = str(args.jobs)

    def run(command, cwd=None):
        print("+ " + " ".join(map(str, command)), flush=True)
        subprocess.run(list(map(str, command)), cwd=cwd, env=environment, check=True)

    def cmake(src, build, options):
        command = ["cmake", "-S", src, "-B", build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                   f"-DCMAKE_INSTALL_PREFIX={prefix}", "-DCMAKE_INSTALL_LIBDIR=lib", "-DBUILD_SHARED_LIBS=OFF",
                   "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"]
        if os.name == "nt":
            command += ["-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"]
        run(command + options)
        run(["cmake", "--build", build, "--parallel", jobs])
        run(["cmake", "--install", build])

    def meson(src, build, options):
        if not (build / "build.ninja").exists():
            run(["meson", "setup", build, src, f"--prefix={prefix}", "--libdir=lib", "--buildtype=release",
                 "--default-library=static", "--wrap-mode=nofallback", "-Dprefer_static=true"] + options)
        run(["meson", "compile", "-C", build, "-j", jobs])
        run(["meson", "install", "-C", build, "--no-rebuild"])

    def autotools(src, build, options):
        build.mkdir(parents=True, exist_ok=True)
        if not (build / "Makefile").exists():
            run([src / "configure", f"--prefix={prefix}", f"--libdir={prefix / 'lib'}", "--disable-shared", "--enable-static"] + options, build)
        run(["make", "-j" + jobs], build)
        run(["make", "install"], build)

    for name in names:
        src = trees[name]
        build = args.build / name
        stamp = args.build / (name + ".built")
        patches = sorted((ROOT / "cmake/patches").glob("libmsi-*.patch")) if name == "msitools" else []
        patch_identity = "".join(hashlib.sha256(path.read_bytes()).hexdigest() for path in patches)
        identity = hashlib.sha256((SOURCES[name]["sha256"] + pathlib.Path(__file__).read_text()
                                  + patch_identity + str(prefix) + environment.get("CC", "") + environment.get("CFLAGS", "")).encode()).hexdigest()
        if stamp.exists() and stamp.read_text() == identity:
            continue
        if name == "zlib":
            cmake(src, build, ["-DZLIB_BUILD_TESTING=OFF", "-DZLIB_BUILD_SHARED=OFF", "-DZLIB_BUILD_STATIC=ON"])
        elif name == "openssl":
            build.mkdir(parents=True, exist_ok=True)
            target = ["VC-WIN64A", "no-asm"] if os.name == "nt" else []
            run(["perl", src / "Configure"] + target + ["no-shared", "no-module", "no-tests", f"--prefix={prefix}", "--libdir=lib"], build)
            make = ["nmake"] if os.name == "nt" else ["make", "-j" + jobs]
            run(make, build)
            run(make + ["install_sw", "install_ssldirs"], build)
        elif name == "libffi":
            autotools(src, build, ["--disable-docs"])
        elif name == "pcre2":
            cmake(src, build, ["-DPCRE2_BUILD_TESTS=OFF", "-DPCRE2_BUILD_PCRE2GREP=OFF", "-DPCRE2_SUPPORT_JIT=OFF"])
        elif name == "glib":
            meson(src, build, ["-Dtests=false", "-Dinstalled_tests=false", "-Dintrospection=disabled", "-Ddocumentation=false",
                              "-Dman-pages=disabled", "-Dnls=disabled", "-Dlibmount=disabled", "-Dselinux=disabled",
                              "-Dlibelf=disabled", "-Dsysprof=disabled", "-Dsystemtap=disabled", "-Ddtrace=disabled"])
        elif name == "libxml2":
            cmake(src, build, ["-DLIBXML2_WITH_PYTHON=OFF", "-DLIBXML2_WITH_PROGRAMS=OFF", "-DLIBXML2_WITH_TESTS=OFF",
                              "-DLIBXML2_WITH_ICONV=OFF", "-DLIBXML2_WITH_LZMA=OFF", "-DLIBXML2_WITH_ZLIB=OFF"])
        elif name == "libgsf":
            autotools(src, build, ["--disable-introspection", "--disable-nls", "--disable-gtk-doc", "--without-bz2", "--without-gdk-pixbuf"])
        elif name in ("gcab", "msitools"):
            # These releases hardcode shared_library(). Adapt only the build
            # declaration in a private copy; never modify bundled source trees.
            adapted = args.build / (name + "-source")
            adaptation_stamp = adapted / ".aas-sign-build-adaptations"
            if not adaptation_stamp.exists() or adaptation_stamp.read_text() != patch_identity:
                shutil.rmtree(adapted, ignore_errors=True)
                shutil.copytree(src, adapted)
                declaration = adapted / ("libgcab" if name == "gcab" else "libmsi") / "meson.build"
                declaration.write_text(declaration.read_text().replace("shared_library(", "library("))
                for patch in patches:
                    run(["patch", "--batch", "--forward", "-p1", "--input", patch], adapted)
                adaptation_stamp.write_text(patch_identity)
            options = ["-Dintrospection=false"]
            if name == "gcab":
                options += ["-Ddocs=false", "-Dvapi=false", "-Dnls=false", "-Dtests=false"]
            meson(adapted, build, options)
        stamp.write_text(identity)
    print(prefix, flush=True)


if __name__ == "__main__":
    main()
