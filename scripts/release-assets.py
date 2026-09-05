#!/usr/bin/env python3
"""Print release asset metadata, deriving the companion revision from the gitlink."""
import argparse
import json
import pathlib
import re
import subprocess


def metadata(root, tag, check_checkout=True):
    if not re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", tag):
        raise ValueError("release tag must contain a semantic version")
    version = tag.removeprefix("v")
    project = re.search(r"project\(aas-sign\s+VERSION\s+(\d+\.\d+\.\d+)\b", (root / "CMakeLists.txt").read_text())
    if not project or re.match(r"\d+\.\d+\.\d+", version)[0] != project[1]:
        raise ValueError("release tag does not match the CMake project version")
    line = subprocess.check_output(
        ["git", "ls-tree", "HEAD", "--", "modules/osslsigncode"], cwd=root, text=True
    ).strip()
    match = re.fullmatch(r"160000 commit ([0-9a-f]{40})\tmodules/osslsigncode", line)
    if not match:
        raise ValueError("HEAD has no osslsigncode submodule gitlink")
    revision = match[1]
    if check_checkout:
        module = root / "modules/osslsigncode"
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=module, text=True).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=module, text=True)
        if actual != revision or dirty:
            raise ValueError("osslsigncode checkout is dirty or differs from the recorded gitlink")
    result = {"version": version, "osslsigncode_revision": revision, "osslsigncode_version": revision[:8]}
    for platform, suffix in (("linux", ""), ("windows", ".exe")):
        result[f"aas_{platform}"] = f"aas-sign-{version}-{platform}-x86_64{suffix}"
        result[f"ossl_{platform}"] = f"osslsigncode-{revision[:8]}-{platform}-x86_64{suffix}"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--github-output", type=pathlib.Path)
    parser.add_argument("--no-check-checkout", action="store_true", help="metadata-only jobs without initialized submodules")
    args = parser.parse_args()
    result = metadata(args.root, args.tag, not args.no_check_checkout)
    if args.github_output:
        with args.github_output.open("a") as output:
            for name, value in result.items():
                output.write(f"{name}={value}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
