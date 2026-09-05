#!/usr/bin/env python3
"""Collect source identities, notices, and rebuilding instructions for release binaries."""
import argparse
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=pathlib.Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
revision = subprocess.check_output(["git", "rev-parse", "HEAD:modules/osslsigncode"], cwd=ROOT, text=True).strip()
project_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
sources = json.loads((ROOT / "cmake/dependency-sources.json").read_text())
(args.output / "provenance.json").write_text(json.dumps({
    "aas-sign": project_revision,
    "osslsigncode": {"revision": revision, "source": f"https://github.com/mtrojnar/osslsigncode/tree/{revision}", "modified": False},
    "static-dependencies": sources,
    "rebuild": "git clone --recurse-submodules; see scripts/build-osslsigncode.py and scripts/build-dependencies.py",
    "build-adaptations": "gcab and msitools: use library() instead of shared_library() in a private build copy to honor static builds; apply the listed libmsi ownership and bounds fixes",
    "dependency-patches": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in sorted((ROOT / "cmake/patches").glob("*.patch"))},
}, indent=2) + "\n")
notices = ["aas-sign release third-party notices\n\n"
           "The aas-sign source release includes its static MSI dependencies and complete build scripts.\n"
           "Rebuild with changed libraries using DEPS=LOCAL, or replace bundled deps and use DEPS=FETCH.\n"
           "The unmodified osslsigncode source is available at the exact revision in provenance.json;\n"
           "initialize the submodule and run scripts/build-osslsigncode.py to rebuild it.\n"
           "Dependency source URLs and SHA-256 hashes are recorded in provenance.json.\n"]
trees = [("osslsigncode", ROOT / "modules/osslsigncode")]
trees += [(name, ROOT / "deps" / name) for name in ("json", "mbedtls", *sources)]
for name, tree in trees:
    candidates = sorted({path for pattern in ("COPYING*", "LICENSE*", "NOTICE*", "LICENCE*", "copyright", "Copyright", "licenses/*", "LICENSES/*") for path in tree.glob(pattern) if path.is_file()})
    if not candidates:
        raise SystemExit(f"No license notices found for {name} in {tree}")
    for path in candidates:
        notices += [f"\n{'=' * 72}\n{name}: {path.relative_to(tree)}\n{'=' * 72}\n", path.read_text(errors="replace")]
(args.output / "THIRD-PARTY-NOTICES.txt").write_text("\n".join(notices))
