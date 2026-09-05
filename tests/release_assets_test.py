#!/usr/bin/env python3
"""Check release naming and gitlink validation without a network or real release."""
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_assets", ROOT / "scripts/release-assets.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseAssetsTest(unittest.TestCase):
    def test_gitlink_is_the_only_revision_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            upstream = root / "upstream"
            repo = root / "repo"
            upstream.mkdir(); repo.mkdir()
            (repo / "CMakeLists.txt").write_text("project(aas-sign VERSION 1.3.0 LANGUAGES CXX C)\n")
            def git(directory, *args):
                return subprocess.check_output(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                                                "-c", "protocol.file.allow=always", *args], cwd=directory,
                                               stderr=subprocess.DEVNULL, text=True).strip()
            for directory in (upstream, repo):
                git(directory, "init")
            (upstream / "source").write_text("one")
            git(upstream, "add", "."); git(upstream, "commit", "-m", "first")
            git(repo, "submodule", "add", str(upstream), "modules/osslsigncode")
            git(repo, "add", "CMakeLists.txt")
            git(repo, "commit", "-am", "submodule")
            old = git(upstream, "rev-parse", "HEAD")
            self.assertEqual(module.metadata(repo, "v1.3.0-rc.2+build.7")["version"], "1.3.0-rc.2+build.7")
            data = module.metadata(repo, "v1.3.0-rc.2")
            self.assertEqual(data["aas_windows"], "aas-sign-1.3.0-rc.2-windows-x86_64.exe")
            self.assertEqual(data["ossl_linux"], f"osslsigncode-{old[:8]}-linux-x86_64")
            (upstream / "source").write_text("two")
            git(upstream, "commit", "-am", "second")
            checkout = repo / "modules/osslsigncode"
            git(checkout, "pull")
            with self.assertRaisesRegex(ValueError, "differs"):
                module.metadata(repo, "1.3.0")
            git(repo, "add", "modules/osslsigncode"); git(repo, "commit", "-m", "update")
            new = git(upstream, "rev-parse", "HEAD")
            self.assertEqual(module.metadata(repo, "1.3.0")["osslsigncode_revision"], new)
            (checkout / "untracked").write_text("dirty")
            with self.assertRaisesRegex(ValueError, "dirty"):
                module.metadata(repo, "1.3.0")
            self.assertEqual(module.metadata(repo, "1.3.0", False)["version"], "1.3.0")
            for bad in ("v", "latest", "../v1.3.0", "v1.3.0/evil", "v1.3", "v1.3.1"):
                with self.assertRaises(ValueError):
                    module.metadata(repo, bad, False)


if __name__ == "__main__":
    unittest.main()
