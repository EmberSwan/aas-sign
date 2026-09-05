#!/usr/bin/env python3
"""Execute the action's real sign step against a recording companion wrapper."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ActionSignTest(unittest.TestCase):
    def test_recursive_is_opt_in_and_paths_stay_arguments(self):
        step = (ROOT / "action.yml").read_text().rsplit("      run: |\n", 1)[1]
        script = "\n".join(line[8:] for line in step.splitlines()) + "\n"
        with tempfile.TemporaryDirectory(prefix="action sign ") as temporary:
            work = pathlib.Path(temporary)
            executable = work / "aas-sign"
            executable.write_text("#!/usr/bin/env python3\nimport json,os,sys\nopen(os.environ['CAPTURE'], 'w').write(json.dumps(sys.argv[1:]))\n")
            executable.chmod(0o755)
            environment = dict(os.environ, PATH=str(work) + os.pathsep + os.environ["PATH"],
                               CAPTURE=str(work / "args.json"), AAS_SIGN_OSSLSIGNCODE=str(work / "osslsigncode"),
                               INPUT_ENDPOINT="example.invalid", INPUT_ACCOUNT="account", INPUT_PROFILE="profile",
                               INPUT_FILES=" file one.msi \n\nfile$(never-executed).msixbundle\nfile.exe\n",
                               INPUT_TOKEN="test-token", INPUT_CLIENT_ID="", INPUT_TENANT_ID="",
                               INPUT_TIMESTAMP_URL="", INPUT_NO_TIMESTAMP="false", INPUT_MSI_DSE="false",
                               INPUT_MAX_PARALLEL="", INPUT_RECURSIVE="false")
            for recursive in ("", "false", "true"):
                environment["INPUT_RECURSIVE"] = recursive
                subprocess.run(["bash", "-c", script], env=environment, check=True, capture_output=True, text=True)
                args = json.loads((work / "args.json").read_text())
                self.assertEqual(args[0:3], ["sign", "--osslsigncode", str(work / "osslsigncode")])
                self.assertEqual("--recursive" in args, recursive == "true")
                self.assertEqual(args[-3:], ["file one.msi", "file$(never-executed).msixbundle", "file.exe"])


if __name__ == "__main__":
    unittest.main()
