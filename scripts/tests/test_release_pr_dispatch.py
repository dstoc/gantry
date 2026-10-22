from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "dispatch_release_pr_checks.sh"


class ReleasePrDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.bin_directory = self.directory / "bin"
        self.bin_directory.mkdir()
        self.capture = self.directory / "gh-args"
        gh = self.bin_directory / "gh"
        gh.write_text(
            "#!/bin/sh\n"
            'printf \'%s\\n\' "$@" >> "$RELEASE_DISPATCH_CAPTURE"\n'
        )
        gh.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_dispatch(self, release_pr: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GH_TOKEN": "test-token",
                "GITHUB_REPOSITORY": "dstoc/gantry",
                "PATH": f"{self.bin_directory}:{environment['PATH']}",
                "RELEASE_DISPATCH_CAPTURE": str(self.capture),
                "RELEASE_PR": release_pr,
            }
        )
        return subprocess.run(
            ["bash", str(SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_action_output_head_branch_name_is_dispatched_to_required_checks(self) -> None:
        action_output = json.dumps(
            {
                "headBranchName": "release-please--branches--main",
                "baseBranchName": "main",
                "number": 15,
                "title": "chore(main): release 0.4.8",
                "body": "release",
                "labels": ["autorelease: pending"],
                "files": [],
            }
        )

        result = self.run_dispatch(action_output)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.capture.read_text().splitlines(),
            [
                "api",
                "--method",
                "POST",
                "repos/dstoc/gantry/actions/workflows/ci.yml/dispatches",
                "--field",
                "ref=release-please--branches--main",
                "api",
                "--method",
                "POST",
                "repos/dstoc/gantry/actions/workflows/release-build-check.yml/dispatches",
                "--field",
                "ref=release-please--branches--main",
            ],
        )

    def test_missing_or_invalid_head_branch_name_fails_before_dispatch(self) -> None:
        for action_output in (
            '{"head":{"ref":"release-please--branches--main"}}',
            '{"headBranchName":"invalid branch name"}',
        ):
            with self.subTest(action_output=action_output):
                self.capture.unlink(missing_ok=True)

                result = self.run_dispatch(action_output)

                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
