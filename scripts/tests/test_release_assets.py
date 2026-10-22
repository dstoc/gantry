from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "release_assets.py"
SPEC = importlib.util.spec_from_file_location("release_assets", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_assets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_assets
SPEC.loader.exec_module(release_assets)


VERSION = "0.4.8"


def create_archive(path: Path, version: str, platform: str, executable: bool = True) -> None:
    root = f"gantry-{version}-{platform}"
    with tarfile.open(path, mode="w:gz") as archive:
        for directory in (root, f"{root}/docs"):
            info = tarfile.TarInfo(f"{directory}/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)

        for name in (*release_assets.BINARIES, *release_assets.DOCUMENTS):
            info = tarfile.TarInfo(f"{root}/{name}")
            info.mode = 0o755 if executable and name in release_assets.BINARIES else 0o644
            content = f"fixture for {name}\n".encode()
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


class ReleaseAssetsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        for platform, name in zip(
            release_assets.PLATFORMS,
            release_assets.expected_archives(VERSION),
            strict=True,
        ):
            create_archive(self.directory / name, VERSION, platform)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_checksums_cover_all_valid_archives(self) -> None:
        release_assets.create_checksums(VERSION, self.directory)

        release_assets.verify_assets(VERSION, self.directory)
        lines = (self.directory / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(
            {line.split("  ", 1)[1] for line in lines},
            set(release_assets.expected_archives(VERSION)),
        )

    def test_checksum_mismatch_fails_verification(self) -> None:
        release_assets.create_checksums(VERSION, self.directory)
        archive = self.directory / release_assets.expected_archives(VERSION)[0]
        archive.write_bytes(archive.read_bytes() + b"changed")

        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release_assets.verify_assets(VERSION, self.directory)

    def test_missing_build_fails_before_checksums_are_written(self) -> None:
        (self.directory / release_assets.expected_archives(VERSION)[1]).unlink()

        with self.assertRaisesRegex(ValueError, "asset set does not match"):
            release_assets.create_checksums(VERSION, self.directory)
        self.assertFalse((self.directory / "SHA256SUMS").exists())

    def test_non_executable_binary_fails_archive_verification(self) -> None:
        name = release_assets.expected_archives(VERSION)[0]
        create_archive(self.directory / name, VERSION, release_assets.PLATFORMS[0], executable=False)

        with self.assertRaisesRegex(ValueError, "not executable"):
            release_assets.create_checksums(VERSION, self.directory)

    def test_size_report_reads_binary_sizes_and_final_archive_size(self) -> None:
        platform = release_assets.PLATFORMS[0]
        archive = self.directory / release_assets.expected_archives(VERSION)[0]

        binary_sizes, archive_size = release_assets.measure_archive(archive, VERSION, platform)

        self.assertEqual(
            binary_sizes,
            {
                name: len(f"fixture for {name}\n".encode())
                for name in release_assets.BINARIES
            },
        )
        self.assertEqual(archive_size, archive.stat().st_size)
        report = release_assets.format_size_report(VERSION, platform, archive)
        self.assertIn(f"| {platform} |", report)
        self.assertIn(str(binary_sizes["gantry"]), report)
        self.assertIn(f"| {archive_size} |", report)

    def test_extra_downloaded_asset_fails_verification(self) -> None:
        release_assets.create_checksums(VERSION, self.directory)
        (self.directory / "unexpected.txt").write_text("stale")

        with self.assertRaisesRegex(ValueError, "asset set does not match"):
            release_assets.verify_assets(VERSION, self.directory)


if __name__ == "__main__":
    unittest.main()
