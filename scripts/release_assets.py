#!/usr/bin/env python3
"""Create and verify the files attached to a Gantry GitHub release."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath


PLATFORMS = (
    "linux-x86_64-gnu",
    "linux-aarch64-gnu",
    "darwin-aarch64",
)
BINARIES = ("gantry", "gantry-supervisor", "run-remote")
DOCUMENTS = ("LICENSE", "README.md", "docs/reference.md")
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+\Z")
CHECKSUM_PATTERN = re.compile(r"([0-9a-f]{64})  ([^/]+)\Z")


def expected_archives(version: str) -> tuple[str, ...]:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"invalid stable release version: {version!r}")
    return tuple(f"gantry-{version}-{platform}.tar.gz" for platform in PLATFORMS)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as archive:
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive(path: Path, version: str, platform: str) -> None:
    root = f"gantry-{version}-{platform}"
    required_files = {f"{root}/{name}" for name in (*BINARIES, *DOCUMENTS)}
    required_directories = {root, f"{root}/docs"}
    seen: set[str] = set()

    try:
        archive = tarfile.open(path, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise ValueError(f"cannot read archive {path.name}: {error}") from error

    with archive:
        for member in archive.getmembers():
            name = member.name.rstrip("/")
            pure_name = PurePosixPath(name)
            if (
                not name
                or pure_name.is_absolute()
                or ".." in pure_name.parts
                or "\\" in name
                or name in seen
            ):
                raise ValueError(f"unsafe or duplicate archive path in {path.name}: {member.name!r}")
            seen.add(name)
            if member.isdir():
                if name not in required_directories:
                    raise ValueError(f"unexpected directory in {path.name}: {member.name!r}")
            elif member.isfile():
                if name not in required_files:
                    raise ValueError(f"unexpected file in {path.name}: {member.name!r}")
                if name.rsplit("/", 1)[-1] in BINARIES and member.mode & 0o111 != 0o111:
                    raise ValueError(f"binary is not executable in {path.name}: {member.name!r}")
            else:
                raise ValueError(f"unsupported archive entry in {path.name}: {member.name!r}")

    expected_members = required_files | required_directories
    if seen != expected_members:
        missing = sorted(expected_members - seen)
        extra = sorted(seen - expected_members)
        raise ValueError(f"archive contents do not match {path.name}; missing={missing}, extra={extra}")


def measure_archive(path: Path, version: str, platform: str) -> tuple[dict[str, int], int]:
    expected_name = f"gantry-{version}-{platform}.tar.gz"
    if path.name != expected_name:
        raise ValueError(f"expected archive name {expected_name}, got {path.name}")
    verify_archive(path, version, platform)

    root = f"gantry-{version}-{platform}"
    with tarfile.open(path, mode="r:gz") as archive:
        binary_sizes = {
            name: archive.getmember(f"{root}/{name}").size for name in BINARIES
        }
    return binary_sizes, path.stat().st_size


def format_size_report(version: str, platform: str, path: Path) -> str:
    binary_sizes, archive_size = measure_archive(path, version, platform)
    headers = " | ".join(
        ("Platform", *(f"{name} bytes" for name in BINARIES), "Archive bytes")
    )
    values = " | ".join(
        (
            platform,
            *(str(binary_sizes[name]) for name in BINARIES),
            str(archive_size),
        )
    )
    return "\n".join(
        (
            f"### Release size: {version}",
            "",
            f"| {headers} |",
            f"| {' | '.join(['---'] * 5)} |",
            f"| {values} |",
        )
    )


def require_files(directory: Path, names: set[str]) -> None:
    if not directory.is_dir():
        raise ValueError(f"asset directory does not exist: {directory}")
    entries = list(directory.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ValueError("asset directory must contain regular files only")
    actual = {path.name for path in entries}
    if actual != names:
        raise ValueError(
            f"asset set does not match; missing={sorted(names - actual)}, "
            f"extra={sorted(actual - names)}"
        )


def create_checksums(version: str, directory: Path) -> None:
    archives = expected_archives(version)
    require_files(directory, set(archives) | ({"SHA256SUMS"} if (directory / "SHA256SUMS").exists() else set()))
    for archive_name, platform in zip(archives, PLATFORMS, strict=True):
        verify_archive(directory / archive_name, version, platform)

    lines = [f"{sha256(directory / name)}  {name}" for name in archives]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")


def verify_assets(version: str, directory: Path) -> None:
    archives = expected_archives(version)
    require_files(directory, set(archives) | {"SHA256SUMS"})

    checksum_lines = (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        match = CHECKSUM_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid SHA256SUMS line: {line!r}")
        digest, name = match.groups()
        if name in checksums:
            raise ValueError(f"duplicate checksum entry: {name}")
        checksums[name] = digest
    if set(checksums) != set(archives):
        raise ValueError(
            f"SHA256SUMS must cover all three archives; "
            f"missing={sorted(set(archives) - checksums.keys())}, "
            f"extra={sorted(checksums.keys() - set(archives))}"
        )

    for archive_name, platform in zip(archives, PLATFORMS, strict=True):
        archive_path = directory / archive_name
        if sha256(archive_path) != checksums[archive_name]:
            raise ValueError(f"checksum mismatch for {archive_name}")
        verify_archive(archive_path, version, platform)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("checksums", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("version")
        subparser.add_argument("directory", type=Path)
    archive_parser = subparsers.add_parser("archive")
    archive_parser.add_argument("version")
    archive_parser.add_argument("platform", choices=PLATFORMS)
    archive_parser.add_argument("archive", type=Path)
    sizes_parser = subparsers.add_parser("sizes")
    sizes_parser.add_argument("version")
    sizes_parser.add_argument("platform", choices=PLATFORMS)
    sizes_parser.add_argument("archive", type=Path)
    args = parser.parse_args()

    try:
        if args.command == "checksums":
            create_checksums(args.version, args.directory)
        elif args.command == "verify":
            verify_assets(args.version, args.directory)
        elif args.command == "sizes":
            print(format_size_report(args.version, args.platform, args.archive))
        else:
            expected_name = f"gantry-{args.version}-{args.platform}.tar.gz"
            if args.archive.name != expected_name:
                raise ValueError(f"expected archive name {expected_name}, got {args.archive.name}")
            verify_archive(args.archive, args.version, args.platform)
    except (OSError, UnicodeError, ValueError, tarfile.TarError) as error:
        print(f"release assets: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
