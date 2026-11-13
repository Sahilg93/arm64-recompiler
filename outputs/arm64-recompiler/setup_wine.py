#!/usr/bin/env python3
"""Install the tested Wine build beside the Windows launcher."""

import argparse
import hashlib
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "wine-runtime"
WINE_PATH = Path("Wine Stable.app/Contents/Resources/wine/bin/wine")
URL = "https://github.com/Gcenx/macOS_Wine_builds/releases/download/11.0_1/wine-stable-11.0_1-osx64.tar.xz"
SHA256 = "b50dc50ec7f41d58b115a6b685d4d1315ba3c797bd3aa0f49213f2703cb82388"


def install(archive):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("run setup with native Python on Apple Silicon macOS")
    subprocess.run(["arch", "-x86_64", "/usr/bin/true"], check=True)
    if RUNTIME.exists():
        subprocess.run([str(RUNTIME / WINE_PATH), "--version"], check=True)
        print(f"Wine is already installed at {RUNTIME}")
        return
    with tempfile.TemporaryDirectory(prefix=".wine-setup-", dir=ROOT) as staging:
        staging = Path(staging)
        if archive is None:
            archive = staging / "wine.tar.xz"
            subprocess.run(["curl", "-fL", "--retry", "2", "--max-time", "300",
                            URL, "-o", str(archive)], check=True)
        digest = hashlib.sha256()
        with archive.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != SHA256:
            raise ValueError("Wine archive checksum did not match")
        extracted = staging / "runtime"
        extracted.mkdir()
        subprocess.run(["tar", "-xf", str(archive), "-C", str(extracted)], check=True)
        subprocess.run([str(extracted / WINE_PATH), "--version"], check=True)
        extracted.rename(RUNTIME)
    print(f"Wine is ready at {RUNTIME}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="use a previously downloaded Wine archive")
    args = parser.parse_args()
    try:
        install(args.archive)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Wine setup failed: {error}\n")


if __name__ == "__main__":
    main()
