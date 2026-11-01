"""Install the Hayabusa Linux release (binary + Sigma rules) for the sandbox. Used by Render's build.

    python scripts/install_hayabusa.py

Downloads one pinned release and refuses it unless its SHA-256 matches, then extracts it to
tools/hayabusa-linux/, where triage.services.sandbox looks for it.
"""

import hashlib
import io
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

VERSION = "4.3.1"
NAME = f"hayabusa-{VERSION}-lin-x64-musl"   # static: the gnu build needs glibc 2.39, newer than Render has
URL = f"https://github.com/Yamato-Security/hayabusa/releases/download/v{VERSION}/{NAME}.zip"
SHA256 = "8592a844a29b0b8ad10d80550fd5b835eec0bea7c488b61e8d48d400a6057402"   # GitHub's published digest
DEST = Path("tools") / "hayabusa-linux"


def main() -> None:
    binary = DEST / NAME
    if binary.is_file():
        print(f"already installed: {binary}")
        return
    request = urllib.request.Request(URL, headers={"User-Agent": "probative-ai"})
    with urllib.request.urlopen(request, timeout=300) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        sys.exit(f"refusing {URL}: sha256 {digest} does not match the pinned {SHA256}")
    DEST.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(DEST)
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed {binary} ({len(data) / 1e6:.1f} MB, sha256 ok)")


if __name__ == "__main__":
    main()
