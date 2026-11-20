#!/usr/bin/env python3
"""Создаёт вредоносные ZIP для автотеста: каталог назначения передаётся аргументом."""
import stat, sys, zipfile
from pathlib import Path

out = Path(sys.argv[1])

with zipfile.ZipFile(out / "slip.zip", "w") as z:
    z.writestr("ok.txt", "ok")
    z.writestr("../../evil.txt", "pwned")

with zipfile.ZipFile(out / "abs.zip", "w") as z:
    z.writestr("/tmp/securefm_evil.txt", "pwned")

with zipfile.ZipFile(out / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("zeros.bin", b"\0" * (40 * 1024 * 1024))

info = zipfile.ZipInfo("link")
info.create_system = 3
info.external_attr = (stat.S_IFLNK | 0o777) << 16
with zipfile.ZipFile(out / "symlink.zip", "w") as z:
    z.writestr(info, "/etc/passwd")

with zipfile.ZipFile(out / "many.zip", "w") as z:
    for i in range(1001):
        z.writestr(f"f{i}.txt", "x")

(out / "broken.zip").write_bytes(b"this is not a zip archive")
