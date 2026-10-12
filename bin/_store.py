"""Private local-store write helpers for NockBrain artifacts."""
from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


DIR_MODE = 0o700
FILE_MODE = 0o600


def secure_mkdir(path: Path) -> None:
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if not existed or ".nock-brain" in path.expanduser().parts:
        path.chmod(DIR_MODE)


def secure_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write then chmod. Not atomic; see secure_replace_text."""
    secure_mkdir(path.parent)
    path.write_text(text, encoding=encoding)
    path.chmod(FILE_MODE)


def secure_write_json(path: Path, value: Any, **json_kwargs: Any) -> bool:
    """Atomic owner-only JSON write (mode FILE_MODE).

    Authoritative store writes go through here so a kill mid-write cannot
    torn-tail facts.json. Markdown/text still uses secure_write_text.
    """
    return secure_write_json_atomic(path, value, **json_kwargs)


def secure_replace_bytes(
    path: Path,
    data: bytes,
    *,
    before_replace=None,
) -> bool:
    """Atomic owner-only replace of ``path`` with ``data`` (mode FILE_MODE).

    Writes to a sibling mkstemp, chmod 0600, then os.replace. Returns True
    if the target was replaced. If ``before_replace`` is given and returns
    a false value, the tmp is discarded and the target is left untouched
    (the verification cache uses this to skip a stale concurrent save).
    Raises on write errors; never leaves the tmp behind on the success or
    skip path.
    """
    path = Path(path)
    secure_mkdir(path.parent)
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        # Write through the descriptor so the tmp pathname cannot be
        # swapped between create and write.
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            os.fchmod(handle.fileno(), FILE_MODE)
        if before_replace is not None and not before_replace():
            return False
        os.replace(tmp, path)
        tmp = None
        return True
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def secure_replace_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    before_replace=None,
) -> bool:
    """Atomic owner-only replace of ``path`` with ``text`` (mode FILE_MODE)."""
    return secure_replace_bytes(
        path, text.encode(encoding), before_replace=before_replace)


def secure_write_json_atomic(
    path: Path,
    value: Any,
    *,
    before_replace=None,
    **json_kwargs: Any,
) -> bool:
    """Atomic owner-only JSON write (mode FILE_MODE)."""
    buf = io.StringIO()
    json.dump(value, buf, **json_kwargs)
    return secure_replace_text(
        path, buf.getvalue(), before_replace=before_replace)


def secure_copyfile(src: Path, dst: Path) -> None:
    secure_mkdir(dst.parent)
    shutil.copyfile(src, dst)
    dst.chmod(FILE_MODE)
