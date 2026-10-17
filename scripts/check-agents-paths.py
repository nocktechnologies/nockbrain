#!/usr/bin/env python3
"""Check that repository paths cited in AGENTS.md exist and are tracked."""

from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "AGENTS.md"
CODE_SPANS = re.compile(r"(`+)(.*?)\1", re.DOTALL)
LINK_TARGETS = re.compile(
    r"\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))", re.DOTALL
)
FILE_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,8}$")
TRAILING_PUNCTUATION = ".,;:!?"


def tracked_paths():
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return {
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\0")
        if item
    }


def path_references(text):
    """Yield link targets and path-like tokens inside complete code spans."""
    for match in LINK_TARGETS.finditer(text):
        target = match.group(1) or match.group(2)
        yield target, "Markdown link"

    # Parse spans over the full file so a span may wrap across lines. Ordinary
    # prose such as Node.js is never considered as a path.
    for span in CODE_SPANS.finditer(text):
        for token in span.group(2).split():
            token = token.strip("`\"'()[]{}")
            candidate = token.rstrip(TRAILING_PUNCTUATION)
            if "/" in candidate or FILE_EXTENSION.search(candidate):
                yield token, "backtick span"


def normalize_reference(raw):
    if any(mark in raw for mark in "<>*?"):
        return None
    raw = raw.strip().strip("`\"'()[]{}")
    raw = raw.rstrip(TRAILING_PUNCTUATION)
    if not raw or raw.startswith(("http://", "https://", "mailto:", "#")):
        return None
    raw = raw.split("#", 1)[0].split("?", 1)[0]
    return raw or None


def check_reference(raw, source, tracked):
    normalized = normalize_reference(raw)
    if normalized is None:
        return None
    if normalized.startswith(("/", "~")):
        return f"{source}: path must be repo-relative: {raw}"
    parts = normalized.split("/")
    if ".." in parts:
        return f"{source}: parent traversal is not allowed: {raw}"

    relative = Path(*[part for part in parts if part not in ("", ".")])
    if not relative.parts:
        return None
    lexical_path = ROOT / relative
    try:
        resolved = lexical_path.resolve(strict=True)
        resolved.relative_to(ROOT)
    except (OSError, ValueError):
        return f"{source}: path does not resolve inside the repository: {raw}"

    repo_path = relative.as_posix()
    if lexical_path.is_dir():
        prefix = repo_path + "/"
        for item in tracked:
            if item.startswith(prefix):
                candidate = ROOT / item
                if candidate.exists():
                    try:
                        candidate.resolve(strict=True).relative_to(ROOT)
                    except (OSError, ValueError):
                        continue
                    return None
        return f"{source}: directory has no tracked file beneath it: {raw}"
    if repo_path not in tracked:
        return f"{source}: path is not git-tracked: {raw}"
    return None


def main():
    if not AGENTS.is_file():
        print("AGENTS.md is missing", file=sys.stderr)
        return 1
    text = AGENTS.read_text(encoding="utf-8")
    tracked = tracked_paths()
    errors = []
    checked = 0
    for raw, source in path_references(text):
        if normalize_reference(raw) is None:
            continue
        checked += 1
        error = check_reference(raw, source, tracked)
        if error:
            errors.append(error)
    if errors:
        print("AGENTS.md path check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"AGENTS.md path check passed ({checked} references)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
