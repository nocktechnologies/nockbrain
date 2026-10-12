"""Secret scrubbing shared by all NockBrain extraction paths."""
# Deferred annotations keep this importable on Python 3.9 (stock macOS
# /usr/bin/python3, which non-interactive shells resolve): PEP 604 unions
# in signatures are a def-time TypeError before 3.10.
from __future__ import annotations

import re


# Prefixes / patterns that mark a fact's content as a raw,
# un-synthesized artifact rather than a durable fact: tool_use.input JSON
# blobs, tool_result payloads, agent inbox dumps (=== AGENT MESSAGE / === SYSTEM
# and other ===... headers), fenced code, harness notification blobs,
# command tags, and cat -n line-numbered file dumps. Genuine facts start with a
# [TAG] (e.g. [DECISION], [INSIGHT]) or with prose, never with these.
_STRUCTURAL_NOISE_PREFIXES = (
    '{"',
    '[{"',
    "```",
    "<command-",
    "<task-notification",
    "<system-reminder",
    "<channel ",
    "[BEGIN UNTRUSTED",
)
# A leading [UPPER-CASE TAG] marks a synthesized/tagged fact. It is an escape
# hatch after the exact structural prefixes, so a transport fence such as
# '[BEGIN UNTRUSTED' cannot evade the guard by resembling a tag. Note '[{"' is
# NOT matched here ('{' is not A-Z), so JSON-array noise is still caught below.
_GENUINE_TAG_RE = re.compile(r"^\[[A-Z][A-Z0-9 _/-]*\]")

# The synthesis judges' own prompt templates. A judge that runs as a one-shot
# Claude session leaves a transcript under the transcript root, and without
# this rule its prompt was minted back into the store as a "fact". These exact
# sentences are the single source of truth: the synthesis and contradiction
# tools BUILD their prompts from them, and
# is_structural_noise drops any candidate embedding one. It is the only substring
# (not prefix) rule in this module, and it is deliberately checked BEFORE the
# genuine-[TAG] escape: a leaked injected-insight rendering arrives tagged
# ("[INSIGHT] Recurring directive (seen 33x): ..."), and no genuine fact ever
# contains a judge template verbatim.
JUDGE_PROMPT_MARKERS = (
    "These notes are the same recurring lesson from past work sessions.",
    "Two memory facts from the same project, EARLIER then LATER.",
)
# 3+ '=' at line start = an inbox/shell/verification dump header. Covers
# '=== AGENT MESSAGE', '=== SYSTEM', channel inbox headers, the generic
# '=== ...', and longer banners like '===== FULL REPORT ====='.
_EQUALS_DUMP_RE = re.compile(r"^={3,}")
_LINE_NUMBERED_DUMP_RE = re.compile(r"^\d+\t")


def is_structural_noise(content: str) -> bool:
    """Return True if *content* is a raw, un-synthesized artifact, not a fact.

    Guards the JSONL->facts path: the transcript refiner was minting
    facts out of raw tool_use.input JSON and inbox-dump message text, because the
    inferred 'merge' pattern fires on "pull request merged" text buried inside a
    command or inbox dump. This prefix/pattern discriminator drops those before
    classification. It is importable by purge-fact.py to sweep pre-existing
    noise with the identical rule.

    Content is structural noise IFF content.lstrip() starts with one of the
    exact _STRUCTURAL_NOISE_PREFIXES, or (when it is not a [TAG]ged fact):
      - matches ^={3,}  (=== ... inbox/shell/dump headers), OR
      - matches ^\\d+\\t (cat -n line-numbered file dumps).

    Prefix/pattern-based with ONE deliberate substring exception: a genuine
    fact like "[CORRECTION] ...the NAME=value setting was passing the wrong
    surface..." must be spared, so we never match 'NAME=' assignments
    anywhere in the text, and a leading [TAG] is an explicit escape hatch.
    The exception is JUDGE_PROMPT_MARKERS: a full judge-template
    sentence anywhere in the text, [TAG]ged or not, is always noise, since
    no genuine fact embeds the tooling's own prompts verbatim.
    Empty/whitespace returns False.
    """
    if not content:
        return False
    stripped = content.lstrip()
    if not stripped:
        return False
    # Judge-template check outranks the [TAG] escape (see JUDGE_PROMPT_MARKERS).
    if any(marker in stripped for marker in JUDGE_PROMPT_MARKERS):
        return True
    if stripped.startswith(_STRUCTURAL_NOISE_PREFIXES):
        return True
    if _GENUINE_TAG_RE.match(stripped):
        return False
    if _EQUALS_DUMP_RE.match(stripped) or _LINE_NUMBERED_DUMP_RE.match(stripped):
        return True
    return False


SENSITIVE_ENV_ASSIGNMENT = re.compile(
    r"(?im)(\b[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)\b\s*=\s*)([^\s\r\n]+)"
)

SECRET_PATTERNS = [
    # Messaging-bot tokens: 123456789:AA... or URL segments like bot123456789:AA...
    re.compile(r"(?<![A-Za-z0-9_])(?:bot)?\d{6,}:[A-Za-z0-9_-]{20,}\b"),
    # Common bare token prefixes seen in shell output and tool results.
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk_[A-Fa-f0-9]{32,}\b"),
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
    re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{32,}(?![A-Za-z0-9])"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{20,}\b"),
    # Bearer tokens and common key assignments.
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=:-]{16,}"
    ),
    # PEM private-key blocks.
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def scrub_secrets(text: str) -> tuple[str, int]:
    redactions = 0
    scrubbed, count = SENSITIVE_ENV_ASSIGNMENT.subn(r"\1[REDACTED_SECRET]", text)
    redactions += count
    for pattern in SECRET_PATTERNS:
        scrubbed, count = pattern.subn("[REDACTED_SECRET]", scrubbed)
        redactions += count
    return scrubbed, redactions
