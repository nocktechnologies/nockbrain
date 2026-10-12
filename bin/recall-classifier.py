#!/usr/bin/env python3
"""Classify whether a user prompt needs memory recall.

Returns exit code 0 (recall needed) or 1 (no recall needed).
Designed to run in <50ms so it can gate retrieval without adding latency.

Usage:
    echo "what did we decide about pricing" | python3 recall-classifier.py
    python3 recall-classifier.py "have we seen this bug before"
    python3 recall-classifier.py --test
"""
from __future__ import annotations

import re
import sys

PAST_PATTERNS = [
    r"\b(?:last time|previously|before|earlier|yesterday|last week|last session)\b",
    r"\b(?:what did (?:we|you|i)|when did (?:we|you))\b",
    r"\b(?:do you remember|did we discuss|have we)\b",
    r"\b(?:same (?:bug|issue|problem|pattern)|seen this before)\b",
]

DECISION_PATTERNS = [
    r"\b(?:what (?:was|were) (?:decided|the decision|the plan|the reason))\b",
    r"\b(?:why did we|how did we decide|what led to)\b",
    r"\b(?:agreed on|settled on|locked|chose to)\b",
    r"\b(?:is .{1,30} still (?:current|true|valid|the plan))\b",
]

ENTITY_PATTERNS = [
    # Short identity lookups ("who is Alice", "who's on the review rota").
    r"\bwho(?:'s| is| was| are)\b",
    r"\bPR\s*#\d+\b.{0,20}\b(?:did|said|status|about)\b",
    r"\b(?:agent|worker|builder)\b.{0,20}\b(?:did|said|built|shipped|delivered|status)\b",
]

# Personal names that count as "the user" in user-context prompts, on top of
# the generic role words. Operator default for the full-install hook (which
# runs this file directly); the standalone hook passes names=frozenset(), and
# the release build rewrites this line to the value after the marker, so a
# released copy names nobody.
OPERATOR_NAMES = frozenset()
GENERIC_USER_WORDS = ("user", "owner", "founder", "boss")


def user_patterns(names=OPERATOR_NAMES) -> list[str]:
    who = "|".join(GENERIC_USER_WORDS + tuple(sorted(re.escape(n.lower()) for n in names if n)))
    return [
        r"(?:%s)\b.{0,20}\b(?:said|asked|told|wants?|needs?|prefers?|thinks?|expects?|directed|mentioned|brought up|decided)\b" % who,
        r"\b(?:his|her|their) (?:take|read|direction|preference|call|view)\b",
        # Question-form user-context query, e.g. "what does the founder want for X".
        # The subject alone is the signal; no specific verb is required, so natural
        # phrasing isn't missed (the gap the regex previously had).
        r"\bwhat (?:does|do|did) (?:the )?(?:%s|he|she|they)\b" % who,
    ]


USER_PATTERNS = user_patterns()

THREAD_PATTERNS = [
    r"\b(?:what happened with|status of|follow up on|update on|where are we on)\b",
    r"\b(?:still (?:open|pending|blocked|waiting)|any progress on)\b",
    r"\b(?:from (?:the|last) (?:handoff|session|conversation))\b",
]

SKIP_PATTERNS = [
    r"^(?:yes|no|ok|thanks|sure|got it|sounds good|shoot|go ahead)\s*[.!?]?\s*$",
    r"^(?:heartbeat|pipeline check|checkpoint|cron)",
    r"^(?:send|dispatch|merge|review|disable|enable)\b",
]

def categories(names=OPERATOR_NAMES) -> list[tuple[str, list[str]]]:
    return [
        ("past_reference", PAST_PATTERNS),
        ("decision_recall", DECISION_PATTERNS),
        ("entity_lookup", ENTITY_PATTERNS),
        ("user_context", user_patterns(names)),
        ("thread_followup", THREAD_PATTERNS),
    ]


ALL_CATEGORIES = categories()


def classify(prompt: str, names=OPERATOR_NAMES) -> tuple[bool, str, list[str]]:
    prompt_lower = prompt.lower().strip()

    for skip in SKIP_PATTERNS:
        if re.match(skip, prompt_lower, re.IGNORECASE):
            return False, "skip_pattern", []

    if len(prompt_lower) < 6:
        return False, "too_short", []

    matched = []
    for category, patterns in categories(names):
        for pat in patterns:
            if re.search(pat, prompt_lower, re.IGNORECASE):
                matched.append(category)
                break

    if matched:
        return True, f"matched:{','.join(matched)}", matched

    return False, "no_trigger", []


def run_tests():
    cases = [
        ("what did we decide about pricing", True),
        ("have we seen this bug before", True),
        ("what happened with the auth migration", True),
        ("is the pricing plan still current", True),
        ("status of the demo", True),
        ("last time we deployed what broke", True),
        ("who is Alice", True),
        ("yes", False),
        ("hi", False),
        ("merge pull request 223", False),
        ("dispatch the agent on the audit", False),
        ("write a test for the heartbeat function", False),
    ]

    passed = 0
    for prompt, expect_recall in cases:
        recall, reason, _ = classify(prompt)
        ok = recall == expect_recall
        if ok:
            passed += 1
        status = "PASS" if ok else "FAIL"
        print(f"  {status}: '{prompt[:50]}' -> recall={recall} ({reason})")

    print(f"\n{passed}/{len(cases)} passed")
    return passed == len(cases)


def main():
    if "--test" in sys.argv:
        success = run_tests()
        sys.exit(0 if success else 1)

    if len(sys.argv) > 1 and sys.argv[1] != "--test":
        prompt = " ".join(sys.argv[1:])
    else:
        prompt = sys.stdin.read().strip()

    if not prompt:
        sys.exit(1)

    recall, reason, categories = classify(prompt)
    print(f"{'RECALL' if recall else 'SKIP'}: {reason}")
    sys.exit(0 if recall else 1)


if __name__ == "__main__":
    main()
