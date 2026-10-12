"""End-to-end smoke test for NockBrain, using only the standard library.

Runs the real command-line flow against this checkout with the interpreter
that runs the tests: init, propose, review, apply, setup-hooks, one Stop
capture, one UserPromptSubmit recall and status. HOME points at an empty
scratch directory and must still be empty at the end.

Run from the repository root:

    python3 -B -m unittest discover -s tests -v
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "bin" / "consumer-brain.py"
EXPLORER = REPO / "bin" / "explore-memory.py"
MCP = REPO / "bin" / "nockbrain-mcp.py"
NOTES = REPO / "examples" / "notes.md"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _run_json(argv, cwd, env, stdin=None):
    done = subprocess.run(argv, cwd=str(cwd), env=env, input=stdin, text=True,
                          capture_output=True, timeout=120)
    if done.returncode != 0:
        raise AssertionError("%s exited %d: %s %s" % (
            argv[3:5], done.returncode, done.stdout.strip()[-800:], done.stderr.strip()[-800:]))
    try:
        return json.loads(done.stdout)
    except ValueError:
        raise AssertionError("non-JSON output from %s: %r" % (argv[3:5], done.stdout[:200]))


class SmokeTest(unittest.TestCase):
    def test_end_to_end_flow(self):
        with tempfile.TemporaryDirectory(prefix="nockbrain-smoke-") as name:
            tmp = Path(name).resolve()
            home = tmp / "home"
            home.mkdir()
            env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "PYTHONDONTWRITEBYTECODE": "1"}
            for key in ("LANG", "LC_ALL", "TMPDIR"):
                if key in os.environ:
                    env[key] = os.environ[key]
            cli = [sys.executable, "-B", str(CLI)]
            store = tmp / "store"

            def run(*args):
                return _run_json(cli + list(args) + ["--store", str(store)], tmp, env)

            init = run("init")
            self.assertEqual(str(uuid.UUID(init["store_id"])), init["store_id"])
            self.assertIn(init["algorithm"], ("ed25519", "hmac-sha256"))
            # CI sets this in the job that installs cryptography.
            expected = os.environ.get("NOCKBRAIN_TEST_EXPECT_ALGORITHM")
            if expected:
                self.assertEqual(init["algorithm"], expected)

            notes = tmp / "notes.md"
            shutil.copyfile(str(NOTES), str(notes))
            proposed = run("propose", "--format", "markdown", "--source", str(notes))
            digest = proposed.get("proposal", "")
            self.assertEqual(proposed.get("candidates"), 3, proposed)
            self.assertRegex(digest, DIGEST)

            review = run("review", "--proposal", digest)
            self.assertEqual(len(review["review"]["candidates"]), 3)
            self.assertFalse(review["stale"])

            applied = run("apply", "--proposal", digest)
            self.assertEqual(applied.get("added"), 3, applied)

            transcripts = tmp / "project" / "transcripts"
            transcripts.mkdir(parents=True)
            session = transcripts / "session.jsonl"
            turns = (
                {"type": "user", "timestamp": "2026-10-01T09:00:00Z",
                 "message": {"role": "user",
                             "content": "[DECISION] The quarterly review moves to Thursday."}},
                # Claude Code can append a system reminder to a typed prompt;
                # the importer strips it and counts it.
                {"type": "user", "timestamp": "2026-10-01T09:01:00Z",
                 "message": {"role": "user",
                             "content": "<system-reminder>reminder text</system-reminder>"
                                        "[DIRECTIVE] Send the agenda two days ahead."}},
            )
            session.write_text("".join(json.dumps(turn) + "\n" for turn in turns),
                               encoding="utf-8")
            hooks = run("setup-hooks", "--transcript-root", str(transcripts))
            settings = json.loads(Path(hooks["settings"]).read_text(encoding="utf-8"))

            def hook(event, payload):
                command = settings["hooks"][event][0]["hooks"][0]["command"]
                body = dict(payload, hook_event_name=event)
                return _run_json(shlex.split(command), tmp, env, json.dumps(body))

            stop = hook("Stop", {"transcript_path": str(session), "stop_hook_active": False})
            self.assertIn("pending proposal", stop.get("systemMessage", ""), stop)

            # The applied markdown proposal stays listed as stale; the capture is current.
            current = [entry for entry in run("pending")["proposals"] if not entry["stale"]]
            self.assertEqual(len(current), 1, current)
            captured = run("review", "--proposal", current[0]["digest"])["review"]
            texts = [item["content"] for item in captured["candidates"]]
            self.assertEqual(texts, ["[DECISION] The quarterly review moves to Thursday.",
                                     "[DIRECTIVE] Send the agenda two days ahead."])
            self.assertEqual(captured["stats"].get("system_reminders_stripped"), 1)

            recall = hook("UserPromptSubmit",
                          {"prompt": "What did we decide about the inventory report?"})
            context = recall.get("hookSpecificOutput", {}).get("additionalContext", "")
            self.assertIn("inventory report", context, recall)

            self.assertEqual(run("status")["facts"], 3)
            self.assertEqual(sorted(p.name for p in home.iterdir()), [])

    def test_explorer_help(self):
        done = subprocess.run([sys.executable, "-B", str(EXPLORER), "--help"],
                              cwd=str(REPO), capture_output=True, text=True, timeout=60,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("usage", done.stdout)

    @unittest.skipUnless(MCP.exists(), "bin/nockbrain-mcp.py ships from 0.2.0")
    def test_mcp_recall_and_status(self):
        with tempfile.TemporaryDirectory(prefix="nockbrain-mcp-") as name:
            tmp = Path(name).resolve()
            home = tmp / "home"
            home.mkdir()
            env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "PYTHONDONTWRITEBYTECODE": "1"}
            store = tmp / "store"
            cli = [sys.executable, "-B", str(CLI)]
            _run_json(cli + ["init", "--store", str(store)], tmp, env)
            digest = _run_json(cli + ["propose", "--store", str(store), "--format", "markdown",
                                      "--source", str(NOTES)], tmp, env)["proposal"]
            _run_json(cli + ["apply", "--store", str(store), "--proposal", digest], tmp, env)

            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "1"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                    "name": "recall", "arguments": {"query": "inventory report"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                    "name": "status", "arguments": {}}},
            ]
            done = subprocess.run([sys.executable, "-B", str(MCP), "--store", str(store)],
                                  cwd=str(tmp), env=env, capture_output=True, text=True, timeout=120,
                                  input="".join(json.dumps(r) + "\n" for r in requests))
            replies = {m["id"]: m for m in map(json.loads, done.stdout.splitlines())}
            self.assertEqual(sorted(replies), [1, 2, 3, 4], done.stderr)
            tools = sorted(t["name"] for t in replies[2]["result"]["tools"])
            self.assertEqual(tools, ["recall", "status"])
            recalled = replies[3]["result"]["content"][0]["text"]
            self.assertIn("untrusted historical context", recalled)
            self.assertIn("inventory report", recalled)
            self.assertFalse(replies[3]["result"].get("isError"))
            self.assertIn('"facts": 3', replies[4]["result"]["content"][0]["text"].replace("'", '"'))
            self.assertEqual(sorted(p.name for p in home.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
