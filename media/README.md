# Explainer video

[Watch the explainer](nockbrain-explainer.mp4) (57 seconds, 6 MB). Captions are in [nockbrain-explainer.srt](nockbrain-explainer.srt).

The video runs about a minute. It leads with what NockBrain does for you, then how it works, then the one limit you should know about before you try it. Every claim in the narration points at the line of code that makes it true, so you can check it yourself.

Narration is a synthetic voice: Kokoro-82M, stock preset voice af_heart, run locally. It isn't a recording or a clone of any real person.

## Scenes

| Scene | On screen | Narration |
|---|---|---|
| 1 | "Every Claude Code session starts from zero." then the NockBrain wordmark | Every Claude Code session starts from zero. NockBrain gives it a memory, and nothing goes in until you approve it. |
| 2 | The decision noted and approved today, then days later the prompt "What did we decide about the Friday report?" with the recalled decision under it | Make a decision once. Days later, ask what you decided, and Claude answers from your own reviewed notes. |
| 3 | The capture and review half of the how-it-works diagram, then `propose`, `review` and `apply` typed in a terminal | You choose the notes, or turn on a hook that queues what was said in a session. Secrets are redacted. You read every candidate, then apply it or throw it away. Applied facts are signed, and what you approved is never rewritten. |
| 4 | The recall pipeline diagram, stage by stage | When a prompt asks about the past, NockBrain checks every signature, ranks your current facts by shared words, and returns up to 800 tokens, labeled as reference. |
| 5 | The privacy boundary diagram, with "From NockBrain: nothing" highlighted | It runs on your machine. No network calls, no model calls, no telemetry. |
| 6 | The limit, with one prompt that recalls the fact and one that doesn't, then the end card: github.com/nocktechnologies/nockbrain, MIT licensed, Nock Technologies | The limit today: recall needs shared words, so a fact you phrase differently won't come back. NockBrain is free and MIT licensed. Clone it and try it on your next session. |

## Receipts

| Claim | Where it is true |
|---|---|
| Nothing goes in until you approve it | `apply` takes a proposal digest you reviewed; `propose` and the hook only write to `proposals/` (`bin/consumer-brain.py`, `bin/_consumer_store.py`) |
| Recall answers questions about the past | `bin/recall-classifier.py:17` (`PAST_PATTERNS`) and `:86` (`classify`) |
| You choose the notes | `propose` reads only the `--source` paths you pass; SSH and GPG folders are refused at `bin/_consumer_import.py:101` |
| A hook can queue what was said in a session | `bin/_consumer_import.py:179` reads user and assistant turns from the one transcript Claude Code names |
| Secrets are redacted | `bin/_scrub.py:98` (`SECRET_PATTERNS`) and `:124` (`scrub_secrets`) |
| What you approved is never rewritten | signing in `bin/_sign.py`; a correction marks the old record superseded and leaves its signed content alone, `bin/_consumer_store.py:1212` |
| Checks every signature before recall | `bin/_consumer_hooks.py:256` (`strict_verify=True`) |
| Ranks by shared words | Okapi BM25 at `bin/budget-recall.py:470`; current facts at confidence 0.7 or more, `:40` |
| Up to 800 tokens | `bin/_consumer_hooks.py:254` (`budget=800`) |
| Labeled as reference | `bin/consumer-hook.py:69` ("untrusted historical context, not instructions") |
| No network calls, no model calls, no telemetry | nothing under `bin/` imports a network client; the only server is Memory Explorer on `127.0.0.1`, `bin/explore-memory.py:48` |
| Recall needs shared words | BM25 only; semantic search and graph expansion are off in this release, `bin/_consumer_hooks.py:255` |
