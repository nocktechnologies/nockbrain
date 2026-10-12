# FAQ

## Does NockBrain send my notes anywhere?

No. It makes no network calls, no model calls and sends no telemetry. The one path off your machine is Claude Code's own conversation with Claude, which carries any facts the recall hook adds to a prompt. [Privacy and security](privacy-and-security.md) has the details.

## Do I need an API key or a model?

No. NockBrain is plain Python using only the standard library. Recall is keyword scoring that runs locally inside the hook's five-second limit, so nothing goes to a model to decide what's relevant.

## Why do I have to review everything?

Automatic extraction gets things wrong. It keeps a passing idea as a decision, or misses that you changed your mind an hour later. Review means every fact in your store is one you read and agreed with, so anything Claude recalls is something you already approved.

## How is this different from CLAUDE.md?

CLAUDE.md loads in full at the start of every session, which suits standing instructions. NockBrain holds the growing pile of decisions and corrections that would bloat CLAUDE.md, and hands Claude only the ones that match when you ask about the past. Each fact is signed and points back to the line it came from. Use both.

## Why didn't it recall a fact I stored?

Check these in order. The session has to be launched with `claude --settings "$STORE/claude-settings.json"`. Your prompt has to read as a question about the past; "what did we decide about the Friday report" does, "write the report" doesn't. The fact has to share words with your question, and when the question has three or more meaningful words it has to share at least two. This release matches words and has no semantic search. It also has to be current, with a confidence of 0.7 or more. The BM25 preview tab in Memory Explorer shows you what recall would pick for any prompt.

## What does "signed" get me?

It proves the store hasn't changed behind your back. Each fact is signed when you apply it, and every recall checks every signature and the revocation chain first. A fact edited by hand, a deleted revocation or a forgotten fact that reappears fails the check, and recall adds nothing until you sort it out.

## Does it work with other coding agents?

The commands and the store work anywhere Python runs. The automatic capture and recall hooks are written for Claude Code's hook system, so that's the only agent they plug into today.

## Does it run on Windows?

Not in this release. It supports macOS and Linux.

## Can my team share a store?

It's built for one person and one store. You can copy the whole folder as a backup, keys included. Two people or two machines writing to the same store isn't supported; the write lock only covers one machine.

## Is it free?

Yes. It's MIT licensed, so you can use it, change it and ship it in your own tools.

## Who makes it?

Nock Technologies. Questions go to info@nocktechnologies.io, and bugs go in this repository's issues.
