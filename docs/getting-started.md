# Getting started

Your first store takes a handful of commands, and the review step is the one to slow down on. Every command here runs from the root of your clone. [Commands](commands.md) has the full reference for each step.

## Check Python

```sh
python3 --version
python3 -c "import cryptography" && echo "Ed25519 available"
```

You need 3.9 or newer. The second line tells you which signing method a new store gets. With `cryptography` installed it's Ed25519, and the public key file is safe to share. Without it the store uses HMAC-SHA256, and both key files hold the same secret, so you keep both private. You don't need to install anything either way.

## Make a store

```sh
STORE="$HOME/nockbrain-store"
python3 bin/consumer-brain.py init --store "$STORE"
```

Pick a path that doesn't exist yet, outside any git repository. `init` creates the folder with access for your user only, writes a fresh signing key, and prints the store ID and algorithm. It never prints key bytes. The store also gets a `.gitignore` that ignores everything in it, as a second line of defense if it ends up inside a repository anyway.

## Write notes NockBrain can read

NockBrain imports Markdown bullet lines that start with `- `. Tag the ones that carry authority, because the importer won't guess that "I decided" means a decision.

```markdown
- [DECISION] Willow Workshop will deliver its weekly inventory report on Friday.
- [DIRECTIVE] Ask the workshop owner before changing the delivery day.
- [CORRECTION] The inventory report covers finished goods, not raw materials.
```

Those three lines are in `examples/notes.md`, and they're made up. Use them for your first run, then switch to your own notes. NockBrain can also import Claude Code transcripts (`.jsonl`) with `--format claude-jsonl`.

## Propose and review

```sh
python3 bin/consumer-brain.py propose --store "$STORE" --format markdown --source "$PWD/examples/notes.md"
python3 bin/consumer-brain.py review --store "$STORE" --proposal FULL_DIGEST
```

`propose` reads only the file you name, redacts text that matches common secret and token shapes, and saves a proposal named by its SHA-256 digest. It prints the candidate count, the digest and the exact review command. Your store is still empty at this point.

Read the whole review. For each candidate, check that the text is accurate and current, the kind is right, and nothing sensitive slipped past the redaction. The stats line counts redactions and anything skipped. If something is wrong, fix your notes, propose again, and discard the old proposal.

## Apply

```sh
python3 bin/consumer-brain.py apply --store "$STORE" --proposal FULL_DIGEST
```

`apply` accepts the whole proposal, signs each new fact and prints how many it added and skipped. There's no way to apply half a proposal. If you only want some of the candidates, write a notes file with just those and propose that instead.

## Look at what you have

```sh
python3 bin/consumer-brain.py open --store "$STORE"
```

Memory Explorer opens in your browser. It's read-only. Browse your facts, open one to see its evidence and verification state, and try the BM25 preview tab with "What did we decide about the inventory report?" to see what recall would pick. Ctrl-C in the terminal stops it. [Memory Explorer](memory-explorer.md) explains every panel.

## Turn on the hooks

```sh
python3 bin/consumer-brain.py setup-hooks --store "$STORE" \
  --transcript-root "$HOME/.claude/projects/YOUR-PROJECT-FOLDER"
claude --settings "$STORE/claude-settings.json"
```

Claude Code keeps one transcript folder per project under `~/.claude/projects/`. Allow the project you want and nothing broader. You can repeat `--transcript-root` to allow a second project. `setup-hooks` writes one file, `claude-settings.json` inside your store, and prints the launch command. The settings point at this clone and this Python by absolute path, so run `setup-hooks` again if you move either one.

Sessions launched with that file get two hooks. On every prompt, the recall hook checks whether you're asking about the past and, if you are, adds matching facts as reference. Each time Claude finishes a reply, the capture hook reads that session's transcript and, if it finds candidates you haven't stored, saves a pending proposal, replacing any earlier pending one from that session, and shows you its digest and candidate count. It never applies anything. Both hooks have time limits and never block Claude Code when something fails.

Your other Claude Code hooks still run alongside these. If you use another memory tool, check `/hooks` inside Claude Code so you know what else is adding context.

## Daily use

Work the way you normally do. Proposals from your sessions wait in the queue.

```sh
python3 bin/consumer-brain.py pending --store "$STORE"
python3 bin/consumer-brain.py review  --store "$STORE" --proposal FULL_DIGEST
python3 bin/consumer-brain.py apply   --store "$STORE" --proposal FULL_DIGEST
python3 bin/consumer-brain.py discard --store "$STORE" --proposal FULL_DIGEST
```

Review in batches when it suits you. Apply what's right and discard the rest. Each session keeps one pending capture proposal, and the newest one always includes everything from the earlier ones. A proposal goes stale once another change lands first; propose again and review the new digest. The queue holds up to 100 proposals, so clear old ones out.

## Fix a fact

Copy the fact ID from Explorer. To correct it, propose a notes file with exactly one replacement fact, then turn that into a correction:

```sh
python3 bin/consumer-brain.py correct --store "$STORE" --fact FACT_ID --replacement-proposal REPLACEMENT_DIGEST
python3 bin/consumer-brain.py review  --store "$STORE" --proposal CORRECTION_DIGEST
python3 bin/consumer-brain.py apply   --store "$STORE" --proposal CORRECTION_DIGEST
```

The old fact stays in history as superseded, and the new one is current. To remove a fact, run `forget --store "$STORE" --fact FACT_ID`, then review and apply its digest the same way. Forgetting clears every saved proposal too, since proposals can hold copies of the text you're removing. Refresh or close Explorer afterward.

## If something gets interrupted

If a change stops halfway, `status` reports that recovery is required and the store refuses new changes until you finish it:

```sh
python3 bin/consumer-brain.py recover --store "$STORE"
```

`recover` completes the change you already accepted, after checking its signed journal. It never applies a pending proposal. Don't edit store files by hand to get past an error.

## Back up and move

Back up the whole store folder with owner-only permissions, and include both `signing-key` and `signing-key.pub`. Losing either one can make the store unusable, and NockBrain won't quietly replace a key. If you move your clone or change Python, run `setup-hooks` again.

## Stop using it

Launch Claude Code without the settings file and NockBrain is out of that session. Nothing outside the store folder was changed, so removing the store folder and your clone removes NockBrain completely.
