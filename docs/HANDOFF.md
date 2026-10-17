# Pod handoff

## Current state

- Work: Nock #11957 standardizes the NockBrain agent docs and adds a CI path
  check. Send the PR URL and head SHA to Rowan on NockCC at closeout.
- What changed: Added the agent index, Claude import, architecture and roadmap
  docs, current handoff, archive policy, path checker, and CI step. The checker
  was simplified and its positive and negative controls pass.
- Starting state: This repository had no `AGENTS.md`, `CLAUDE.md`, or
  `docs/HANDOFF.md`; no earlier pod notes were available.
- What bit us: The supplied relative file-bus command does not resolve from
  this checkout. Running the script from the `crm-mira` checkout returned an
  empty inbox. NockCC denied the read acknowledgment for the matching directive
  with HTTP 403, so it remains unread. The simplification CLI warned that its
  Linux sandbox needed user-namespace support before it could run the review.
- Open: Human review and merge; retry the NockCC acknowledgment only when the
  agent identity issue is resolved.

Update this summary at the end of each run. Store dated handoff snapshots under
`docs/archive/` and keep this file focused on the current state.
