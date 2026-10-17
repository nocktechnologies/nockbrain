# Roadmap

NockBrain does not publish dated feature commitments. Large changes should be
discussed in an issue before implementation, as described in
`CONTRIBUTING.md`. This page records the direction supported by the current
product and distinguishes it from a promise of upcoming work.

## Current direction

- Keep memory local and explicit: selected inputs become proposals, and the
  user reviews and applies each proposal before any fact is stored.
- Keep the standard library as the only required dependency and preserve the
  Python 3.9+ support floor on macOS and Linux.
- Keep recall fail-closed on store verification problems and label returned
  memories as untrusted historical reference.
- Keep MCP read-only. Capture outside Claude Code remains an explicit notes
  import through the CLI.

## Current limits

The consumer recall interfaces use lexical matching; semantic search and graph
expansion are not enabled. Automatic capture is Claude Code only. Windows,
semantic recall, and multi-person stores are outside the current release scope.
These limits are not scheduled features. Track proposed changes through GitHub
issues and update this file only when the project makes a concrete commitment.
