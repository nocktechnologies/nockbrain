# Contributing to NockBrain

Bug reports, fixes and documentation improvements are welcome. This page explains how to run the tests, the rules the code follows, and how a change gets into a release.

## Run the tests

From the repository root:

```sh
python3 -B -m unittest discover -s tests -v
```

`tests/test_smoke.py` runs the real command-line flow in a temporary directory with an empty home directory: `init`, `propose` on `examples/notes.md`, `review`, `apply`, `setup-hooks`, one `Stop` capture, one `UserPromptSubmit` recall, and `status`. It also checks that nothing was written to the home directory. The tests need no network access and no extra packages.

On macOS, also run the tests with the stock interpreter, because Python 3.9 is the floor NockBrain promises:

```sh
/usr/bin/python3 -B -m unittest discover -s tests -v
```

CI runs the same tests on Linux and macOS with Python 3.9 through 3.13, once with the stock macOS `/usr/bin/python3`, and once with `cryptography` installed so the Ed25519 path is covered.

## Rules for the code

NockBrain uses only the Python standard library, and it has to stay that way. The `cryptography` package is optional: when it's importable, new stores sign with Ed25519, and without it they use HMAC-SHA256. Don't add a required dependency, a build step, or a package manager.

Python 3.9 is the minimum. Don't use syntax or library features added after 3.9, such as `match` statements or `X | Y` unions evaluated at runtime. Modules that write `X | Y` in annotations start with `from __future__ import annotations`.

NockBrain stays local. Changes must not add network calls, model calls or telemetry. The only server is Memory Explorer on `127.0.0.1`.

Keep the review-first model intact. Nothing becomes a stored fact without an explicit `apply` of a reviewed proposal digest, and the hooks never apply anything.

## How changes get in

This repository is published from the source tree Nock Technologies maintains. When a pull request is accepted, the change is applied in that source tree and comes back to this repository with the next release, and the contributor is credited in [CHANGELOG.md](CHANGELOG.md). Your pull request may be closed instead of merged here once its change has been applied.

Open an issue before you start a large change, so we can agree on the approach before you spend time on it. Small fixes can go straight to a pull request.

## Keep private data out

Never include real memories, transcripts, store files or keys in issues, pull requests, tests or fixtures. Use fictitious examples like the ones in [examples/notes.md](examples/notes.md). Tests create their stores in temporary directories and delete them afterward.

## Security issues

Don't report vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md) instead.

## Conduct

Everyone who takes part in this project agrees to follow the [code of conduct](CODE_OF_CONDUCT.md).
