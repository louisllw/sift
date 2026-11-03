# Contributing to Sift

Thanks for taking a look — contributions are very welcome, whether it's a bug report, a new
delivery backend, a diagnostic for the exec allowlist, or docs.

## Guiding principles

Sift stays small and boring on purpose:

- **Zero runtime dependencies.** The server is Python 3 standard library only; the agents are
  POSIX `bash` + `curl`. Please don't add pip/apt dependencies — if something needs a library,
  it probably belongs behind the optional LLM endpoint or as a separate opt-in.
- **Fail open, never drop.** If the AI is unreachable, events must still get through.
- **Read-only stays read-only.** The remote-exec feature is a fixed allowlist run as an argv
  array (no shell). Anything that could write, install, restart or delete does **not** belong in
  it. New diagnostics must be read-only and argument-validated on both the server and the agent.
- **Outbound-only agents.** Agents dial out; the server never connects into a host. Keep it that
  way — no inbound agent ports, no stored credentials on the server.
- **Privacy.** No personal hostnames, IPs, tokens or real config in the repo. `config.json`,
  `data/`, `*.db` and `compose.yml` are git-ignored; keep real values there.

## Dev setup

```sh
git clone https://github.com/louisllw/sift && cd sift
cp config.example.json data/config.json     # edit: ingest_token, optional llm, delivery
python3 sift.py data/config.json             # runs on :8130, no build step
```

Open `http://localhost:8130/`, set an admin password, and publish a test event (see the README
quickstart). Rules-only mode (no `llm` block) is the quickest way to iterate without a model.

## Before you open a PR

- Keep it stdlib/bash-only and run a quick syntax check: `python3 -m py_compile sift.py` and
  `bash -n agents/*.sh`.
- Test the path you touched end to end where you can (ingest → triage → delivery, or an agent
  round-trip).
- One focused change per PR, with a short description of the behaviour before/after.

## Reporting bugs / ideas

Open an issue with what you expected, what happened, your config shape (redact secrets!), and
relevant logs. Feature ideas and "this was confusing" notes are just as useful as bug reports.

By contributing, you agree your contributions are licensed under the project's MIT License.
