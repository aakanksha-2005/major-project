# Contributing to RASP

Thanks for helping improve RASP — a **prototype** security layer where
honesty about limitations matters as much as features.

## Ground rules

1. **Inspect before you change.** Preserve existing work; ask before
   overwriting anything you did not create.
2. **Small, reviewable changes.** Security-relevant decisions get an
   explanation in the commit message.
3. **Every security fix ships with a regression test.**
4. **Never claim results you did not run.** "Tests pass" only after
   `uv run pytest` actually ran. Report failures honestly.
5. **No overclaims.** No "jailbreak-proof", "100% secure", "bias-free",
   or certification language without evidence.

## Prohibited in this repository

- Credentials, tokens, private keys, or real personal records.
- Disabling authorization/authentication to make tests pass.
- "Just this once" fallbacks that let a denied action through.
- Executing arbitrary model-generated shell commands, SQL, paths, or URLs.
- Connecting to live public-service systems or deploying publicly without
  explicit authorization.

## Workflow

1. `uv sync`
2. Create a focused branch; implement.
3. Quality gate: `uv run ruff check src tests && uv run ruff format --check src tests && uv run pytest`
4. Update docs when behavior or limitations change
   (`docs/LIMITATIONS.md`, README status table).
5. Open a PR describing: what changed, how it was tested, residual risks.

Read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for architecture rules and
the tool-addition checklist.
