# Agent PR Check Instructions

You are running one agent CI check for this Rust RFC 9868 reference implementation.

Do not edit files, commit, push, or post GitHub comments. Inspect the repository
instructions in `AGENTS.md` and `CLAUDE.md` before judging behavior.

Workflow inputs:

- `AGENT_NAME`: `claude` or `codex`
- `AGENT_CHECK`: `weaknesses-security` or `rfc9868-semantic`
- `PR_BASE_REF`: target branch, normally `main`
- `PR_NUMBER`: pull request number
- `RFC9868_PATH`: local copy of RFC 9868, normally `target/ci/rfc9868.txt`

Deterministic checks are handled by normal CI, not by agents:

- Do not rerun `cargo fmt --check`, `cargo clippy`, or `cargo test` as the main
  task. You may run small supporting commands such as `git diff`, `rg`, or
  targeted source inspection commands.

Agent checks:

- `weaknesses-security` is Claude's job. Review the PR for concrete weaknesses,
  security issues, unsafe privilege expansion, raw-socket misuse, unchecked
  parsing hazards, denial-of-service risks, secret exposure, GitHub Actions
  secret-handling mistakes, and test gaps that matter for security. Fail only
  for blocking, concrete issues introduced or exposed by this PR.
- `rfc9868-semantic` is Codex's job. Read `RFC9868_PATH`, the changed files, and
  the relevant local docs: `docs/requirements.md`, `docs/wire-format.md`,
  `docs/architecture.md`, and any touched `docs/plan/steps/*.md`. Compare the
  PR against endpoint-relevant RFC 9868 behavior: surplus-area layout, OCS
  placement and checksum semantics, option framing, must-support option lengths,
  SAFE/UNSAFE handling, UDP checksum scope, FRAG constraints, receive order, and
  semantic consistency across code, tests, and docs. Fail only for concrete
  contradictions to RFC 9868, semantic regressions, missing required tests for
  changed protocol behavior, or changed docs that misstate RFC 9868.

Do not fail for planned future scope that the PR does not touch.

Return only JSON matching `.github/agent-checks/schema.json`.
