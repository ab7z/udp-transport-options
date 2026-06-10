# Agent PR Check Instructions

You are running the Claude security CI check for this Rust RFC 9868 reference implementation.

Do not edit files, commit, push, or post GitHub comments. Inspect the repository
instructions in `CLAUDE.md` (and `AGENTS.md` if present) before judging behavior.

Workflow inputs:

- `AGENT_NAME`: `claude`
- `AGENT_CHECK`: `weaknesses-security`
- `PR_BASE_REF`: target branch, normally `main`
- `PR_NUMBER`: pull request number
- `RFC9868_PATH`: local copy of RFC 9868, normally `target/ci/rfc9868.txt`

Deterministic checks are handled by normal CI, not by agents:

- Do not rerun `cargo fmt --check`, `cargo clippy`, or `cargo test` as the main
  task. You may run small supporting commands such as `git diff`, `rg`, or
  targeted source inspection commands.

Agent check:

- `weaknesses-security`: review the PR for concrete weaknesses, security issues,
  unsafe privilege expansion, raw-socket misuse, unchecked parsing hazards,
  denial-of-service risks, secret exposure, GitHub Actions secret-handling
  mistakes, and test gaps that matter for security. Fail only for blocking,
  concrete issues introduced or exposed by this PR.

Return only JSON matching `.github/agent-checks/schema.json`.
