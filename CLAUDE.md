# CLAUDE.md — how the agent works on Lyntinel

Lyntinel is a security AI agent: an orchestration and correlation layer over the
tools a security team already runs (see `README.md`). This file defines the
**working process** every change must follow, so that builds are consistent and
safe to trust in a security context.

## Golden rule

**Lyntinel augments the security stack; it never replaces it.** AI-generated code
does not stand in for a vetted vendor product. Everything here adds correlation,
prioritisation and triage *on top of* the tools a team already runs. Keep this
framing in code and docs.

## The development workflow (non-negotiable)

Work like a developer, not a script-runner:

1. **Branch.** Never commit directly to `main`. Create a branch per change
   (`feat/…`, `fix/…`, `chore/…`).
2. **Test-first discipline.** Run the full test suite before and after your change:
   `python3 -m unittest discover -s tests -t .` (stdlib `unittest`, no pytest —
   the standard-library-only rule applies to test deps too).
   - If the change adds or alters behaviour and **no test covers it, write the
     test** as part of the same change.
   - A change is not done while any test fails.
3. **Commit the tests too** — the new/updated tests go in the same commit/PR as
   the code they cover.
4. **Open a PR**, not a direct merge. The PR description states what changed, why,
   and how it was verified.
5. **A human merges.** The agent never self-merges. Merge only on green tests +
   human review.

If you cannot satisfy a step (e.g. a test is genuinely infeasible), stop and say
so in the PR — do not skip it silently.

## Safety principles (these are the product)

- **Human-in-the-loop by default.** Reads are free; every WRITE or DESTRUCTIVE
  action stops at an approval gate (`core/safety.py: ApprovalGate`).
- **Break-glass is the only exception.** It is designed for a *confirmed,
  time-critical* compromise (the dashboard's event-driven breach response) and is
  not implemented in the agent. If it is ever built, it must be logged and
  configurable per severity — never the default path.
- **No hallucinated findings.** Every claim carries an evidence label
  (CONFIRMED / INFERRED / UNKNOWN / SIMULATED). A guess must never render as a fact.

## Data sources

- Every source reads labelled mock data from `data/mock/`
  (`scenarios/appsec/connectors.py`). The connectors cannot reach the network,
  and a test enforces it.
- Secrets are never hard-coded or committed. `.env` is gitignored, and the
  conventions test fails if a GitHub token, AWS key or private key is committed.

## Conventions

- Integrations are named by category (AppSec scanner, EDR, ticketing…), never by
  vendor — and that includes vendor-specific endpoint paths and field names.
  `tests/test_conventions.py` enforces this.

## Repo map

```
core/         safety.py (gate/evidence/boundary), scoring.py, report.py
scenarios/    appsec (connectors, enrich, assistant, run), infra, trends, threatmodel, review
data/mock/    labelled mock payloads
docs/         limitations.md, screenshots/
dashboard/    dashboard.html (concept demo)
tests/        stdlib unittest suite
```

## Environment

- Python 3.9+, standard library only (keeps the agent's own supply chain tiny).
- Run scenarios with `python3 -m scenarios.<name>.run` (add `--auto` for hands-off).

## When adding a capability

1. Reuse `core` (gate, evidence, scoring) — don't reinvent safety plumbing.
2. Keep reasoning auditable; if an LLM is introduced, it sits *behind* the gates,
   not around them.
3. Add mock data + a test; label everything simulated.
4. Update the relevant doc in `docs/`.
