# Limitations

Lyntinel is a capability demonstration, not a production system. This page lists everything that is simulated, unbuilt or still an open problem. The agent labels every claim with the evidence behind it, and this page applies the same standard to the project itself.

---

## 1. Every source is simulated

Every source Lyntinel reads is mocked: the AppSec scanner, source control, EDR, email security, awareness platform, ticketing, GRC platform, asset inventory and exploit intel. Every simulated value is labelled at runtime, with `[SIM]` in the sources list and `[SIMULATED]` on each claim derived from it.

The mock data is realistic enough to exercise the triage, scoring and correlation logic end to end. The dashboard (`dashboard/dashboard.html`) is canned throughout.

## 2. The reasoning is rules, not a language model

Triage, enrichment, scoring, remediation text and threat suggestions all come from deterministic Python rules, not a language model. The README's Purpose section explains why. The "Claude reasoning" answers in the dashboard are pre-written examples, not model output.

## 3. The data is fictional

`payments-service`, its users, the risk register, the scan history and all of the business context are invented. The CVEs are real, but their reachability, acceptance status and context are made up for the scenario. Nothing here is a finding about a real system.

## 4. Nothing is actually written anywhere

"Filing a ticket" produces the ticket text and records the approval. It doesn't reach any ticketing system. "Quarantining a host" prints a line. This keeps the demo safe to run anywhere, but it also means the write path hasn't been built. That path (authentication, error handling, retries, idempotency) is real work.

## 5. The scoring model is a starting heuristic

The composite score in `core/scoring.py` (internet-facing +20, formally accepted −30, and so on) is a reasonable first draft, not a calibrated model. The weights are round numbers chosen to produce a sensible ordering. In production they would need tuning with a security team against real historical incidents. They all sit in one small file so they're easy to find and argue about.

## 6. Coverage is narrow

- One application, one threat model and a handful of findings. A real estate has thousands.
- The OWASP mapping and the control-coverage inference are small keyword tables, so they will mis-map inputs they haven't seen.
- The threat-modelling assistant runs a fixed rule set. It misses threats outside its rules and reads text only, not diagrams.
- There is no de-duplication across scanners, no history of a finding's lifecycle, and no SLA tracking.

## 7. Securing the agent itself is only partly addressed

The controls that are built in are described in the README. These problems are not solved:

- **Prompt injection through the data the agent reads,** such as a malicious finding title or a poisoned threat model. This becomes a real risk once a model is in the loop. Today's deterministic rules are largely immune, but that's a side effect of the demo, not a defence. The direction to take is to treat all tool output as untrusted input, and never let it widen the agent's permissions.
- **Secrets management.** A deployed agent would need credentials for every tool it reads, held in a vault rather than on disk. That isn't built.
- **Who can approve what.** Anyone at the terminal can approve an action. Production needs real identity, plus role checks on who may approve which actions.
- **Break-glass.** Before the dashboard's autonomous containment could be built, its trigger threshold and the actions it's allowed to take would need agreeing with a security team, and testing.
- **Supply chain.** Using only the standard library keeps the agent's own attack surface small. A production build would add dependencies, and each one would need the same scrutiny.