# 8. Agentic Behaviors and Their Guardrails

> **This repository:** scheduler = **`maintenance_service.py`**; cluster auto-fixes = **`auto_remediate.py`**; LLM recommendations = **`enhanced_health_monitor.py`** / **`es_health_monitor.py`** (OpenAI or Ollama). Details: [**docs/00**](00-design-spec-vs-this-repo.md).

Three parts of this module take action without a human in the loop.
They run on their own timers, make their own decisions, and — in one
case — commit changes to the Elasticsearch cluster operators rely on.
This section names each one, states the scope of what it is allowed
to do, and documents the specific guardrails that keep it from doing
more.

## 8.1 Agent 1 — the scheduler-driven collector loop

**Source:** [`siem_maint/scheduler.py`](02-cadence.md#21-scheduler-wiring-with-apscheduler)

The APScheduler `BackgroundScheduler` is the first agent. No external
caller requests a probe; the scheduler initiates every call on its own
timer, hands the result to
[`alerting/classify.py`](03-thresholds-and-alert-bands.md#32-transition-alerting-not-sample-alerting),
and either emits or suppresses an alert via
[`alerting/cooldown.py`](05-alert-routing.md#51-the-cooldown-gate).
It observes state, takes the decision on whether to notify, and
persists memory across its own restarts through `last_bands.json` and
`cooldowns.json`.

**Guardrail.** The four-hour cooldown timer per category in
`alerting/cooldown.py` is what keeps it bounded. No matter what any
collector observes, the module can page at most once every four hours
per category, and the five categories — `cluster_health`,
`node_pressure`, `data_freshness`, `model_staleness`, `agent_down` —
run independent timers.

## 8.2 Agent 2 — the remediation loop

**Source:** [`siem_maint/remediation/apply.py`](04-remediation-loop.md#41-investigate-fix-verify) +
[`remediation/fixes.py`](04-remediation-loop.md#42-the-seven-safe-auto-fixes)

The seven auto-fix paths form a closed-loop agent. `apply.py` detects
a condition from the investigate-stage observation data, selects a
pre-approved action from the `FIX_HANDLERS` dispatch table in
`fixes.py`, runs three pre-flight checks, executes the action against
the live cluster, verifies the effect, and appends a structured record
to `audit.jsonl`. It does all of this without any operator approval.

**Guardrails.** Five constraints apply, in order:

1. The fix type must be one of the seven entries on `SAFE_FIX_TYPES`
   — anything else returns `escalate_to_llm` and routes to Agent 3.
2. The target index must not match any of the five hardcoded
   `PROTECTED` patterns — a match returns `blocked_protected` with
   no attempt made.
3. The same fix for the same target cannot have been applied within
   the last 24 hours — a repeat returns `blocked_loop`, preventing
   the failure mode where a fix masks its own recurrence.
4. Every action is verified by re-reading the metric that triggered
   it, and a failed verification becomes an alert rather than a
   retry.
5. The full input and output of every attempt is appended to
   `audit.jsonl` so the sequence of decisions is reconstructable
   after the fact.

Before enabling this agent in production, an operator can exercise
all five guardrails against a staging cluster using
`--dry-run-remediation` (see
[§7.4](07-module-architecture.md#74-command-line-entry-points)),
which runs investigate and prints what `apply_fix` would have done
without mutating the cluster.

## 8.3 Agent 3 — the LLM recommendation agent

**Source:** [`siem_maint/remediation/`](04-remediation-loop.md#44-when-the-llm-gets-involved)
(LLM call) + [`alerting/chat.py`](05-alert-routing.md#52-posting-the-card-to-google-chat) (output)

Issues that fall outside `SAFE_FIX_TYPES` are handed to a local LLM
served by Ollama (default model `gemma4:e4b` — see
[§4.4](04-remediation-loop.md#44-when-the-llm-gets-involved)), which
produces a recommendation rather than a fix. The prompt is
deliberately constrained: it receives only factual observations
expressed as short declarative sentences and is asked for exactly
three outputs — one command to diagnose, one to fix, one to verify.
The three commands are posted to the SIEM-MAINTENANCE chat space by
`alerting/chat.py` so the operator can copy-paste them.

**Guardrails.** Four constraints apply:

1. The agent has no tool access — nothing it writes is executed by
   the module. The only consumer of its output is the operator
   reading chat.
2. The prompt includes the list of `PROTECTED` patterns so
   destructive actions against those indices are explicitly
   discouraged in the model's output.
3. Every call is wrapped in a timeout and a request budget against
   the Ollama server.
4. When the model is unavailable (timeout, model not loaded, or
   network error), the module falls back to a pre-built library of
   recommendations covering eight issue categories.

Because the LLM is local — served by Ollama on the same host — no
observations about the cluster ever leave the host. This was a
deliberate choice over a hosted model: cluster topology, node names,
and index patterns are sensitive enough that a hosted recommendation
agent would have required a separate review.

## 8.4 What the operator still owns

Everything outside the seven auto-fix types is a human decision.
Changes to the threshold bands in `alerting/classify.py`,
modifications to the `PROTECTED` list in `remediation/apply.py`,
approvals for fixes targeted at protected indices, escalation when
`audit.jsonl` shows a pattern of repeat fixes, and every tuning
decision for the collector intervals all require a person.

The module will not promote itself: there is no path by which
Agent 3's output can become an auto-fix, and no mechanism by which
`apply.py` can add a new entry to `SAFE_FIX_TYPES`. Expanding the
auto-fix surface is a code change, reviewed and released through the
normal tarball release process described in
[`docs/09`](09-deployment.md).

---

Previous: [← 7. The siem_maint.monitor module](07-module-architecture.md)
Next: [9. Deployment guide →](09-deployment.md)
