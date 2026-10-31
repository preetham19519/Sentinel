# Sentinel: Incident Investigation Agent

## Project direction

Sentinel is an experimental, local-first system that investigates operational incidents through a bounded observe–hypothesize–check loop. It starts from the existing Distributed Log Investigator prototype and evolves from offline batch analysis toward a reproducible agent experiment. It is not yet an autonomous production remediation system.

The central question is:

> When evidence is incomplete or competing causes are plausible, does a bounded investigator that selects evidence-gathering tools improve diagnosis quality and evidence coverage over a one-shot LLM ranking or fixed playbook, without increasing unsafe recommendations?

This is a candidate research question, not a claim of novelty. Commercial tools already describe hypothesis-driven telemetry investigation and operational actions. RCAEval provides 735 failures across three microservice systems and reproducible baselines; newer datasets such as AnoMod add logs, metrics, traces, API responses, and code coverage. Sentinel should compare against this prior work and identify a precise gap before claiming contribution.

## What exists today

`loginvestigator.py` is a useful baseline: it parses JSONL and syslog-like records, applies deterministic pattern detectors, groups events, ranks a few causes heuristically, optionally asks an OpenAI-compatible endpoint for a second ranking, validates cited evidence IDs, and writes a JSON report with an input checksum. It has no durable investigation state, iterative tool selection, metrics/traces adapters, evidence graph, action authorization, or recovery verification. Parallel parsing is implemented; MPI, live collection, multi-agent coordination, and remediation are not.

Keep the parser, deterministic detectors, heuristic ranking, provider boundary, and file-based reproducibility metadata as a baseline. Refactor them behind interfaces as the investigation loop grows; do not replace the baseline with an LLM-only system.

## Architecture and answers to the six design questions

### 1. Observations

An incident begins with a trigger or a manually supplied event window. Version one accepts offline JSONL/syslog files. Later adapters can provide host/service metrics, deployment events, traces, health checks, and synthetic test outcomes. Normalize each observation into an immutable record with a stable ID, source, timestamp, clock-quality/offset metadata when known, host, service, kind, attributes, and a redacted payload reference. Preserve raw source data separately; tool outputs must identify their source and collection time.

### 2. Next-step selection

The coordinator keeps a typed investigation state: incident scope, current hypotheses, evidence references, unanswered questions, tool budget, action history, and stop reason. A deterministic policy or LLM proposes one next read-only diagnostic with a rationale and the hypothesis it will discriminate. A policy gate validates the proposal against available tools, scope, budget, and schemas before execution. The result is added to state, hypotheses are revised, and the loop repeats until evidence is sufficient, the budget is exhausted, no useful tool remains, or human input is required. The system must be able to stop with “unknown / insufficient evidence.”

### 3. Tools

Use narrow, typed tools, not arbitrary shell access. Initial tools: search records in a bounded time window; summarize event counts by host/service; retrieve a metric series from a fixture; inspect service/deployment status from a fixture; query a dependency map; run a health check against a disposable test service. Every tool declares read/write class, allowed scope, input/output schema, timeout, and whether approval is required. Tool arguments and results are stored in the investigation trace. Treat log text as untrusted data, never instructions.

### 4. Evidence and competing causes

Represent observations, derived facts, hypotheses, and relationships as separate typed objects. Each hypothesis has a statement, status (candidate / supported / weakened / unresolved), supporting evidence IDs, contradicting evidence IDs, missing evidence, and calibrated score or explicit qualitative confidence. Edges record relations such as precedes, same-service, dependency-of, supports, contradicts, and derived-from. Do not claim causality from timing alone. Reports distinguish observed facts from inference and disclose missing modalities or collection gaps.

### 5. Allowed actions

Default mode is read-only. The model cannot call a shell or arbitrary URL. In later isolated experiments, remediation actions are an explicit allowlist of reversible operations against disposable services (for example, restart a fixture service or roll back a fixture configuration). The action proposal must include expected effect, evidence, blast radius, reversibility, and rollback. A policy engine checks scope and risk; the human approval boundary is explicit. No production writes, credential blocking, package installation, or unrestricted computer control.

### 6. Recovery verification

An action is not considered successful because the command returned success. Before an action, define observable success criteria (health endpoint, error rate, restart count, or a metric returning to baseline) and a bounded verification window. Collect before/after observations, evaluate those criteria, and report recovered / not recovered / inconclusive. Capture side effects and rollback status. If verification fails, stop or return to diagnosis; do not repeatedly apply actions without a new authorization policy.

## Investigation lifecycle

```text
Trigger or supplied event window
  -> collect bounded observations
  -> detect and scope incident
  -> create competing hypotheses
  -> choose one diagnostic question/tool
  -> policy-check and run tool
  -> append evidence and update hypotheses
  -> stop, ask for human input, or continue within budget
  -> report diagnosis and safe options
  -> (sandbox only, after approval) execute allowlisted action
  -> verify against predeclared criteria
  -> record outcome for evaluation
```

The investigation trace is the source of truth. The human-readable report is generated from this trace, not from hidden model reasoning. Store concise rationales, tool calls, outputs, evidence references, and state changes; do not depend on private chain-of-thought.

## Proposed repository shape

```text
src/sentinel/
  domain/        incident, observation, hypothesis, action, report schemas
  ingestion/     JSONL and syslog readers; later telemetry adapters
  detection/     deterministic event detectors and correlation
  investigation/ coordinator, policies, budgets, stop conditions
  tools/         typed read-only fixture tools and later adapters
  models/        provider interface and structured-output validation
  evidence/      provenance store and graph queries
  remediation/   sandbox-only allowlisted actions and verification
  reporting/     JSON and Markdown reports
tests/           unit, contract, and scenario tests
scenarios/       versioned fixtures, fault definitions, ground truth
docs/            design decisions, threat model, experiment protocol
```

Do not build this entire tree up front. Introduce modules only as each milestone needs them. A persistent database, web UI, live packet capture, MPI, and multi-agent roles are optional later experiments, not initial requirements.

## Evaluation and candidate contribution

Build scenario fixtures with ground-truth fault injection metadata and include: obvious cause; two plausible causes; misleading/incorrect first hypothesis; missing modality; clock skew; no safe fix; successful recovery; failed recovery; and prompt-injection-like strings inside logs. Keep scenario labels hidden from the agent. Use a disposable local service or deterministic simulator before any real service integration.

Compare at least:

1. Existing deterministic heuristic baseline.
2. One-shot LLM ranking from the same initial evidence.
3. Fixed diagnostic playbook.
4. Bounded iterative investigator with the same tool budget.

Report top-1/top-3 cause ranking, evidence precision/recall or citation validity, unsupported-claim rate, correct abstention rate, useful diagnostic yield, number/cost of tool calls, end-to-end latency, action safety violations, and recovery success/verification accuracy. Run each model-backed scenario repeatedly and record model/provider, prompt version, temperature, fixture hash, and tool policy. Use ablations to isolate the effect of iterative planning, tool access, and evidence graph representation. Avoid claiming broad generalization from a small synthetic suite.

Candidate gap to test: *diagnostic action efficiency under ambiguity and incomplete evidence, with calibrated abstention and recovery verification*. Existing RCA datasets chiefly support fault localization from collected telemetry; vendor products already perform tool-assisted incident investigation. Sentinel can contribute an open, controlled experiment on whether active evidence acquisition and explicit stop/verification policies improve performance over one-shot and fixed-playbook baselines under a student-scale, reproducible test harness. Validate this against current literature before presenting it as novel.

## Milestones

1. **Baseline and schemas:** preserve current CLI behavior; define typed incident, observation, hypothesis, evidence reference, and report schemas; add scenario format.
2. **Reproducible scenarios:** create small fixtures covering memory/OOM, deployment regression, misleading evidence, missing data, and no-fix cases. Establish baseline metrics.
3. **Investigation loop:** add bounded state, tool registry, read-only fixture tools, budgets, and explicit stop reasons. Initially use deterministic planning so behavior is testable.
4. **LLM planner:** implemented as an optional OpenAI-compatible next-tool selector. It returns a tool name and rationale, and Python validates the selection against currently eligible read-only tools. Provider errors or malformed/unsafe selections fall back to the deterministic planner. Evaluation against the deterministic planner and one-shot ranking remains future work.
5. **Evidence graph and report:** represent support, contradiction, temporal order, and dependencies with provenance; expose concise evidence-backed explanations and unknowns.
6. **Sandbox recovery:** add one or two allowlisted reversible actions for a disposable service, with human approval and predeclared verification checks.
7. **Research evaluation:** run baselines/ablations on a larger scenario suite and, if feasible, a public benchmark; document limitations and reproducibility details.

## Safety and privacy

- The first useful agent is read-only and offline by default.
- Never pass secrets, tokens, or unredacted personal data to a model provider.
- Do not expose arbitrary shell, filesystem writes, network destinations, or production APIs as model tools.
- Enforce scope, schema validation, timeouts, output limits, and call budgets outside the model.
- Treat retrieved logs, issue text, and tool output as untrusted content.
- Require human authorization for every sandbox remediation during early development.
- Preserve an auditable trace and support deterministic replay of fixture-based investigations.

## Initial reading

- Pham et al., [RCAEval (2024 preprint; published 2025)](https://arxiv.org/abs/2412.17015): 735 failure cases across three systems and 15 reproducible baselines.
- Ping et al., [AnoMod (2026)](https://arxiv.org/abs/2601.22881): multimodal logs, metrics, traces, API responses, and code coverage, with performance, service, database, and code anomalies.
- Datadog, [Bits Agent Builder documentation](https://docs.datadoghq.com/actions/agents/) and [Bits investigation documentation](https://docs.datadoghq.com/bits_ai/bits_investigation/investigate_issues/): examples of commercial tool-using operational agents and hypothesis validation.
- Bogomolov and Borisenko, [OpenStack-RCA-Bench (ASE 2026)](https://conf.researchr.org/details/ase-2026/ase-2026-tools-and-data-sets/58/OpenStack-RCA-Bench-A-Reproducible-IaaS-Root-Cause-Analysis-Dataset): reproducible injected incidents and a useful reminder that zero-shot LLM RCA can remain difficult.

