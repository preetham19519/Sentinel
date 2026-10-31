# Sentinel — AI Incident Investigation Prototype

Sentinel is a local-first demo that investigates controlled application faults using evidence, bounded diagnostics, and an optional Ollama model. The model can select read-only checks and propose a diagnosis; Python validates its output, recovery requires human approval, and the demo verifies the result. The earlier distributed-log parser remains available as a deterministic baseline.

See [PROJECT_REPORT.md](PROJECT_REPORT.md) for scope, evaluation methodology, recorded results, limitations, and resume wording. This is a portfolio prototype, not a production incident-response system.

## Run the prototype

Requires Python 3.10 or newer; there are no third-party dependencies.

```powershell
python loginvestigator.py sample-logs --workers 4 --output report.json
```

The first version reads JSON Lines and common syslog-style text, detects repeated authentication failures, disk warnings, service crashes, and resource pressure, then emits evidence-linked JSON with heuristic-ranked causes. `--workers 1` runs the serial baseline; higher values use Python worker processes to parse file partitions in parallel.

To ask an OpenAI-compatible model for a second ranking, point it at a local or hosted endpoint. For example, a local Ollama-compatible endpoint can be passed as `--llm-endpoint http://localhost:11434/v1 --model <model-name>`. The deterministic report still works if no model is configured or the model call fails. Set `OPENAI_API_KEY` only when the chosen endpoint requires it. The model output is kept separate from the heuristic baseline, and its cited evidence IDs are checked against the input records.

The current prototype analyzes offline files. Network telemetry correlation, clock-skew handling, a multi-agent coordinator, MPI support, and scaling benchmarks are planned research milestones rather than implemented features.

## Run the Sentinel investigation slice

The separate `sentinel.py` prototype adds a bounded, fixture-backed investigation loop without changing the original CLI:

```powershell
python sentinel.py scenarios/service-crash/incident.json --max-steps 3 --output investigation.json
```

It begins with crash log evidence, then selects up to three allowlisted read-only diagnostics from the scenario fixture (memory history, deployment history, and host events). The JSON report records the hypotheses, supporting and contradicting evidence IDs, tool calls, and stop reason. It performs no remediation and does not expose shell access. See [ARCHITECTURE.md](ARCHITECTURE.md) for the intended boundaries and [scenarios/service-crash/incident.json](scenarios/service-crash/incident.json) for the scenario inputs.

Diagnostic selection is priority-ranked from the current unresolved questions and missing evidence. Each recorded action includes the selection reason and priority so the investigation path can be reviewed.

To enable the model-driven investigation loop, provide an OpenAI-compatible endpoint and model:

```powershell
python sentinel.py scenarios/service-crash/incident.json --planner-endpoint http://localhost:11434/v1 --model <model-name> --max-steps 3
```

The model proposes and revises evidence-cited hypotheses and chooses the next diagnostic from the currently eligible read-only tools. The coordinator validates the response schema and every cited evidence ID; tool execution remains allowlisted and bounded. If a model call fails, Sentinel records the fallback and uses its deterministic planner. Each model request has a 180-second default timeout, adjustable with `--llm-timeout`. For a first local run, load the model once with `ollama run qwen3:4b`, then exit the chat and run Sentinel. Set `OPENAI_API_KEY` only when the endpoint requires it. The default run remains deterministic and works offline.

### Local browser interface

Start the interface from the project folder:

```powershell
python sentinel_web.py
```

Then open [http://127.0.0.1:8765](http://127.0.0.1:8765) in your browser. Keep the terminal open while using it; press `Ctrl+C` there to stop the local server. The page lets you choose a bundled scenario, set a diagnostic limit, and watch the investigation timeline, hypotheses, evidence, and read-only tool calls. With **Use Ollama model** selected, Ollama must be running and the chosen model (the default is `qwen3:4b`) must already be downloaded. Turn it off to use the deterministic planner.

This first interface runs the existing scenario fixtures; it does not yet accept arbitrary uploaded logs or connect to live production systems. It runs no shell commands and has no remediation controls. The Ollama API address is used by the Python server; opening `http://localhost:11434/v1` in a browser is not the Sentinel interface and may show a 404 because it is an API endpoint.

### Full-stack live demo playground

To demonstrate a live application incident and bounded recovery, start the separate local demo:

```powershell
python demo_app.py
```

Open [http://127.0.0.1:8780](http://127.0.0.1:8780). This playground serves a small orders page, a Python API, and a SQLite database created under `demo-data/`. Fault buttons inject an API 500, a slow API response, a real SQLite exclusive lock, invalid API configuration, worker-pool exhaustion, or a shipping dependency outage. With **Use local Ollama planner** enabled, Sentinel asks the local OpenAI-compatible Ollama endpoint (`http://localhost:11434/v1`, default model `qwen3:4b`) which bounded read-only diagnostic to run next, then asks it to form evidence-cited hypotheses and a diagnosis. Python validates tool names, cause IDs, and evidence references; if the model is unavailable or returns invalid output, the planner trace shows a deterministic fallback. It requests JSON output with reasoning disabled for compatibility with thinking models. It can select up to two diagnostics, with a 20-second per-call timeout and a 55-second total investigation budget. Disable the checkbox for a rules-only baseline. If Sentinel identifies a bounded recovery, it presents the action and risk for approval. **Approve & recover** executes that exact saved proposal only if the incident is unchanged, then verifies the API, database, and dependency; **Cancel** leaves the fault in place. **Clear injected fault** resets the demo directly.

The **Run evaluation** button starts a background comparison across all six fault controls, running the deterministic baseline and Ollama planner on each one. The page polls progress and shows per-planner cause accuracy, validated diagnoses, tool selections, abstentions, and fallbacks. Each completed run is saved as JSON under `demo-data/evaluations/` and can be opened from the page. The evaluator resets only the demo fault fixture between runs; it never approves or runs Sentinel recovery actions. The 12 investigations can take several minutes with local inference. End-to-end accuracy includes fallback cases; consult the separate validated-diagnosis count before attributing accuracy to Ollama.

Recovery is limited to the demo's in-memory fault state and its held SQLite lock. SQLite lock injection owns a dedicated connection; Sentinel releases that exact connection and verifies the database query before reporting recovery. Sentinel does not run commands, change host settings, or access another application. The page is bound to `127.0.0.1` and uses demo data; it is not a production incident response tool and does not claim to fix arbitrary application failures. After updating this code, restart an already-running `demo_app.py` process so it loads the recovery changes.

To see how it handles missing telemetry, run:

```powershell
python sentinel.py scenarios/service-crash-incomplete/incident.json --max-steps 3
```

With no diagnostic tools available, hypotheses should remain unresolved and the report should say there is insufficient evidence.

For a case where both a memory increase and a recent deployment are plausible, run:

```powershell
python sentinel.py scenarios/service-crash-ambiguous/incident.json --max-steps 3
```

The report should show both leads as evidence-backed but unresolved; a deployment occurring before a crash is not proof that it caused the crash.

Run the fixture evaluation suite with:

```powershell
python sentinel.py --evaluate evaluation.json --max-steps 3
```

The manifest contains expected hypothesis statuses separately from the investigator inputs. The report lists per-scenario checks, diagnostic call counts, and an aggregate pass rate. A pass only means the current scenarios match their declared expectations; it is not evidence of general diagnostic accuracy.

The suite also includes a diagnostic outage case. The memory check is selected but returns no data; Sentinel records it as unavailable, moves on to other checks, and keeps the memory trend listed as unknown.

It also includes a database connection-pool incident. Sentinel checks pool occupancy/connection age and request volume, then compares a connection-leak hypothesis with a traffic-spike hypothesis. The fixture is deterministic and does not represent a live database integration.

### Optional AI planner

Sentinel can ask an OpenAI-compatible model to choose the next diagnostic from the currently eligible read-only tools:

```powershell
python sentinel.py scenarios/service-crash/incident.json --max-steps 3 --planner-endpoint http://localhost:11434/v1 --model <model-name>
```

Set `OPENAI_API_KEY` only if the endpoint requires it. Without `--planner-endpoint`, Sentinel uses the deterministic planner. The model proposes only a tool name and rationale; Python validates the tool against the current allowlist and executes the fixture-backed implementation. Invalid responses and provider failures fall back to deterministic planning and are recorded in the report. The prompt includes log evidence, so use local inference for sensitive data and do not send secrets or personal data to an unapproved endpoint.

## Project question

In a controlled local demo, can an Ollama-backed investigator choose useful diagnostics and produce evidence-linked causes, while remaining bounded and requiring approval for recovery?

## Implemented architecture

```text
Six local fault injectors
        ↓
Orders API + SQLite + demo logs
        ↓
API probe → Ollama or rules select up to two read-only checks
        ↓
Cause/evidence validation → investigation report
        ↓
Human approval → bounded demo-only recovery → health verification
```

Ollama output is advisory and may abstain. Python validates selected tool names, known cause identifiers, and evidence IDs; invalid output falls back to rules and is recorded. A valid evidence ID establishes that a source exists, not that the model's interpretation is semantically correct. Scores are model-assigned, not calibrated probabilities. Recovery is limited to this local demo and requires explicit approval.

## Longer-term research ideas (not implemented)

Potential extensions include additional ambiguous and adversarial fixtures, real but read-only telemetry adapters, clock-skew-aware cross-service correlation, and throughput tests. Multi-agent orchestration, production integrations, MPI/HPC scaling, and automatic changes to real services are outside the current prototype.

## Current evaluation

The deterministic CLI suite contains five scenarios: clear OOM, incomplete evidence, ambiguous memory-versus-deployment evidence, diagnostic outage, and database-pool exhaustion. The latest run passed **5/5** declared checks with 11 diagnostic calls. This is a small synthetic fixture suite, not a general accuracy claim.

The live browser evaluation compares deterministic and Ollama investigation over six injected faults, records model validation/fallback/abstention separately from end-to-end accuracy, and saves completed results under `demo-data/evaluations/`. The latest measured result and its limitations are documented in [PROJECT_REPORT.md](PROJECT_REPORT.md).

## Scope and safeguards

- The browser demo runs only on localhost and uses disposable local demo data.
- The LLM has no direct tool or shell access; tool execution stays in Python and is allowlisted.
- Recovery is offered only for known injected demo faults and requires human approval.
- Evaluation performs fixture setup/teardown but never approves Sentinel recovery.
- Do not send secrets or personal data to an unapproved model endpoint.
