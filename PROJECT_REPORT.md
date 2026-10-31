# Sentinel: AI Incident Investigation Prototype

## Summary

Sentinel is a local-first prototype that investigates faults in a disposable orders application. It combines a Python API, a SQLite database, controlled fault injection, bounded diagnostics, an optional Ollama planner, human-approved recovery, and post-recovery verification.

The prototype demonstrates an investigation workflow. It does not repair arbitrary websites, browsers, operating systems, or production services.

## What the demo does

1. Inject one of six controlled faults into the local demo: API handler error, slow API, SQLite lock, invalid configuration, worker-pool exhaustion, or shipping dependency outage.
2. Probe the API and select up to two read-only diagnostics from an allowlist. Ollama may select a diagnostic or abstain; a deterministic fallback is recorded when the model response is invalid or unavailable.
3. Generate competing causes and a diagnosis. Python validates the cause identifier and evidence references; model output is displayed as an inference, not ground truth.
4. Present the bounded recovery and risk. Sentinel waits for approval and checks that the incident has not changed.
5. Apply only a demo-owned fault reset or release the exact SQLite lock connection created by the demo, then verify the API, database, and dependency.

The demo binds to `127.0.0.1`. It has no shell tool and does not change host settings or access other applications.

## Evaluation

The browser evaluation compares a deterministic baseline and the Ollama path across the six injected faults. It reports end-to-end diagnosis accuracy separately from validated model diagnoses, model-selected tools, abstentions, and deterministic fallbacks. End-to-end Ollama accuracy includes fallback cases and must not be presented as model-only accuracy.

Each completed browser evaluation is saved as JSON under `demo-data/evaluations/` and can be opened from the page. Evaluation resets the demo fault fixture between runs. It does not approve or execute Sentinel recovery actions.

The repository also includes offline scenario fixtures for an obvious OOM, incomplete evidence, ambiguous memory-versus-deployment evidence, diagnostic outage, and database-pool exhaustion. Run the deterministic suite with:

```powershell
python sentinel.py --evaluate evaluation.json --max-steps 3
```

Latest deterministic fixture run: **5/5 scenarios passed**, with 11 diagnostic calls. This confirms expected behavior for the current five declared fixtures only.

### Recorded model results and limits

Latest full live-demo evaluation (Qwen3:4b, prompt `sentinel-demo-v2`): **rules 6/6 (100%) and Ollama end-to-end 6/6 (100%)**. Ollama directly validated **5/6 diagnoses**; the `api_error` diagnosis used deterministic fallback after an Ollama HTTP 500. Ollama abstained from additional diagnostics in all six scenarios, so this evaluation does not demonstrate successful model-selected tool execution. Mean Ollama-path time was 14.5 seconds per case versus 0.5 seconds for rules. No recovery was approved or executed during this comparison, as intended. This result is saved in the evaluation JSON produced by the browser run.

These six synthetic faults are small, known cases. Their score does not establish performance on unfamiliar incidents or production systems. Model scores are not calibrated probabilities. A cited evidence ID proves the reference exists, not by itself that the claim is semantically supported.

## Run the live demo

```powershell
ollama list
python demo_app.py
```

Open [http://127.0.0.1:8780](http://127.0.0.1:8780), choose a fault, click **Investigate**, review the evidence and planner trace, and approve recovery only after reviewing the proposal. To compare planners, click **Run evaluation** and allow several minutes for local inference. Use `Ctrl+C` in the server terminal to stop the app.

## Resume description

> Built Sentinel, a local incident-investigation prototype that uses Ollama to analyze service evidence and select bounded diagnostics, validates model output, requires approval for demo-only recovery, and verifies service health afterward. Evaluated its Ollama and deterministic paths on six injected faults with explicit fallback and abstention reporting.
