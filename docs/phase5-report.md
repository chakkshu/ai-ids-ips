# Phase 5 report — sensor, flow meter, replay, and detection engine

Branch: `phase-5-pipeline` (created from `master` at `af56321`).
Active model: `cicids-80k-no-port`, 77 features, no `Destination Port`.
No training was run and the active model pointer/artifacts were not changed.

## Scope delivered

- `capture/flow_meter.py`: bidirectional flow aggregation with active/idle
  timeouts and a finite, ordered mapping for all 77 saved model features.
- `capture/sniffer.py`: passive Scapy/Npcap capture, interface selection, BPF
  filter, drop/rate stats, graceful shutdown, and hard refusal without
  Administrator/root privileges. No packet injection or offensive code.
- `capture/replay_simulator.py`: streams only `split_indices.json["test"]` rows,
  adjustable flows/second, mandatory `SIMULATION` tag, canonical `source_label`
  and `source_index` ground truth on every event.
- `services/sensor`: publishes completed flows to Redis stream `raw-flows` using
  strict Phase 5 event schemas, consumer-group-aware stream limits, retries,
  dead-letter stream, and backpressure errors.
- `services/detection_engine`: consumes `raw-flows`, loads the verified active
  model through `ml.predict`, enforces the saved feature contract, stores
  `Detection` rows with `model_version`, emits detection and dry-run prevention
  candidate events, applies the documented confidence rule, and gates rare
  classes behind an explicit flag.
- Verdicts: `known attack`, `benign`, `anomaly`, `uncertain`. The documented
  low-confidence rule is `confidence < 0.7` (active model
  `confidence_threshold`), producing `uncertain` and no blocking candidate.
  Candidate promotion additionally requires `confidence >= 0.85`
  (`PREVENTION_CONFIDENCE_THRESHOLD`).
- Capture mode: `CAPTURE_MODE` is canonical when set; otherwise the Phase 1
  `SENSOR_SIMULATION_MODE` boolean decides. In simulation mode all forwarded
  events carry `SIMULATION`, and every prevention candidate has
  `firewall_action="dry_run"` and `blocking_candidate=False`.

Stream names used: `raw-flows`, `detections:stream`, `prevention:action`,
`raw-flows:dead-letter`, `detections:stream:dead-letter`.

## Feature fidelity disclosure

See `docs/phase5-feature-coverage.md` for the complete 77-row table. It lists
every approximated, derived, or zero-filled feature and its likely accuracy
impact. Key points:

- This meter is **not CICFlowMeter** and makes no parity claim.
- Bulk, active/idle, subflow, down/up ratio, header-length, segment-size, and
  payload-activity features are approximations from IP/TCP headers and arrival
  times, with zero defaults where undefined.
- Simulation replay bypasses the live flow meter and uses the original
  processed TEST rows, so the benchmark below measures inference/transport, not
  live feature-extraction fidelity.
- Any live feature difference from the CICFlowMeter-derived training
  distribution can reduce accuracy; low-support classes are especially weak.

## Benchmarks (real numbers, this machine, 2026-11-21)

Command:

```powershell
.\.venv\Scripts\python.exe -c "from services.detection_engine.benchmark import benchmark_pipeline; import json; print(json.dumps(benchmark_pipeline(flows=200), indent=2, sort_keys=True))"
```

Results:

```json
{
  "anomalies": 107,
  "available_ram_gb": 0.6938705444335938,
  "backpressure_drops": 0,
  "candidates": 0,
  "cold_model_load_seconds": 1.6984572999999727,
  "elapsed_seconds": 58.93370700000014,
  "flows_requested": 200,
  "inference_latency_mean_ms": 15.394144499973663,
  "inference_latency_p50_ms": 14.646899999206653,
  "inference_latency_p95_ms": 20.096399999602,
  "malicious": 0,
  "processed": 200,
  "queue_backlog_at_start": 200,
  "queue_lag_mean_ms": 29879.941154999997,
  "queue_lag_p95_ms": 55859.06,
  "rare_blocked": 0,
  "redis_backend": "fakeredis",
  "throughput_flows_per_sec": 3.393643640981205,
  "uncertain": 23
}
```

Interpretation:

- Inference itself is about **15 ms/flow** on this machine, but end-to-end
  throughput is only **3.39 flows/s** because the benchmark includes SQLite
  `NetworkFlow`/`Detection` persistence and two Redis-stream publishes per
  event. These numbers are not a Redis Server benchmark.
- Queue lag is large because the harness intentionally publishes all 200 events
  before consuming them. The reported lag is `processing_time - event_creation_time`,
  i.e. time waiting in the backlog, not model runtime. The initial backlog was
  200 flows.
- The machine has only about **0.69 GB available RAM** during the run (7.75 GB
  total, >90% used). This 8 GB constraint limits throughput, test parallelism,
  and any attempt to run Docker Redis; results should not be extrapolated to a
  production host.
- Cold model load (checksum verification plus artifact deserialization) took
  **1.70 s** and was excluded from the timing loop but reported separately.

## Verification

The six tool commands were run in a randomly generated order:
`mypy → ruff → pytest → black → pip-audit → bandit`.

### mypy

Command: `.\.venv\Scripts\python.exe -m mypy core services capture run.py`

```text
services\web_api\blueprints\auth.py:273: note: By default the bodies of untyped functions are not checked, consider using --check-untyped-defs  [annotation-unchecked]
services\web_api\blueprints\auth.py:513: note: By default the bodies of untyped functions are not checked, consider using --check-untyped-defs  [annotation-unchecked]
Success: no issues found in 38 source files
```

### ruff

Command: `.\.venv\Scripts\python.exe -m ruff check .`

```text
All checks passed!
```

### pytest (first full run)

Command: `.\.venv\Scripts\python.exe -m pytest -q`

```text
F....s.................................................................. [ 34%]
........................................................................ [ 68%]
..................................................................       [100%]
================================== FAILURES ===================================
_______________ test_natural_benign_fpr_scores_raw_benign_rows ________________
...
E           MemoryError: memory guard triggered for train-smoke-20261120T193002: available RAM 0.50 GB < 0.50 GB minimum
...
FAILED tests/unit/ml/test_train_evaluate_smoke.py::test_natural_benign_fpr_scores_raw_benign_rows
1 failed, 208 passed, 1 skipped in 96.31s (0:01:36)
```

This is a pre-existing Phase 4 training-smoke test whose memory guard refused
to run at `0.50 GB` available RAM. It is an environment limitation, not a Phase 5
failure; no training was retried.

### pytest (randomized rerun, memory-heavy test deselected)

Command:

```powershell
.\.venv\Scripts\python.exe -m pytest --randomly-seed=568525788 --deselect=tests/unit/ml/test_train_evaluate_smoke.py::test_natural_benign_fpr_scores_raw_benign_rows -q
```

```text
s....................................................................... [ 34%]
........................................................................ [ 68%]
.................................................................        [100%]
208 passed, 1 skipped, 1 deselected in 96.55s (0:01:36)
```

Phase 5 test groups included in that result:

- `tests/unit/capture/test_flow_meter.py` — hand-built Scapy packets,
  bidirectional counts, flags, IAT, headers, timeouts, finite values, and
  feature-order parity with the saved 77-feature list.
- `tests/unit/capture/test_sniffer.py` — admin refusal, interface selection,
  capture stats and drop counters; no live capture socket opened.
- `tests/unit/capture/test_replay_simulator.py` — test-only indices, `SIMULATION`
  tag, source labels, speed/limit/backpressure behavior.
- `tests/unit/core/test_events.py` — strict schemas, verdicts, dry-run candidate.
- `tests/unit/services/test_streams.py` — consumer groups, retries, dead-letter,
  acknowledgements, and backpressure with fakeredis.
- `tests/unit/services/test_detection_engine.py` — real active model E2E in
  simulation mode, `Detection` row with model version, feature enforcement,
  rare-class gating, and active-pointer/feature-file byte comparison before and
  after.

### black

Command: `.\.venv\Scripts\python.exe -m black --check .`

```text
All done! ✨ 🍰 ✨
80 files would be left unchanged.
```

### pip-audit

Command: `.\.venv\Scripts\python.exe -m pip_audit`

```text
No known vulnerabilities found
```

### bandit

Command: `.\.venv\Scripts\python.exe -m bandit -r core ml services prevention capture utils -ll`

```text
Test results:
	No issues identified.

Code scanned:
	Total lines of code: 8592
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 3
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 3
Files skipped (0):
```

## Verified / Written but unverified / Skipped

### Verified

- Active pointer remains `cicids-80k-no-port`; saved 77-feature order equals the
  flow meter and simulator contract; `Destination Port` is absent.
- Checksum-verified model loading and feature enforcement through `ml.predict`.
- Bidirectional flow aggregation, timeout emission, TCP/UDP header extraction,
  and finite 77-feature output using hand-built Scapy packets.
- Replay streams only held-out TEST rows and tags every event `SIMULATION`.
- Redis stream groups, idempotent group creation, retries, dead-letter, acks,
  and backpressure using fakeredis.
- Detection engine E2E in simulation mode: `Detection` row persisted with
  `model_version`; all four verdicts are representable; low-confidence and
  rare-class gates behave as documented.
- Simulation prevention candidates are always dry-run and non-blocking.
- ruff, black, mypy, bandit, pip-audit, and the non-training pytest suite pass.

### Written but unverified

- Live Scapy/Npcap capture on an elevated Windows host with a real NIC: code and
  unit tests exist, but no privileged live capture was started here.
- Real Redis Server consumer-group concurrency, `XCLAIM`/reclaim under consumer
  crashes, and production stream latency: only fakeredis was exercised.
- End-to-end dashboard display of ground-truth vs prediction after detection:
  events contain `source_label`/`source_index`, but no Phase 5 UI was requested.
- Live-mode accuracy against CICFlowMeter-derived training features: no live
  traffic ground truth was collected, and no parity is claimed.

### Skipped

- Real Redis via Docker Compose integration. Available RAM was measured at
  `0.6079 GB` at Phase 5 start and about `0.69 GB` during the benchmark; Docker
  Redis was not started because the 8 GB host is already above 92% memory use.
- Any training, retraining, promotion, rollback, or active-model change.
- Phase 6 prevention/firewall implementation and active blocking.
- CICFlowMeter installation/comparison and any claim of feature parity.

## Risks

1. **Feature distribution shift:** live header-derived approximations can differ
   materially from CICFlowMeter values, especially bulk, active/idle, subflow,
   header-length, and segment-size features. Accuracy on live traffic is
   unverified and may be lower than held-out CICIDS test metrics.
2. **Low-support classes:** `Heartbleed`, `Infiltration`, and
   `Web Attack - SQL Injection` have fewer than 20 test samples in the active
   model metrics. Predictions for these classes are unreliable and are blocked
   from candidates without the explicit operator flag.
3. **Memory pressure:** at roughly 0.5–0.7 GB available, the pre-existing
   Phase 4 smoke test trips its 0.50 GB guard. Production-like throughput and
   real Redis were not measurable here.
4. **fakeredis vs Redis Server:** fakeredis validates contract logic but not real
   network, persistence, consumer failover, or `XPENDING` behavior under load.
5. **Process-local retry counts:** after a consumer restart, pending messages are
   retried but the attempt counter resets. A future phase should persist attempt
   metadata or use XPENDING delivery counts.
6. **Npcap privilege requirement:** without elevation, the sniffer refuses to
   start by design; this is intentional and was unit-tested via monkeypatch.
7. **Simulation lag methodology:** all events were queued before processing, so
   the reported queue lag is dominated by deliberate backlog, not service time.
