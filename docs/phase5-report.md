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
- Batch path: `StreamConsumer.process_batch()` calls one engine batch handler;
  `DetectionEngine.process_events()` uses one `ModelBundle.predict_batch()` and
  one database commit per stream batch. Per-message failures are still returned
  to the consumer for retry/dead-letter, so one bad flow does not drop the rest.
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
  processed TEST rows, so the benchmarks below measure inference/transport, not
  live feature-extraction fidelity.
- Any live feature difference from the CICFlowMeter-derived training
  distribution can reduce accuracy; low-support classes are especially weak.
- Manual live-capture steps are in `docs/live-capture-test.md`.

## Deselected Phase 4 smoke test

Initial available RAM was **1.1575 GB** (`total_gb=7.7467`, `percent_used=85.1`),
above the existing 0.50 GB guard. Command:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/ml/test_train_evaluate_smoke.py::test_natural_benign_fpr_scores_raw_benign_rows -q
```

Result:

```text
.                                                                        [100%]
1 passed in 5.64s
```

The test was listed as “deselected for memory” only until this passing rerun.
No guard threshold was changed and no environment-variable override was added.

## Throughput investigation and batching

### Benchmark correction

The earlier `3.39 flows/s` / `3.01 flows/s` numbers were distorted by a
benchmark fixture that called `Base.metadata.create_all()` on every event
(400 calls, about 65 s of an 84 s profile). `services/detection_engine/benchmark.py`
now creates the temporary SQLite schema once and yields a fresh session per
scope. The corrected single-flow baseline on the same 200 held-out TEST rows is
the valid “before” number.

### Before (single-flow processing)

Command:

```powershell
.\.venv\Scripts\python.exe -c "from services.detection_engine.benchmark import benchmark_pipeline; import json; print(json.dumps(benchmark_pipeline(flows=200), indent=2, sort_keys=True))"
```

Real output:

```json
{
  "anomalies": 107,
  "available_ram_gb": 0.7667617797851562,
  "backpressure_drops": 0,
  "candidates": 0,
  "cold_model_load_seconds": 2.0580396999994264,
  "elapsed_seconds": 6.962244400001509,
  "flows_requested": 200,
  "inference_latency_mean_ms": 21.88169299995934,
  "inference_latency_p50_ms": 20.755799998369184,
  "inference_latency_p95_ms": 27.701600000000326,
  "malicious": 0,
  "processed": 200,
  "queue_backlog_at_start": 200,
  "queue_lag_mean_ms": 3603.6674199999998,
  "queue_lag_p95_ms": 6627.500999999999,
  "rare_blocked": 0,
  "redis_backend": "fakeredis",
  "throughput_flows_per_sec": 28.72636875544855,
  "uncertain": 23
}
```

Corrected before-profile (cProfile, cumulative):

- Total: **20.591 s** including cold imports/model load.
- `core/streams.py:250(process)`: **15.128 s**.
- `services/detection_engine/engine.py:166(process_event)`: **14.989 s**.
- `ml/predict.py:130(predict_single)`: **11.786 s** (one model call per flow).
- `engine.py:318(_persist)`: **2.546 s** (one SQLite commit per flow).
- Model load: **3.001 s**.

### After (batched inference and one commit per batch)

Same command as above, same 200 rows. Real output:

```json
{
  "anomalies": 107,
  "available_ram_gb": 0.7437858581542969,
  "backpressure_drops": 0,
  "candidates": 0,
  "cold_model_load_seconds": 2.1300503999991633,
  "elapsed_seconds": 0.9674868999991304,
  "flows_requested": 200,
  "inference_latency_mean_ms": 1.2410670000099344,
  "inference_latency_p50_ms": 0.8479281249833548,
  "inference_latency_p95_ms": 2.348243750020629,
  "malicious": 0,
  "processed": 200,
  "processing_mode": "batched",
  "queue_backlog_at_start": 200,
  "queue_lag_mean_ms": 578.997415,
  "queue_lag_p95_ms": 856.015,
  "rare_blocked": 0,
  "redis_backend": "fakeredis",
  "stream_batch_size": 32,
  "throughput_flows_per_sec": 206.72114526840596,
  "uncertain": 23
}
```

Focused after-profile (cProfile, cumulative, 7.644 s total including cold load):

| Component | Calls | Cumulative time |
|---|---:|---:|
| `_persist_batch` / `_write_detection` | 7 / 200 | 0.823 s / 0.776 s |
| Redis `execute_command` (fakeredis) | 1423 | 0.571 s |
| `predict_batch` | 7 | 0.442 s |
| Redis `xadd` (client/fakeredis) | 400 | 0.219 s / 0.047 s |
| Random Forest `predict_proba` | 7 | 0.172 s |
| Isolation Forest `score_samples` | 7 | 0.162 s |
| `json.dumps` | 800 | 0.055 s |
| `EventModel.to_stream_fields` | 400 | 0.050 s |

Interpretation:

- Throughput improved from **28.73** to **206.72 flows/s** on the same rows
  (about **7.2x**), and mean inference time fell from **21.88 ms** to
  **1.24 ms** by amortizing model calls over stream batches.
- The model, saved feature order, and verdict logic were not changed. The batch
  path reuses the existing `predict_batch()` and only changes how rows are
  grouped.
- Event serialization is not a bottleneck (0.050 s for 400 stream fields in
  the profiled run). Redis/fakeredis command overhead and DB writes remain the
  larger non-model costs.
- Batching adds one commit per stream batch instead of one commit per event while
  preserving per-event validation failures, retries, and dead-lettering.
- These numbers use fakeredis and SQLite on an 8 GB host with roughly
  **0.7–1.1 GB available RAM** during runs. They are not Redis Server, network,
  disk, or production-traffic benchmarks. **Real traffic can exceed this
  measured rate**, and real Redis latency/persistence will differ.

### Equivalence and isolation tests

- `test_batch_results_match_single_flow_results_on_same_rows` compares verdict,
  predicted label, confidence, anomaly score, top features, and detection row id
  for single-flow and batch processing of the same held-out rows.
- `test_batch_dead_letters_one_bad_flow_without_dropping_valid_flows` publishes
  one contract-violating flow between two valid flows. After three batch polls,
  the valid flows are processed/persisted and only the bad flow is dead-lettered.
- `test_consumer_process_batch_keeps_per_message_outcomes` verifies success,
  retry, and pending-count behavior at the stream layer.

## Queue lag

The earlier `29.88 s` queue-lag figure is an **artifact of pre-queuing all 200
events before consuming**. It measured deliberate backlog/wait time, not live
latency. The final concurrent measurement runs a fixed-rate producer at
20 flows/s while the consumer runs in a separate thread.

Command:

```powershell
.\.venv\Scripts\python.exe -c "from services.detection_engine.benchmark import benchmark_concurrent_queue_lag; import json; print(json.dumps(benchmark_concurrent_queue_lag(flows=200, rate_flows_per_sec=20.0), indent=2, sort_keys=True))"
```

Real output:

```json
{
  "anomalies": 107,
  "available_ram_gb": 0.7619400024414062,
  "backpressure_drops": 0,
  "candidates": 0,
  "consumer_elapsed_seconds": 15.72258309999961,
  "flows_requested": 200,
  "inference_latency_mean_ms": 21.904449500007104,
  "inference_latency_p50_ms": 20.799699999770382,
  "inference_latency_p95_ms": 28.61789999951725,
  "malicious": 0,
  "processed": 200,
  "producer_consumer_mode": "concurrent",
  "producer_elapsed_seconds": 15.704714499999682,
  "queue_lag_mean_ms": 30.12238,
  "queue_lag_p95_ms": 45.03,
  "rare_blocked": 0,
  "rate_flows_per_sec": 20.0,
  "redis_backend": "fakeredis",
  "stream_length_at_end": 200,
  "uncertain": 23
}
```

Report this concurrent lag (**30.12 ms mean, 45.03 ms p95**) instead of the
pre-queued artifact. `stream_length_at_end=200` is retained acked stream entries
in Redis Streams, not a backlog. Inference remains near single-flow latency here
because a 20 flows/s producer usually gives the consumer one item per poll.

## Verification

The six commands were run in this randomly generated order after all code
changes: `pytest -> pip-audit -> bandit -> mypy -> ruff -> black`.

### pytest

Command: `.\.venv\Scripts\python.exe -m pytest -q`

```text
........................................................................ [ 33%]
................................ssss.................................... [ 66%]
........................................................................ [100%]
212 passed, 4 skipped in 134.71s (0:02:14)
```

Exact skipped tests:

- `tests/integration/test_ml_postgres.py::test_registry_lifecycle_on_postgres`
  — skipped because `AI_IDS_TEST_DATABASE_URL` is not set.
- `tests/integration/test_redis_streams.py::test_real_redis_consumer_group_and_batch_acks`
  — skipped because `AI_IDS_TEST_REDIS_URL` is not set / no real Redis is reachable.
- `tests/integration/test_redis_streams.py::test_real_redis_retries_then_dead_letters_one_event`
  — same reason.
- `tests/integration/test_redis_streams.py::test_real_redis_backpressure_on_stream_length`
  — same reason.

No tests were deselected in the final run. The formerly deselected Phase 4
smoke test passed earlier in this review and is included in the 212 passes.

### pip-audit

Command: `.\.venv\Scripts\python.exe -m pip_audit`

```text
No known vulnerabilities found
```

### bandit

Command: `.\.venv\Scripts\python.exe -m bandit -r core ml services prevention capture utils -ll`

```text
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.13.1
Working... ---------------------------------------- 100% 0:00:01
Run started:2026-11-20 20:14:02.787848+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 8981
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

### black

Command: `.\.venv\Scripts\python.exe -m black --check .`

```text
All done! ✨ 🍰 ✨
81 files would be left unchanged.
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
  and backpressure using fakeredis, including the new batch path.
- Batch predictions equal single-flow predictions on the same held-out rows.
- One bad batch event is retried/dead-lettered while valid events still process.
- Detection engine E2E in simulation mode: `Detection` row persisted with
  `model_version`; all four verdicts are representable; low-confidence and
  rare-class gates behave as documented.
- Simulation prevention candidates are always dry-run and non-blocking.
- Phase 4 training-smoke test passes at 1.1575 GB available RAM; no guard change.
- Throughput improved from 28.73 to 206.72 flows/s on the same 200 TEST rows.
- ruff, black, mypy, bandit, pip-audit, and full pytest pass.

### Written but unverified

- Live Scapy/Npcap capture on an elevated Windows host with a real NIC: manual
  steps are in `docs/live-capture-test.md`, but no privileged live capture was
  started here. Status remains **Written but unverified** until you confirm.
- Real Redis Server consumer-group concurrency, `XCLAIM`/reclaim under consumer
  crashes, and production stream latency: the integration test exists and
  auto-skips when `AI_IDS_TEST_REDIS_URL` is unset or Redis is unreachable, but
  it was not run against a real Redis Server.
- End-to-end dashboard display of ground-truth vs prediction after detection:
  events contain `source_label`/`source_index`, but no Phase 5 UI was requested.
- Live-mode accuracy against CICFlowMeter-derived training features: no live
  traffic ground truth was collected, and no parity is claimed.

### Skipped

- Real Redis via container: available RAM was measured at **1.0401 GB** and
  approval was explicitly declined. No Docker/Redis process was started; the
  real-Redis item remains **UNVERIFIED**.
- Any training, retraining, promotion, rollback, or active-model change.
- Phase 6 prevention/firewall implementation and active blocking.
- CICFlowMeter installation/comparison and any claim of feature parity.

## Pending items and risks

1. **Live capture confirmation:** run `docs/live-capture-test.md` and report the
   interface, BPF filter, flows published, detection count, verdicts, and any
   warnings. Until then, live capture is unverified.
2. **Real Redis confirmation:** set `AI_IDS_TEST_REDIS_URL` and run
   `tests/integration/test_redis_streams.py` when approved; it covers consumer
   groups, batch acks, retries/dead-letter, and backpressure.
3. **Feature distribution shift:** live header-derived approximations can differ
   materially from CICFlowMeter values, especially bulk, active/idle, subflow,
   header-length, and segment-size features. Accuracy on live traffic is
   unverified and may be lower than held-out CICIDS test metrics.
4. **Low-support classes:** `Heartbleed`, `Infiltration`, and
   `Web Attack - SQL Injection` have fewer than 20 test samples in the active
   model metrics. Predictions for these classes are unreliable and are blocked
   from candidates without the explicit operator flag.
5. **Memory pressure:** this 8 GB host ran at roughly **0.7–1.1 GB available**
   during the review. Production-like throughput and real Redis were not
   measurable here, and real traffic can exceed the measured rate.
6. **fakeredis vs Redis Server:** fakeredis validates contract logic but not real
   network, persistence, consumer failover, or `XPENDING` behavior under load.
7. **Process-local retry counts:** after a consumer restart, pending messages are
   retried but the attempt counter resets. A future phase should persist attempt
   metadata or use XPENDING delivery counts.
8. **Npcap privilege requirement:** without elevation, the sniffer refuses to
   start by design; this is intentional and was unit-tested via monkeypatch.
9. **Benchmark scope:** the pre-queued lag figure was an artifact; the concurrent
   figure is still a local fakeredis/SQLite measurement at a fixed 20 flows/s.
