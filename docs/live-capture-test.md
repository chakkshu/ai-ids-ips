# Manual live-capture test (written but unverified)

This checklist is for you to run on the Windows host. No live capture was
started while preparing this document. It is passive capture only: the sensor
reads packets and publishes flows; it does not inject traffic, spoof addresses,
or change firewall state.

## Accuracy warning

Live predictions are expected to be **rougher than the held-out TEST results**.
The Phase 5 flow meter is a best-effort adapter from IP/TCP/UDP/ICMP headers to
the active 77-feature `cicids-80k-no-port` contract. It is **not CICFlowMeter**
and does not claim feature parity. Bulk features, active/idle windows, subflows,
header lengths, segment sizes, and payload-activity features are approximated or
zero-filled. Read `docs/phase5-feature-coverage.md` before interpreting results,
especially for low-support classes.

## Prerequisites

1. Install Npcap from the official site: <https://npcap.com/#download>.
   During installation, keep WinPcap API-compatible mode if you want Scapy's
   default Windows backend to work.
2. Reboot or restart the Npcap service if the installer requests it.
3. Open **Windows Terminal / PowerShell as Administrator**. The sniffer calls
   `require_admin()` and refuses to start without elevation.
4. From the repository root, activate/use the project virtual environment:

   ```powershell
   .\.venv\Scripts\python.exe --version
   ```

5. Redis must already be reachable through the configured `REDIS_URL`. If you
   choose to start only Redis for this manual test:

   ```powershell
   docker compose up -d redis
   ```

   Stop it afterward with `docker compose stop redis`. Do not start the whole
   stack unless you intentionally need the other services.

## 1. List capture interfaces

In the elevated terminal:

```powershell
.\.venv\Scripts\python.exe -c "from capture.sniffer import available_interfaces; print('\n'.join(available_interfaces()))"
```

Npcap interfaces usually appear as `\Device\NPF_{GUID}`. Pick the Wi-Fi or
Ethernet interface that carries your harmless test traffic. `auto` is also
accepted and asks Scapy for its working interface.

## 2. Start the detection engine

In one elevated terminal:

```powershell
$env:CAPTURE_MODE="live"
.\.venv\Scripts\python.exe run.py detection-engine
```

Leave it running. It reads `raw-flows`, writes `Detection` rows, and publishes
to `detections:stream`.

## 3. Start the passive sniffer

In a second elevated terminal:

```powershell
$env:CAPTURE_MODE="live"
.\.venv\Scripts\python.exe run.py sensor --interface "auto" --bpf "ip and (tcp or udp or icmp)"
```

Replace `auto` with the exact interface string from step 1 if needed. IPv6 is
not handled by this flow meter, so the filter intentionally uses `ip`.

The sniffer is capture-only. It does not send, inject, spoof, or modify packets.

## 4. Generate harmless traffic

While the sensor is running, in a normal terminal/browser:

```powershell
ping 1.1.1.1
curl.exe https://example.com
```

Also browse a few ordinary HTTP/HTTPS sites. The BPF filter captures both
directions of the resulting IPv4 TCP/UDP/ICMP flows.

Wait about **30 seconds** after the traffic stops. The flow meter emits a flow
when the idle timeout expires (or on active timeout/flush). You can also press
`Ctrl+C` in the sensor terminal to stop gracefully and flush remaining flows.

## 5. Confirm flows and predictions

If Redis CLI is available through the compose service:

```powershell
docker compose exec redis redis-cli XLEN raw-flows
docker compose exec redis redis-cli XRANGE raw-flows - + COUNT 5
docker compose exec redis redis-cli XLEN detections:stream
docker compose exec redis redis-cli XRANGE detections:stream - + COUNT 5
```

Expected observations:

- `XLEN raw-flows` increases after completed flows are published.
- Each `raw_flow` event is tagged `SIMULATION` only in simulation mode. Live
  events have `source="live"` and should **not** carry that tag.
- `XLEN detections:stream` increases by roughly the number of consumed flows.
- Detection events contain `model_version="cicids-80k-no-port"`, a verdict, a
  confidence score, and the measured `inference_latency_ms` / `queue_lag_ms`.

Confirm persisted rows:

```powershell
.\.venv\Scripts\python.exe -c "from core.db import get_db_session; from core.models.detection import Detection; s=get_db_session(); print('detection_rows', s.query(Detection).count()); s.close()"
```

Stop both processes with `Ctrl+C`. Stop only the Redis container if you started
it solely for this test:

```powershell
docker compose stop redis
```

## What to record back

Please report: interface used, BPF filter, approximate flows published,
detection count, observed verdicts, any errors/backpressure warnings, and
whether predictions looked plausible. Until you confirm those observations,
this item remains **Written but unverified** in `docs/phase5-report.md`.
