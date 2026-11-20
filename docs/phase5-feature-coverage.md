# Phase 5 flow feature coverage (active model `cicids-80k-no-port`)

## Scope and non-claim

`capture/flow_meter.py` converts passively observed Scapy/Npcap packet headers into
the **77 ordered features** required by
`ml/registry/active/cicids-80k-no-port/features.json`. `Destination Port` is
intentionally absent because it was removed from the active model.

This is a **best-effort header-derived adapter**, not CICFlowMeter. It does **not**
claim feature parity with CICFlowMeter, and no measured accuracy parity is claimed.
The model was trained on CICFlowMeter-derived CICIDS2017 features; live capture
features may differ in header accounting, idle/active windowing, bulk segmentation,
subflow segmentation, and timeout policy. Any such difference is a distribution
shift and can reduce precision/recall, especially for low-support classes.

## Extraction policy

- Bidirectional key: TCP/UDP/ICMP endpoint pair plus protocol, normalized so both
  directions aggregate into one record. The first observed direction is "forward".
- Timeouts: active = `SENSOR_FLOW_TIMEOUT_ACTIVE` (120 s), idle =
  `SENSOR_FLOW_TIMEOUT_IDLE` (30 s). Expired flows are emitted on the next packet or
  explicit `expire()/flush()` call.
- Clock: packet arrival timestamp (`time.time()` unless supplied by the caller).
- Undefined statistics (zero packets in a direction, zero duration, one sample,
  no IAT/active/idle transition) are **zero-filled**, not NaN. Non-finite values
  are rejected before publication; `ml.predict` additionally imputes from the saved
  per-column imputation vector if a caller bypasses the meter.
- Payload bytes are not inspected. Lengths come from the IPv4 total-length field
  (falling back to the parsed IP layer length). "Header length" is IPv4 IHL bytes
  plus TCP data-offset bytes (or fixed 8-byte UDP / 4-byte ICMP approximation).
- Standard deviation is population std (`statistics.pstdev`), not sample std.
- Bulk segments are split when the gap between consecutive directional packets
  exceeds the configured idle timeout. Active/idle periods use the same threshold;
  CICFlowMeter conventionally uses a shorter activity threshold, so values may differ.
- Subflow features are set equal to whole-flow directional totals (a single
  subflow per direction); no CICFlowMeter subflow segmentation is reproduced.
- Simulation replay does not use this meter: it streams the original processed
  TEST rows directly, so simulation timings measure inference and transport, not
  live feature-extraction fidelity.

## Per-feature disclosure

| # | Feature | Source in this meter | Status / default | Likely accuracy impact |
|---:|---|---|---|---|
| 1 | Flow Duration | `last_packet_time - first_packet_time` | Direct observation; 0 for a single packet | Comparable in principle, but timeouts differ from CICFlowMeter |
| 2 | Total Fwd Packets | Count of forward-direction packets | Direct | Low |
| 3 | Total Backward Packets | Count of backward-direction packets | Direct | Low |
| 4 | Total Length of Fwd Packets | Sum of IP total lengths, forward | Direct from headers | Low to moderate if off-link IPv4 options/length quirks differ |
| 5 | Total Length of Bwd Packets | Sum of IP total lengths, backward | Direct from headers | Low to moderate |
| 6 | Fwd Packet Length Max | Max forward IP length | Direct; 0 if no forward packets | Low |
| 7 | Fwd Packet Length Min | Min forward IP length | Direct; 0 if no forward packets | Low |
| 8 | Fwd Packet Length Mean | Mean forward IP length | Direct; 0 default | Low |
| 9 | Fwd Packet Length Std | Population std of forward lengths | Direct; 0 for <2 samples | Low; population vs sample std may differ slightly |
| 10 | Bwd Packet Length Max | Max backward IP length | Direct; 0 if none | Low |
| 11 | Bwd Packet Length Min | Min backward IP length | Direct; 0 if none | Low |
| 12 | Bwd Packet Length Mean | Mean backward IP length | Direct; 0 default | Low |
| 13 | Bwd Packet Length Std | Population std of backward lengths | Direct; 0 for <2 samples | Low |
| 14 | Flow Bytes/s | Total observed bytes / duration | Direct; 0 when duration is 0 | Moderate if duration/timeout differs from training generator |
| 15 | Flow Packets/s | Total packets / duration | Direct; 0 when duration is 0 | Moderate |
| 16 | Flow IAT Mean | Mean of consecutive packet gaps | Direct; 0 for <2 packets | Low to moderate; capture scheduling noise included |
| 17 | Flow IAT Std | Population std of packet gaps | Direct; 0 for <2 gaps | Low to moderate |
| 18 | Flow IAT Max | Max packet gap | Direct; 0 default | Moderate; idle gaps can be truncated by flow timeout |
| 19 | Flow IAT Min | Min packet gap | Direct; 0 default | Low; capture timestamp resolution matters |
| 20 | Fwd IAT Total | Sum of forward directional gaps | Direct; 0 default | Low |
| 21 | Fwd IAT Mean | Mean forward gap | Direct; 0 default | Low |
| 22 | Fwd IAT Std | Population std of forward gaps | Direct; 0 for <2 gaps | Low |
| 23 | Fwd IAT Max | Max forward gap | Direct; 0 default | Moderate |
| 24 | Fwd IAT Min | Min forward gap | Direct; 0 default | Low |
| 25 | Bwd IAT Total | Sum of backward directional gaps | Direct; 0 default | Low |
| 26 | Bwd IAT Mean | Mean backward gap | Direct; 0 default | Low |
| 27 | Bwd IAT Std | Population std of backward gaps | Direct; 0 for <2 gaps | Low |
| 28 | Bwd IAT Max | Max backward gap | Direct; 0 default | Moderate |
| 29 | Bwd IAT Min | Min backward gap | Direct; 0 default | Low |
| 30 | Fwd PSH Flags | TCP PSH bits in forward packets | Direct; 0 for non-TCP | Low; offloading may alter TCP flags |
| 31 | Bwd PSH Flags | TCP PSH bits in backward packets | Direct; 0 for non-TCP | Low |
| 32 | Fwd URG Flags | TCP URG bits in forward packets | Direct; 0 for non-TCP | Low (rarely nonzero) |
| 33 | Bwd URG Flags | TCP URG bits in backward packets | Direct; 0 for non-TCP | Low |
| 34 | Fwd Header Length | Sum of IPv4 IHL + TCP data-offset (or UDP/ICMP approximation) | **Approximated**; 0 default | Moderate; exact CICFlowMeter header accounting is not reproduced |
| 35 | Bwd Header Length | Same rule, backward | **Approximated**; 0 default | Moderate |
| 36 | Fwd Packets/s | Forward count / duration | Direct; 0 when duration is 0 | Moderate |
| 37 | Bwd Packets/s | Backward count / duration | Direct; 0 when duration is 0 | Moderate |
| 38 | Min Packet Length | Min combined IP length | Direct; 0 default | Low |
| 39 | Max Packet Length | Max combined IP length | Direct; 0 default | Low |
| 40 | Packet Length Mean | Mean combined IP length | Direct; 0 default | Low |
| 41 | Packet Length Std | Population std of combined lengths | Direct; 0 for <2 packets | Low |
| 42 | Packet Length Variance | Squared packet-length std | Derived; 0 for <2 packets | Low |
| 43 | FIN Flag Count | TCP FIN bits across both directions | Direct; 0 for non-TCP | Low |
| 44 | SYN Flag Count | TCP SYN bits | Direct; 0 for non-TCP | Low |
| 45 | RST Flag Count | TCP RST bits | Direct; 0 for non-TCP | Low |
| 46 | PSH Flag Count | TCP PSH bits | Direct; 0 for non-TCP | Low |
| 47 | ACK Flag Count | TCP ACK bits | Direct; 0 for non-TCP | Low |
| 48 | URG Flag Count | TCP URG bits | Direct; 0 for non-TCP | Low |
| 49 | CWE Flag Count | TCP CWR bit (0x80) | Direct; 0 for non-TCP | Low; naming follows CIC contract |
| 50 | ECE Flag Count | TCP ECE bit (0x40) | Direct; 0 for non-TCP | Low |
| 51 | Down/Up Ratio | Backward packet count / forward packet count | **Approximated**; 0 when no forward packets | Moderate; CICFlowMeter may use byte-based directionality |
| 52 | Average Packet Size | Total bytes / total packets | Direct; 0 default | Low |
| 53 | Avg Fwd Segment Size | Forward bytes / forward packets | Direct from IP length; 0 default | Moderate; not TCP payload segment size |
| 54 | Avg Bwd Segment Size | Backward bytes / backward packets | Direct from IP length; 0 default | Moderate |
| 55 | Fwd Header Length_Duplicate | Mirrors feature 34 | **Deliberate duplicate** from saved CIC schema; 0 default | Same as feature 34; duplication is required by the contract |
| 56 | Fwd Avg Bytes/Bulk | Mean IP bytes per forward gap-segmented bulk | **Approximated**; 0 if no forward packets | Moderate to high; bulk segmentation and payload accounting differ |
| 57 | Fwd Avg Packets/Bulk | Mean packets per forward bulk | **Approximated**; 0 default | Moderate to high |
| 58 | Fwd Avg Bulk Rate | Mean bulk bytes / bulk duration | **Approximated**; 0 for zero-duration bulk | High; timing/segmentation sensitive |
| 59 | Bwd Avg Bytes/Bulk | Mean IP bytes per backward bulk | **Approximated**; 0 default | Moderate to high |
| 60 | Bwd Avg Packets/Bulk | Mean packets per backward bulk | **Approximated**; 0 default | Moderate to high |
| 61 | Bwd Avg Bulk Rate | Mean backward bulk bytes / duration | **Approximated**; 0 default | High |
| 62 | Subflow Fwd Packets | Equal to total forward packets | **Approximated** as one subflow; 0 default | Moderate for multi-phase flows |
| 63 | Subflow Fwd Bytes | Equal to total forward bytes | **Approximated**; 0 default | Moderate |
| 64 | Subflow Bwd Packets | Equal to total backward packets | **Approximated**; 0 default | Moderate |
| 65 | Subflow Bwd Bytes | Equal to total backward bytes | **Approximated**; 0 default | Moderate |
| 66 | Init_Win_bytes_forward | TCP window of first forward packet | Direct; 0 for non-TCP or no forward packet | Low to moderate; only meaningful for TCP |
| 67 | Init_Win_bytes_backward | TCP window of first backward packet | Direct; 0 if none | Low to moderate |
| 68 | act_data_pkt_fwd | Forward packets with IP length greater than computed header | **Approximated payload signal**; 0 default | Moderate; IPv4 options/tunneling can misclassify |
| 69 | min_seg_size_forward | Min forward IP total length | **Approximated** from IP length; 0 default | Moderate; not true TCP data segment size |
| 70 | Active Mean | Mean active-block duration from idle-gap threshold | **Approximated**; 0 if no block | High; threshold differs from CICFlowMeter |
| 71 | Active Std | Population std of active-block durations | **Approximated**; 0 for <2 blocks | High |
| 72 | Active Max | Max active-block duration | **Approximated**; 0 default | High |
| 73 | Active Min | Min active-block duration | **Approximated**; 0 default | High |
| 74 | Idle Mean | Mean inter-block gap >= idle timeout | **Approximated**; 0 if no gap | High |
| 75 | Idle Std | Population std of idle gaps | **Approximated**; 0 for <2 gaps | High |
| 76 | Idle Max | Max idle gap | **Approximated**; 0 default | High |
| 77 | Idle Min | Min idle gap | **Approximated**; 0 default | High |

## Contract enforcement

- `capture/flow_meter.FEATURE_NAMES` is derived from
  `features_for_variant("no_destination_port")`; the parity test compares it with
  the saved `features.json` byte-level list.
- `capture/replay_simulator.saved_active_feature_names()` reads the saved active
  contract and refuses to run if it is not the 77-feature no-port list.
- `ml.predict.ModelBundle._check_columns()` rejects missing or extra names before
  inference. `DetectionEngine` performs the same explicit check and then reorders
  the mapping to the saved order; no silent inference with a different schema is
  possible.
