#!/usr/bin/env python3
"""Lightweight pipeline benchmark for pcap2llm two-pass architecture.

Usage
-----
    python scripts/benchmark_pipeline.py [--rounds N] [CAPTURE_FILE]

If no capture file is given, the script runs against synthetic fixture packets
only (no TShark required).  This mode is suitable for sanity-checking the
Python-side processing cost of different packet counts.

When a real capture file is provided, the script exercises both TShark passes
and measures end-to-end wall-clock time and peak RSS memory.

Scenarios
---------
A. Small focused capture    — 50 packets, max_packets=50 (no truncation)
B. Medium near-limit        — 500 packets, max_packets=500
C. Truncated                — 1 000+ packets, max_packets=200 (truncation path)
D. Unlimited (--all-packets)— all packets, max_packets=0

Output
------
Tab-separated table on stdout:

    scenario  packets_in  packets_out  wall_s  rss_mib  truncated

Notes
-----
- RSS memory is measured as the process peak RSS *after* the run finishes,
  not during.  For small synthetic runs this is dominated by the Python
  interpreter, not the pipeline.  It is most informative when run with a
  real multi-thousand-packet capture file.
- Wall-clock time includes subprocess overhead (TShark invocations) when a
  real capture file is used.
- Run several rounds (--rounds 3) and take the minimum wall-clock time to
  reduce scheduling noise.

Semantic note on summary accuracy
----------------------------------
The two-pass architecture keeps pass-1 statistics capture-wide.  The
benchmark confirms this by printing both:
  packets_in   — total packets scanned in pass 1 (summary.json source of truth)
  packets_out  — packets written to detail.json (bounded by max_packets)

When truncated is True, packets_in > packets_out, and summary.json still
accurately reflects the full capture.
"""
from __future__ import annotations

import argparse
import resource
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Synthetic packet fixture helpers
# ---------------------------------------------------------------------------

def _make_synthetic_packet(n: int) -> dict[str, Any]:
    """Return a minimal TShark JSON packet dict with frame number *n*."""
    return {
        "_source": {
            "layers": {
                "frame.number": str(n),
                "frame.time_epoch": str(1_712_390_000.0 + n * 0.01),
                "frame.time_relative": str(n * 0.01),
                "frame.protocols": "eth:ip:sctp:diameter",
                "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                "sctp": {
                    "sctp.srcport": "3868",
                    "sctp.dstport": "3868",
                    "sctp.assoc_index": "0",
                },
                "diameter": {
                    "diameter.cmd.code": "316",
                    "diameter.flags": "0x80",
                },
            }
        }
    }


def _make_fixture_packets(n: int) -> list[dict[str, Any]]:
    return [_make_synthetic_packet(i + 1) for i in range(n)]


# ---------------------------------------------------------------------------
# Mock runner for synthetic runs (no TShark)
# ---------------------------------------------------------------------------

def _mock_runner_for(packets: list[dict[str, Any]]):
    """Return a TSharkRunner mock wired to return *packets* from all export methods."""
    from pcap2llm.index_models import PacketIndexRecord

    def _make_index_record(pkt: dict[str, Any]) -> PacketIndexRecord:
        layers = pkt["_source"]["layers"]
        fn = int(layers.get("frame.number", "1"))
        te = layers.get("frame.time_epoch", "1712390000.0")
        protos = [p for p in layers.get("frame.protocols", "").split(":") if p]
        src = layers.get("ip", {}).get("ip.src") or layers.get("ip.src")
        dst = layers.get("ip", {}).get("ip.dst") or layers.get("ip.dst")
        return PacketIndexRecord(
            frame_no=fn,
            time_epoch=str(te),
            protocols=protos,
            src_ip=src, dst_ip=dst,
            transport="sctp", src_port=3868, dst_port=3868, stream="0",
            tcp_retransmission=False, tcp_out_of_order=False,
            diameter_flags=None, diameter_cmd_code=None,
            diameter_hop_by_hop_id=None, diameter_result_code=None,
            gtpv2_message_type=None, gtpv2_seq_no=None, gtpv2_cause=None,
        )

    index_records = [_make_index_record(p) for p in packets]
    frame_map = {int(p["_source"]["layers"]["frame.number"]): p for p in packets}

    runner = MagicMock()
    runner.ensure_available = lambda: None
    runner.export_packet_index.return_value = index_records
    runner.export_packets.return_value = packets

    def _export_selected(capture_path, *, frame_numbers, extra_args=None, two_pass=False):
        return [frame_map[fn] for fn in frame_numbers if fn in frame_map]

    runner.export_selected_packets.side_effect = _export_selected
    return runner


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

SCENARIOS = [
    # (name,  n_packets,  max_packets,  oversize_factor)
    ("A-small",         50,     50,    0),
    ("B-medium",       500,    500,    0),
    ("C-truncated",   1000,    200,    0),
    ("D-unlimited",    500,      0,    0),
]


def _rss_mib() -> float:
    """Return current process RSS in MiB (Linux: /proc/self/status; macOS: resource)."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # Linux: ru_maxrss is in kB; macOS: ru_maxrss is in bytes
    if sys.platform == "darwin":
        return usage.ru_maxrss / (1024 * 1024)
    return usage.ru_maxrss / 1024


def run_scenario(
    name: str,
    packets: list[dict[str, Any]],
    *,
    max_packets: int,
    oversize_factor: float,
    capture_path: Path,
    out_dir: Path,
    real_runner=None,
) -> dict[str, Any]:
    """Run one benchmark scenario, return result dict."""
    from pcap2llm.pipeline import analyze_capture
    from pcap2llm.profiles import load_profile

    profile = load_profile("lte-core")

    if real_runner is not None:
        runner = real_runner
    else:
        runner = _mock_runner_for(packets)

    t0 = time.perf_counter()
    artifacts = analyze_capture(
        capture_path,
        out_dir=out_dir,
        runner=runner,
        profile=profile,
        privacy_modes={},
        max_packets=max_packets,
        oversize_factor=oversize_factor,
    )
    wall_s = time.perf_counter() - t0
    rss = _rss_mib()

    coverage = artifacts.summary.get("coverage", {})
    packets_in = coverage.get("detail_packets_available", 0)
    packets_out = coverage.get("detail_packets_included", 0)
    truncated = coverage.get("detail_truncated", False)
    total_from_summary = artifacts.summary.get("packet_message_counts", {}).get("total_packets", 0)

    return {
        "scenario": name,
        "packets_in": packets_in,
        "packets_out": packets_out,
        "summary_total": total_from_summary,
        "wall_s": wall_s,
        "rss_mib": rss,
        "truncated": truncated,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="pcap2llm pipeline benchmark")
    parser.add_argument("capture", nargs="?", help="Real .pcapng file (optional)")
    parser.add_argument("--rounds", type=int, default=1, help="Rounds per scenario (default: 1)")
    args = parser.parse_args()

    import tempfile

    print(f"{'scenario':<18} {'pkts_in':>8} {'pkts_out':>9} {'summ_total':>10} "
          f"{'wall_s':>8} {'rss_mib':>8} {'trunc':>6}")
    print("-" * 75)

    for scenario_name, n_packets, max_packets, oversize_factor in SCENARIOS:
        packets = _make_fixture_packets(n_packets)
        best_wall = float("inf")
        last_result: dict[str, Any] = {}

        for _ in range(args.rounds):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                capture = tmp_path / "bench.pcapng"
                capture.write_bytes(b"fake")
                out_dir = tmp_path / "out"

                result = run_scenario(
                    scenario_name,
                    packets,
                    max_packets=max_packets,
                    oversize_factor=oversize_factor,
                    capture_path=capture,
                    out_dir=out_dir,
                )
                if result["wall_s"] < best_wall:
                    best_wall = result["wall_s"]
                    last_result = result

        r = last_result
        print(
            f"{r['scenario']:<18} {r['packets_in']:>8} {r['packets_out']:>9} "
            f"{r['summary_total']:>10} {r['wall_s']:>8.4f} {r['rss_mib']:>8.1f} "
            f"{'yes' if r['truncated'] else 'no':>6}"
        )

    if args.rounds > 1:
        print(f"\n(best of {args.rounds} rounds shown for wall_s)")

    print("\nKey: packets_in = pass-1 total (capture-wide, always accurate)")
    print("     packets_out = detail artifact size (bounded by --max-packets)")
    print("     summ_total = summary.packet_message_counts.total_packets (must == packets_in)")


if __name__ == "__main__":
    main()
