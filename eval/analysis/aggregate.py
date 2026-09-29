#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Aggregate raw per-attempt CSVs into a summary table.

Reads every ``*_warm.csv`` and ``*_cold.csv`` under ``<run_dir>``, computes
per-(protocol, cache_policy) statistics on ``total_e2e_ms`` plus the
per-phase fields, and writes ``<run_dir>/summary.csv``.

Failed attempts (``ok == 0``) are excluded from statistics but counted in
``n_failed``.  The exclusion is reported so a high failure rate is visible.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Iterable

SUMMARY_FIELDS = [
    "protocol",
    "cache_policy",
    "n",
    "n_failed",
    "mean_total_ms",
    "p50_total_ms",
    "p95_total_ms",
    "p99_total_ms",
    "mean_tcp_ms",
    "mean_tls_ms",
    "mean_attest_ms",
    "mean_extra_tcp_ms",
    "mean_extra_tls_ms",
    "mean_http_ms",
    "min_total_ms",
    "max_total_ms",
]

PHASE_FIELDS = (
    "tcp_ms",
    "tls_ms",
    "attest_ms",
    "extra_tcp_ms",
    "extra_tls_ms",
    "http_ms",
)


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def _mean(values: Iterable[float]) -> float:
    vs = list(values)
    return sum(vs) / len(vs) if vs else float("nan")


def _load(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _summarize(rows: list[dict]) -> dict | None:
    ok_rows = [r for r in rows if int(r.get("ok", 1)) == 1]
    if not ok_rows:
        return None
    totals = [float(r["total_e2e_ms"]) for r in ok_rows]
    summary = {
        "n": len(ok_rows),
        "n_failed": len(rows) - len(ok_rows),
        "mean_total_ms": round(_mean(totals), 4),
        "p50_total_ms": round(_percentile(totals, 50), 4),
        "p95_total_ms": round(_percentile(totals, 95), 4),
        "p99_total_ms": round(_percentile(totals, 99), 4),
        "min_total_ms": round(min(totals), 4),
        "max_total_ms": round(max(totals), 4),
    }
    for field in PHASE_FIELDS:
        vals = [float(r.get(field, 0.0) or 0.0) for r in ok_rows]
        summary[f"mean_{field}"] = round(_mean(vals), 4)
    return summary


def _parse_latency_name(stem: str) -> tuple[str, str] | None:
    """Split ``<protocol>_<cache>`` for latency-mode CSVs.

    Returns None for scale-mode CSVs (whose stems contain ``_scale_``)
    or anything else unparseable.
    """
    if "_scale_" in stem or stem.endswith("_scale"):
        return None
    if stem.endswith("_breakdown"):
        return None
    for cache in ("warm", "cold"):
        suffix = "_" + cache
        if stem.endswith(suffix):
            return stem[: -len(suffix)], cache
    return None


def _aggregate_scale_steps(run_dir: Path) -> int:
    """Concatenate per-step summary CSVs into one ``scale_summary.csv``.

    The step CSVs are already pre-aggregated per (protocol, cache, rate);
    here we just concatenate them so plots can read a single file.
    """
    step_csvs = sorted(run_dir.glob("*_scale_*_steps.csv"))
    if not step_csvs:
        return 0
    out = run_dir / "scale_summary.csv"
    header_written = False
    n = 0
    with open(out, "w", newline="") as f_out:
        writer = None
        for c in step_csvs:
            with open(c, newline="") as f_in:
                reader = csv.DictReader(f_in)
                for row in reader:
                    if writer is None:
                        writer = csv.DictWriter(f_out, fieldnames=reader.fieldnames)
                        writer.writeheader()
                        header_written = True
                    writer.writerow(row)
                    n += 1
    if header_written:
        print(f"wrote {out} ({n} rows from {len(step_csvs)} step files)")
    return n


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir")
    args = parser.parse_args()
    run_dir = Path(args.run_dir)

    # ── Latency-mode summary ──────────────────────────────────────────
    csvs = sorted(run_dir.glob("*_warm.csv")) + sorted(run_dir.glob("*_cold.csv"))
    summary_rows: list[dict] = []
    for c in csvs:
        parsed = _parse_latency_name(c.stem)
        if not parsed:
            continue
        protocol, cache = parsed
        rows = _load(c)
        s = _summarize(rows)
        if s is None:
            print(f"no successful attempts: {c}", file=sys.stderr)
            continue
        s["protocol"] = protocol
        s["cache_policy"] = cache
        summary_rows.append(s)

    wrote_any = False
    if summary_rows:
        out = run_dir / "summary.csv"
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
            w.writeheader()
            for s in summary_rows:
                w.writerow({k: s.get(k, "") for k in SUMMARY_FIELDS})
        print(f"wrote {out} ({len(summary_rows)} rows)")
        wrote_any = True

    # ── Scale-mode summary ────────────────────────────────────────────
    if _aggregate_scale_steps(run_dir) > 0:
        wrote_any = True

    if not wrote_any:
        print(f"no data in {run_dir}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
