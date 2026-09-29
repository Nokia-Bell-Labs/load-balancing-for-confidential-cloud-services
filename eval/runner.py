#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Evaluation infrastructure entry point.

One invocation runs one protocol against one configuration in one mode
(``latency`` or ``scale``) and writes per-attempt + per-step CSVs plus a
metadata JSON.  Re-running with the same ``(RUN_ID, protocol, mode,
cache_policy)`` refuses to overwrite unless ``--force`` is passed.

The runner is protocol-agnostic: protocol logic lives entirely in
``clients/<protocol>.py`` modules that expose ``build_client(env, runs,
...)``.  Mode-specific logic lives in this file as ``_run_latency_mode``
and ``_run_scale_mode``.

End-to-end semantics for both modes is defined in
``clients/_base.py``: ``total_e2e_ms`` covers TCP + all TLS handshakes
+ attestation verify + HTTP GET to first response byte.  In ``scale``
mode an additional ``wait_ms`` records the client-side queue time so
the saturation curve is response time, not just service time.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import os
import json
import queue
import random
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

import yaml

# Ensure ``clients`` resolves when invoked from the bench dir, and that
# the repository root is on the path so clients can import
# existing helpers like ``common.snp_attestation`` and ``ratls_bridge``
# rather than reimplementing them.
_BENCH_DIR = Path(__file__).resolve().parent
_CODEBASE_DIR = _BENCH_DIR.parent
for _p in (str(_BENCH_DIR), str(_CODEBASE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from clients._base import MAIN_FIELDS, AttemptResult, JwksCache  # noqa: E402

PROTOCOLS = ("vanilla", "ctls_proxy", "ctls_redirect", "ratls", "httpa")
MODES = ("latency", "scale")

# Extra columns the scale mode adds to MAIN_FIELDS on the per-attempt CSV.
SCALE_EXTRA_FIELDS = ("target_rate_rps", "wait_ms", "response_ms")

# Per-step summary CSV schema for scale mode.
SCALE_STEPS_FIELDS = (
    "protocol", "mode", "cache_policy", "target_rate_rps",
    "duration_s", "n_offered", "n_completed", "n_failed",
    "achieved_rps",
    "mean_lat_ms", "p50_lat_ms", "p95_lat_ms", "p99_lat_ms",
    "mean_resp_ms", "p50_resp_ms", "p95_resp_ms", "p99_resp_ms",
    "mean_wait_ms", "p50_wait_ms", "p95_wait_ms", "p99_wait_ms",
)


# ─────────────────────────────────────────────────────────────────────────
# Setup helpers
# ─────────────────────────────────────────────────────────────────────────

def _git_commit() -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
    except Exception:
        return "unknown"


def _git_dirty() -> bool:
    try:
        rc = subprocess.call(
            ["git", "diff", "--quiet"], stderr=subprocess.DEVNULL
        )
        return rc != 0
    except Exception:
        return False


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _check_endpoints(env: dict, protocol: str) -> None:
    """Refuse to run if the relevant endpoint is still TBD."""
    cfg = env["protocols"].get(protocol)
    if not cfg:
        raise SystemExit(f"runner: no env config for protocol {protocol!r}")
    tbds = [k for k, v in cfg.items() if isinstance(v, str) and v == "TBD"]
    if tbds:
        raise SystemExit(
            f"runner: configs/env.yaml has TBD values for {protocol}: {tbds}.\n"
            f"Fill them in (or override via env) before running."
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


def _safe_measure(client, run_id: str, attempt_id: int) -> AttemptResult:
    """Always return an AttemptResult; capture exceptions as ok=False rows."""
    try:
        return client.measure_one_attempt(
            attempt_id=attempt_id, run_id=run_id, is_warmup=False
        )
    except Exception as exc:  # noqa: BLE001
        return AttemptResult(
            protocol=getattr(client, "protocol_name", "unknown"),
            mode=getattr(client, "mode_name", ""),
            run_id=run_id,
            attempt_id=attempt_id,
            ok=False,
            notes=f"{type(exc).__name__}: {exc}",
        )


def _check_phase_sum(result: AttemptResult) -> None:
    """Warn if per-phase fields don't sum (within noise) to total_e2e_ms.

    Schema invariant: ``tcp_ms + tls_ms + attest_ms + extra_tcp_ms +
    extra_tls_ms + http_ms ≈ total_e2e_ms``.  Drift means a protocol
    module is mis-accounting time, which would silently bias the
    comparison.  Warn (not fail) so the run is not aborted on a
    borderline attempt but the deviation is visible.
    """
    if not result.ok or result.total_e2e_ms <= 0:
        return
    s = result.phase_sum_ms()
    e2e = result.total_e2e_ms
    tol = max(5.0, 0.10 * e2e)
    if abs(s - e2e) > tol and os.environ.get("JANUS_RUNNER_VERBOSE") == "1":   # a diagnostic of the phase breakdown, off by default
        print(
            f"  warn: phase sum {s:.2f}ms vs total_e2e {e2e:.2f}ms "
            f"(attempt {result.attempt_id}, delta {s - e2e:+.2f}ms)",
            file=sys.stderr,
        )


# ─────────────────────────────────────────────────────────────────────────
# Latency mode: sequential warmup + measurement
# ─────────────────────────────────────────────────────────────────────────

def _run_latency_mode(client, env, runs, args, out: Path, run_id: str,
                      cache_policy: str) -> int:
    csv_main = out / f"{args.protocol}_{cache_policy}.csv"
    csv_breakdown = out / f"{args.protocol}_{cache_policy}_breakdown.csv"
    meta_path = out / f"{args.protocol}_{cache_policy}.meta.json"

    if csv_main.exists() and not args.force:
        print(
            f"runner: refusing to overwrite {csv_main}.\n"
            f"Pass --force or pick a new RUN_ID.",
            file=sys.stderr,
        )
        return 2

    n_warmup = int(runs["n_warmup"])
    n_measure = int(runs["n_measure"])

    meta = _common_meta(args, runs, env, run_id, cache_policy, mode="latency")
    meta.update({"n_warmup": n_warmup, "n_measure": n_measure})
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"[{args.protocol}/{cache_policy}/latency] warmup {n_warmup}...")
    warmup_errors = 0
    for i in range(n_warmup):
        try:
            client.measure_one_attempt(
                attempt_id=-1 - i, run_id=run_id, is_warmup=True
            )
        except Exception as exc:  # noqa: BLE001
            warmup_errors += 1
            print(f"  warmup[{i}] error: {exc}", file=sys.stderr)
    if n_warmup > 0 and warmup_errors >= max(1, n_warmup // 2):
        print(
            f"runner: {warmup_errors}/{n_warmup} warmup attempts failed; aborting.",
            file=sys.stderr,
        )
        return 3

    print(f"[{args.protocol}/{cache_policy}/latency] measure {n_measure}...")
    main_writer = None
    bd_writer = None
    with open(csv_main, "w", newline="") as f_main, open(
        csv_breakdown, "w", newline=""
    ) as f_bd:
        for i in range(n_measure):
            result = _safe_measure(client, run_id, i)
            _check_phase_sum(result)
            row = result.to_main_row()
            if main_writer is None:
                main_writer = csv.DictWriter(f_main, fieldnames=MAIN_FIELDS)
                main_writer.writeheader()
            main_writer.writerow(row)
            f_main.flush()
            bd_row = result.to_breakdown_row()
            if bd_row:
                if bd_writer is None:
                    # extrasaction="ignore": protocol breakdown dicts may vary
                    # their keys across attempts (e.g. the RA+TLS wrapper emits
                    # extra timing fields on some connections); tolerate that
                    # rather than crashing the run.
                    bd_writer = csv.DictWriter(
                        f_bd, fieldnames=list(bd_row.keys()),
                        extrasaction="ignore"
                    )
                    bd_writer.writeheader()
                bd_writer.writerow(bd_row)
                f_bd.flush()

    print(f"wrote {csv_main}")
    if bd_writer is not None:
        print(f"wrote {csv_breakdown}")
    # completeness rule: a latency run is a reproduction only if at least 90 % of the
    # measured attempts succeeded (every attempt is in the CSV either way, with ok=0/1).
    ok_rows = sum(1 for r in csv.DictReader(open(csv_main)) if r.get("ok") == "1")
    if ok_rows < 0.9 * n_measure:
        print(f"runner: only {ok_rows}/{n_measure} measured attempts succeeded ({csv_main}); FAILED", file=sys.stderr)
        return 4
    print(f"runner: {ok_rows}/{n_measure} measured attempts succeeded")
    return 0


# ─────────────────────────────────────────────────────────────────────────
# Scale mode: open-loop Poisson arrivals, per-rate run
# ─────────────────────────────────────────────────────────────────────────

def _run_scale_mode(client, env, runs, args, out: Path, run_id: str,
                    cache_policy: str) -> int:
    scale_cfg = dict(runs.get("scale", {}) or {})
    # per-run overrides (eval/ae/run_fig6.sh uses the paper's per-N grids): comma-separated rates, seconds
    if os.environ.get("JANUS_SCALE_RATES"):
        scale_cfg["rates_rps"] = [float(x) for x in os.environ["JANUS_SCALE_RATES"].split(",") if x.strip()]
    for k, envk in (("per_step_warmup_s", "JANUS_SCALE_WARMUP_S"), ("per_step_window_s", "JANUS_SCALE_WINDOW_S")):
        if os.environ.get(envk): scale_cfg[k] = float(os.environ[envk])
    rates: list[float] = [float(r) for r in scale_cfg.get("rates_rps", [])]
    if not rates:
        print(
            "runner: runs.yaml has no scale.rates_rps; nothing to do in scale mode.",
            file=sys.stderr,
        )
        return 2
    warmup_s = float(scale_cfg.get("per_step_warmup_s", 5))
    window_s = float(scale_cfg.get("per_step_window_s", 20))
    max_workers = int(scale_cfg.get("max_workers", 64))
    base_seed = int(scale_cfg.get("seed", 17))

    csv_main = out / f"{args.protocol}_scale_{cache_policy}.csv"
    csv_steps = out / f"{args.protocol}_scale_{cache_policy}_steps.csv"
    csv_breakdown = out / f"{args.protocol}_scale_{cache_policy}_breakdown.csv"
    meta_path = out / f"{args.protocol}_scale_{cache_policy}.meta.json"

    if csv_main.exists() and not args.force:
        print(
            f"runner: refusing to overwrite {csv_main}.\n"
            f"Pass --force or pick a new RUN_ID.",
            file=sys.stderr,
        )
        return 2

    meta = _common_meta(args, runs, env, run_id, cache_policy, mode="scale")
    meta.update({
        "scale_rates_rps": rates,
        "per_step_warmup_s": warmup_s,
        "per_step_window_s": window_s,
        "max_workers": max_workers,
        "base_seed": base_seed,
    })
    meta_path.write_text(json.dumps(meta, indent=2))

    main_fields = list(MAIN_FIELDS) + list(SCALE_EXTRA_FIELDS)
    with open(csv_main, "w", newline="") as f_main, \
         open(csv_steps, "w", newline="") as f_steps, \
         open(csv_breakdown, "w", newline="") as f_bd:
        main_writer = csv.DictWriter(f_main, fieldnames=main_fields)
        main_writer.writeheader()
        steps_writer = csv.DictWriter(f_steps, fieldnames=list(SCALE_STEPS_FIELDS))
        achieved_any = False
        steps_writer.writeheader()
        bd_writer = None  # lazy

        for rate in rates:
            seed = base_seed * 1000 + int(rate)
            print(
                f"[{args.protocol}/{cache_policy}/scale] rate={rate} req/s "
                f"warmup={warmup_s}s window={window_s}s "
                f"workers={max_workers} seed={seed}"
            )
            step = _run_scale_step(
                client=client, target_rate=rate,
                warmup_s=warmup_s, window_s=window_s,
                max_workers=max_workers, seed=seed,
                run_id=run_id, cache_policy=cache_policy,
            )
            for wait_ms, result in step["attempts"]:
                row = result.to_main_row()
                row["target_rate_rps"] = rate
                row["wait_ms"] = round(wait_ms, 4)
                row["response_ms"] = round(
                    wait_ms + (result.total_e2e_ms if result.ok else 0.0), 4
                )
                main_writer.writerow(row)
                bd_row = result.to_breakdown_row()
                if bd_row:
                    bd_row["target_rate_rps"] = rate
                    if bd_writer is None:
                        # See note above: tolerate varying breakdown keys.
                        bd_writer = csv.DictWriter(
                            f_bd, fieldnames=list(bd_row.keys()),
                            extrasaction="ignore"
                        )
                        bd_writer.writeheader()
                    bd_writer.writerow(bd_row)
            steps_writer.writerow(step["summary"])
            achieved_any = achieved_any or float(step["summary"]["achieved_rps"]) > 0
            f_main.flush(); f_steps.flush(); f_bd.flush()
            print(
                f"  achieved={step['summary']['achieved_rps']:.1f} req/s  "
                f"completed={step['summary']['n_completed']}/"
                f"{step['summary']['n_offered']}  "
                f"p50_resp={step['summary']['p50_resp_ms']:.2f}ms  "
                f"p99_resp={step['summary']['p99_resp_ms']:.2f}ms"
            )

    # a throughput run is a measurement only if some offered rate produced successful requests
    # (overload at high rates is expected and recorded per attempt; none at all is a broken path)
    if not achieved_any:
        print(f"runner: no successful request at any offered rate ({csv_main}); FAILED", file=sys.stderr)
        return 4
    print(f"wrote {csv_main}")
    print(f"wrote {csv_steps}")
    if bd_writer is not None:
        print(f"wrote {csv_breakdown}")
    return 0


def _run_scale_step(*, client, target_rate: float, warmup_s: float,
                    window_s: float, max_workers: int, seed: int,
                    run_id: str, cache_policy: str) -> dict:
    """Run one (protocol, rate) step.

    Open-loop driver: a producer schedules Poisson-spaced arrivals into a
    bounded queue; ``max_workers`` thread workers pull and execute one
    attempt each.  ``wait_ms`` is ``actual_pull_time - planned_arrival``
    so queue time at the client driver counts toward response time.

    Phases:
      0..warmup_s   — settle TCP slow-start, JWKS cache, JIT, etc.  Not measured.
      warmup_s..warmup_s+window_s — the measurement window.  Attempts
          scheduled in this window are recorded.

    Attempts scheduled after the window aren't issued: the producer
    exits at ``t_window_end`` and remaining in-flight attempts drain
    with a short grace period.
    """
    rng = random.Random(seed)
    # Unbounded queue so the producer stays on its Poisson schedule
    # regardless of worker progress.  A bounded queue would block the
    # producer at saturation, silently degrading the measurement from
    # open-loop to closed-loop: achieved_rps would match offered_rps
    # even past capacity, hiding the very saturation we want to expose.
    # Queue items are tiny tuples; memory is bounded in practice by
    # (offered_rate × window_s) which is well under 100k entries for
    # realistic run parameters.
    job_q: queue.Queue = queue.Queue()
    stop = threading.Event()

    measured_lock = threading.Lock()
    # Each row: (wait_ms, result, t_completion).  t_completion is the
    # perf_counter() reading right after the attempt finished, and is
    # used to compute throughput within the window (completions that
    # finished after t_window_end are recorded for latency analysis
    # but do not count toward achieved_rps).
    measured: list[tuple[float, AttemptResult, float]] = []

    # Computed below; bound via mutable container so the worker closure
    # can read the value after the producer assigns it.
    window_end_holder: list[float] = [float("inf")]

    def worker():
        while True:
            try:
                item = job_q.get(timeout=0.5)
            except queue.Empty:
                if stop.is_set():
                    return
                continue
            if item is None:
                job_q.task_done()
                return
            planned_t, attempt_id, is_window = item
            try:
                t_pull = time.perf_counter()
                wait_ms = max(0.0, (t_pull - planned_t) * 1000.0)
                result = client.measure_one_attempt(
                    attempt_id=attempt_id, run_id=run_id,
                    is_warmup=not is_window,
                )
                t_done = time.perf_counter()
                _check_phase_sum(result)
                if is_window:
                    with measured_lock:
                        measured.append((wait_ms, result, t_done))
            except Exception as exc:  # noqa: BLE001
                if is_window:
                    err = AttemptResult(
                        protocol=getattr(client, "protocol_name", "?"),
                        mode=getattr(client, "mode_name", ""),
                        run_id=run_id, attempt_id=attempt_id,
                        ok=False, notes=f"{type(exc).__name__}: {exc}",
                    )
                    with measured_lock:
                        measured.append((0.0, err, time.perf_counter()))
            finally:
                job_q.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max_workers)]
    for t in threads:
        t.start()

    # Producer: schedule arrivals at Poisson interarrival 1/lambda.
    #
    # Two-phase open-loop driver:
    #   1. WARMUP: schedule arrivals at the target rate for warmup_s,
    #      letting TCP slow-start / JWKS cache / JIT / etc. settle.
    #      These arrivals are tagged is_window=False so their
    #      completions don't enter ``measured``.
    #   2. At warmup_end, DRAIN the queue (drop unstarted warmup items)
    #      and wait for in-flight warmup work to finish.  Without this
    #      drain, overloaded rates would leave the queue front-loaded
    #      with warmup items, starving window arrivals of worker
    #      capacity and depressing achieved_rps artificially.
    #   3. WINDOW: schedule arrivals at the target rate for window_s.
    #      Completions whose ``t_completion`` falls inside the window
    #      count toward achieved_rps.
    attempt_id = 0
    n_offered_window = 0
    t_phase_start = time.perf_counter()
    t_warmup_end = t_phase_start + warmup_s
    # Defaults so the summary block remains well-defined even if phase 3
    # never starts (an exception during warmup, for example).
    t_window_start_actual = t_warmup_end
    t_window_end = t_warmup_end + window_s
    window_end_holder[0] = t_window_end
    next_arrival = t_phase_start
    drained_at_boundary = 0

    def _pace_arrivals(end_t: float, is_window: bool):
        """Run the Poisson producer until ``end_t``.

        Schedules arrivals at the target rate using ``next_arrival`` as
        the rolling absolute deadline so accumulated sleep slop doesn't
        drift the long-run rate.
        """
        nonlocal attempt_id, next_arrival, n_offered_window
        while True:
            now = time.perf_counter()
            if now >= end_t:
                return
            if now < next_arrival:
                # Coarser sleep at higher rates is fine: wait_ms is
                # measured against planned_t, so any producer slip is
                # honestly accounted for, not lost.
                time.sleep(min(next_arrival - now, 0.05))
                continue
            attempt_id += 1
            job_q.put_nowait((next_arrival, attempt_id, is_window))
            if is_window:
                n_offered_window += 1
            next_arrival += rng.expovariate(target_rate)

    try:
        # Phase 1: warmup arrivals.
        _pace_arrivals(t_warmup_end, is_window=False)

        # Phase 2: drain.  Pop any remaining warmup items so the window
        # starts from a quiet queue; then wait for in-flight warmup
        # items to complete (job_q.join blocks until every put() has a
        # matching task_done(), so workers finishing their current item
        # releases the join).
        try:
            while True:
                job_q.get_nowait()
                job_q.task_done()
                drained_at_boundary += 1
        except queue.Empty:
            pass
        job_q.join()

        # Phase 3: window arrivals.  Re-anchor next_arrival to ``now``
        # so the inter-arrival sequence doesn't carry warmup slop into
        # the window's schedule.
        t_window_start_actual = time.perf_counter()
        t_window_end = t_window_start_actual + window_s
        window_end_holder[0] = t_window_end
        next_arrival = t_window_start_actual
        _pace_arrivals(t_window_end, is_window=True)
    finally:
        stop.set()
        # Let in-flight + queued window requests drain so we observe a
        # steady-state sample of completions.  Bounded so an overloaded,
        # low-capacity server (response time >> window) still terminates.
        grace_deadline = time.perf_counter() + max(15.0, window_s * 2.0)
        while not job_q.empty() and time.perf_counter() < grace_deadline:
            time.sleep(0.1)
        for _ in threads:
            try:
                job_q.put_nowait(None)
            except queue.Full:
                break
        for t in threads:
            t.join(timeout=2)

    successful = [(w, r, t) for (w, r, t) in measured if r.ok]
    failed = [(w, r, t) for (w, r, t) in measured if not r.ok]
    lats = [r.total_e2e_ms for (_, r, _) in successful]
    waits = [w for (w, _, _) in successful]
    resps = [w + r.total_e2e_ms for (w, r, _) in successful]
    # Achieved throughput = steady-state inter-completion rate: the number
    # of window-tagged successful completions divided by the elapsed time
    # between the first and last such completion.  This equals the server's
    # service rate (capacity) under saturation and the offered rate under
    # light load, and is robust to (a) the pipeline fill-up transient at
    # window start and (b) within-window truncation when the response time
    # exceeds the window -- the two artifacts that made achieved_rps
    # non-monotonic for the low-capacity attested-TLS baselines.
    comp_times = sorted(t for (_, _, t) in successful)
    if len(comp_times) >= 2 and (comp_times[-1] - comp_times[0]) > 0:
        achieved_rps = (len(comp_times) - 1) / (comp_times[-1] - comp_times[0])
    else:
        achieved_rps = len(comp_times) / window_s if window_s > 0 else 0.0

    summary = {
        "protocol": getattr(client, "protocol_name", "?"),
        "mode": getattr(client, "mode_name", ""),
        "cache_policy": cache_policy,
        "target_rate_rps": target_rate,
        "duration_s": window_s,
        "n_offered": n_offered_window,
        "n_completed": len(successful),
        "n_failed": len(failed),
        "achieved_rps": round(achieved_rps, 4),
        "mean_lat_ms": round(sum(lats) / len(lats), 4) if lats else float("nan"),
        "p50_lat_ms": round(_percentile(lats, 50), 4) if lats else float("nan"),
        "p95_lat_ms": round(_percentile(lats, 95), 4) if lats else float("nan"),
        "p99_lat_ms": round(_percentile(lats, 99), 4) if lats else float("nan"),
        "mean_resp_ms": round(sum(resps) / len(resps), 4) if resps else float("nan"),
        "p50_resp_ms": round(_percentile(resps, 50), 4) if resps else float("nan"),
        "p95_resp_ms": round(_percentile(resps, 95), 4) if resps else float("nan"),
        "p99_resp_ms": round(_percentile(resps, 99), 4) if resps else float("nan"),
        "mean_wait_ms": round(sum(waits) / len(waits), 4) if waits else float("nan"),
        "p50_wait_ms": round(_percentile(waits, 50), 4) if waits else float("nan"),
        "p95_wait_ms": round(_percentile(waits, 95), 4) if waits else float("nan"),
        "p99_wait_ms": round(_percentile(waits, 99), 4) if waits else float("nan"),
    }
    # Strip the t_completion from the per-attempt rows; the runner only
    # writes (wait_ms, result) into the CSV.
    attempts_for_csv = [(w, r) for (w, r, _) in measured]
    return {"attempts": attempts_for_csv, "summary": summary}


# ─────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────

def _common_meta(args, runs, env, run_id, cache_policy, mode) -> dict:
    return {
        "schema_version": runs.get("schema_version", 1),
        "run_id": run_id,
        "protocol": args.protocol,
        "mode": mode,
        "cache_policy": cache_policy,
        "started_iso": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "git_dirty": _git_dirty(),
        "quote_policy": runs.get("quote_policy", "fresh_per_connection"),
        "maa_url": env.get("maa", {}).get("url"),
        "payload_path": env.get("payload", {}).get("path"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Janus bench runner")
    parser.add_argument("--protocol", required=True, choices=PROTOCOLS)
    parser.add_argument(
        "--mode", choices=MODES, default="latency",
        help="latency = sequential per-attempt timing (default).  "
             "scale = open-loop Poisson arrivals at each rate in "
             "runs.yaml::scale.rates_rps.",
    )
    parser.add_argument("--env", default="configs/env.yaml")
    parser.add_argument("--runs", default="configs/runs.yaml")
    parser.add_argument(
        "--out", required=True,
        help="Output directory (typically data/<RUN_ID>).",
    )
    parser.add_argument(
        "--cache-policy", choices=("warm", "cold"), default=None,
        help="Override runs.yaml cache_policy.",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite existing CSVs.  Off by default to protect prior data.",
    )
    args = parser.parse_args()

    env = _load_yaml(Path(args.env))
    runs = _load_yaml(Path(args.runs))
    cache_policy = args.cache_policy or runs.get("cache_policy", "warm")

    _check_endpoints(env, args.protocol)

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    run_id = out.name

    mod_name = f"clients.{args.protocol}"
    try:
        mod = importlib.import_module(mod_name)
    except ImportError as e:
        print(
            f"runner: protocol client {mod_name} is not implemented yet.\n"
            f"  ImportError: {e}",
            file=sys.stderr,
        )
        return 2
    if not hasattr(mod, "build_client"):
        print(
            f"runner: {mod_name} does not expose build_client(env, runs, ...)",
            file=sys.stderr,
        )
        return 2

    if os.environ.get("JANUS_PAYLOAD_PATH"):      # e.g. eval/ae/run_fig6.sh: the capped /health for every protocol
        env.setdefault("payload", {})["path"] = os.environ["JANUS_PAYLOAD_PATH"]
    jwks_cache = JwksCache(out / "jwks_cache", policy=cache_policy)
    client = mod.build_client(
        env=env, runs=runs, jwks_cache=jwks_cache, cache_policy=cache_policy
    )

    if args.mode == "latency":
        return _run_latency_mode(client, env, runs, args, out, run_id, cache_policy)
    elif args.mode == "scale":
        return _run_scale_mode(client, env, runs, args, out, run_id, cache_policy)
    else:
        raise SystemExit(f"runner: unknown mode {args.mode!r}")


if __name__ == "__main__":
    sys.exit(main())
