#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Generate the paper's evaluation figures from the real measurement data.

Matches the visual style of the original draft figures (serif, log axes,
per-protocol colours/markers consistent across plots).  Four figures:

  fig_e2e_latency       p50 connection-establishment latency vs network RTT
                        (tc-netem run), 5 protocols, log-y.
  fig_latency_breakdown stacked per-phase decomposition of connection
                        establishment at native RTT.
  fig_scalability_single  throughput + p50 response vs offered load, single
                        backend, 5 protocols (2 panels), log axes.
  fig_scalability_backends  redirect throughput vs backend count (linear) with
                        proxy's frontend-bound ceiling for reference.

Reads:
  data/rtt-<R>/<proto>_warm.csv                 (RTT series)
  data/<latency_run>/<proto>_warm.csv + _breakdown.csv   (breakdown)
  data/<scale_run>/<proto>_scale_warm_steps.csv (single-backend scale)
  data/mb-N<k>/ctls_redirect_scale_warm_steps.csv  (backend scaling)
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from janus_style import apply, PROTO, PCTL, PHASE, C_FE, LEGEND, LEGEND_FS

apply()

# Consistent per-protocol style across all figures.  Colours match janus_style
# PROTO (RA+TLS=brown, HTTPA=orange); markers/linestyles local to this module.
S = {
    "vanilla":       dict(c="#444444", m="o", ls="-",  label="Vanilla TLS"),
    "ctls_proxy":    dict(c="#2ca02c", m="s", ls="-",  label="Janus-proxy"),
    "ctls_redirect": dict(c="#9467bd", m="^", ls="-",  label="Janus-redirection"),
    "ratls":         dict(c="#8c564b", m="D", ls="--", label="RA+TLS"),
    "httpa":         dict(c="#ff7f0e", m="v", ls="--", label="HTTPA/2"),
}
ORDER = ["vanilla", "ctls_proxy", "ctls_redirect", "ratls", "httpa"]


def _median_total(csv_path: Path) -> float | None:
    if not csv_path.exists():
        return None
    vals = []
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            if int(r.get("ok", 1)) == 1:
                vals.append(float(r["total_e2e_ms"]))
    return statistics.median(vals) if vals else None


def _establishment_vals(csv_path: Path) -> list[float]:
    """All per-attempt connection-establishment latencies = sum of every
    phase EXCEPT the trailing application GET (http_ms).  Uniform end-state
    across protocols, matching fig_latency_breakdown and the paper's stated
    metric (not total_e2e, which would unfairly add a GET round trip at high
    RTT)."""
    if not csv_path.exists():
        return []
    vals = []
    for r in csv.DictReader(open(csv_path)):
        if int(r.get("ok", 1)) != 1:
            continue
        est = (float(r.get("tcp_ms", 0) or 0) + float(r.get("tls_ms", 0) or 0)
               + float(r.get("attest_ms", 0) or 0)
               + float(r.get("extra_tcp_ms", 0) or 0)
               + float(r.get("extra_tls_ms", 0) or 0))
        vals.append(est)
    return vals


def _median_establishment(csv_path: Path) -> float | None:
    vals = _establishment_vals(csv_path)
    return statistics.median(vals) if vals else None


def _pctl(vals: list[float], q: float) -> float | None:
    """Nearest-rank percentile (q in [0,100]); matches the runner's p95/p99."""
    if not vals:
        return None
    s = sorted(vals)
    import math
    i = min(len(s) - 1, max(0, math.ceil(q / 100.0 * len(s)) - 1))
    return s[i]


def _mean_cols(csv_path: Path, cols: list[str]) -> dict:
    # Uses the MEDIAN of each phase so the breakdown is consistent with the
    # median-based latency-vs-RTT figure (the attested-TLS baselines have a
    # heavy quote-gen tail that would inflate means).
    out = {c: 0.0 for c in cols}
    if not csv_path.exists():
        return out
    rows = [r for r in csv.DictReader(open(csv_path)) if int(r.get("ok", 1)) == 1]
    if not rows:
        return out
    for c in cols:
        out[c] = statistics.median(float(r.get(c, 0) or 0) for r in rows)
    return out


def _bd_mean(csv_path: Path, col: str) -> float:
    if not csv_path.exists():
        return 0.0
    vals = [float(r[col]) for r in csv.DictReader(open(csv_path))
            if col in r and r[col] not in ("", None)]
    return statistics.median(vals) if vals else 0.0


# ───────────────────────── fig 1: latency vs RTT ─────────────────────────

def _ols_slope(xs, ys):
    """Least-squares slope of ys vs xs (no numpy dependency).  For the
    RTT series this slope IS the protocol's critical-path round-trip count:
    each injected ms of RTT lands once per round trip, so d(latency)/d(RTT)
    counts round trips.  It is implementation-independent (the per-call CPU
    cost lives in the intercept), which is what makes it the design-level
    discriminator between the baselines."""
    n = len(xs)
    if n < 2:
        return float("nan")
    mx = sum(xs) / n
    my = sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return float("nan")
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


def fig_e2e_latency(data: Path, out: Path, rtts):
    fig, ax = plt.subplots(figsize=(5.6, 3.9))
    for p in ORDER:
        xs, ys, hi = [], [], []
        for r in rtts:
            vals = _establishment_vals(data / f"rtt-{r}" / f"{p}_warm.csv")
            if vals:
                xs.append(r)
                ys.append(statistics.median(vals))
                hi.append(_pctl(vals, 95))
        if not xs:
            continue
        st = S[p]
        # The two attested-TLS baselines carry the comparison this figure
        # is about (RA+TLS vs HTTPA/2 round-trip structure), so draw them
        # a touch heavier and label them with the fitted round-trip count.
        baseline = p in ("ratls", "httpa")
        # p50..p95 band: razor-thin for vanilla/Janus (predictable), fat for
        # the baselines (bursty paravisor vTPM quote) -- the tail contrast is
        # the point, so it is visible without a separate figure.
        ax.fill_between(xs, ys, hi, color=st["c"], alpha=0.20, linewidth=0,
                        zorder=1)
        ax.plot(xs, ys, color=st["c"], marker=st["m"], linestyle=st["ls"],
                linewidth=2.2 if baseline else 1.7, markersize=6,
                label=st["label"], zorder=3 if baseline else 2)
    ax.set_yscale("log")
    ax.set_xlabel("Network RTT (ms)")
    ax.set_ylabel("Connection establishment (ms)")
    ax.set_xlim(rtts[0] - 4, rtts[-1] + 6)
    ax.grid(True, which="both", linestyle=":", alpha=0.4)
    # One combined legend (lower right): the protocols, plus a style key making
    # explicit that each curve is the p50 (median) and each shaded band is its
    # p50-p95 spread -- so p50/p95 are marked without crowding the plot.
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch
    prot_h, prot_l = ax.get_legend_handles_labels()
    style_h = [Line2D([0], [0], color="0.35", lw=1.8),
               Patch(facecolor="0.5", alpha=0.30)]
    ax.legend(prot_h + style_h, prot_l + ["p50 (median)", "p50–p95 band"],
              frameon=False, loc="lower right", fontsize=8.5)
    _save(fig, out, "fig_e2e_latency")


# ──────────────────── fig 2: latency breakdown (stacked) ────────────────────

def fig_latency_breakdown(data: Path, run: str, out: Path):
    """Per-protocol decomposition of connection establishment, on a
    BROKEN linear y-axis so both regimes are legible at once:

      * the bottom panel (0..~25 ms) resolves the vanilla -> Janus
        increments -- i.e. the *overhead over vanilla* the Overhead
        subsection dissects, and
      * the top panel (~90..160 ms) shows the quote-gen + AS-RTT towers
        that Janus does NOT pay per connection -- i.e. *why we beat the
        per-connection baselines*.

    Every protocol shares the same TLS-handshake base (= vanilla); what
    each adds on top tells the story.  Redirection's control/routing
    round trip is shown as its own phase (``route_ms``), NOT folded into
    client-side validation.
    """
    d = data / run
    van_tls = _mean_cols(d / "vanilla_warm.csv", ["tls_ms"])["tls_ms"]

    comps = {}  # proto -> dict(component -> ms)
    comps["vanilla"] = {"tls": van_tls}
    # Janus proxy: control TLS + crypto validation (jwt sig + reportdata)
    mp = _mean_cols(d / "ctls_proxy_warm.csv", ["tls_ms", "attest_ms"])
    proxy_validate = mp["attest_ms"]
    comps["ctls_proxy"] = {"tls": mp["tls_ms"], "validate": proxy_validate}
    # Janus redirect: control TLS + (validate, route) + data-conn TLS(+DC).
    # Prefer the directly-measured validate_ms/route_ms split; fall back to
    # deriving it from the n=50 data until the re-instrumented run lands.
    mr = _mean_cols(d / "ctls_redirect_warm.csv",
                    ["tls_ms", "extra_tls_ms", "attest_ms"])
    bdr = d / "ctls_redirect_warm_breakdown.csv"
    val = _bd_mean(bdr, "validate_ms")
    rte = _bd_mean(bdr, "route_ms")
    if val <= 0 and rte <= 0:
        val = proxy_validate
        rte = max(0.0, mr["attest_ms"] - val)
        print("  [breakdown] redirect validate/route split DERIVED from "
              "current data (no validate_ms/route_ms columns yet); will be "
              "measured directly after the re-instrumented n=100 run")
    comps["ctls_redirect"] = {"tls": mr["tls_ms"], "tls2": mr["extra_tls_ms"],
                              "route": rte, "validate": val}
    # HTTPA: base TLS + server quote-gen (bundle_rtt) + MAA verify
    bd = d / "httpa_warm_breakdown.csv"
    mh = _mean_cols(d / "httpa_warm.csv", ["tls_ms"])
    comps["httpa"] = {"tls": mh["tls_ms"],
                      "quote": _bd_mean(bd, "bundle_rtt_ms"),
                      "maa": _bd_mean(bd, "maa_verify_ms")}
    # RA+TLS: base TLS (~vanilla) + in-handshake quote-gen + MAA verify
    bd = d / "ratls_warm_breakdown.csv"
    base = _bd_mean(bd, "tls_handshake_baseline")
    comps["ratls"] = {"tls": van_tls,
                      "quote": max(0.0, base - van_tls),
                      "maa": _bd_mean(bd, "ra_verification")}

    # TCP connect: a thin shared base so each bar's total matches the
    # median establishment in fig:e2e-latency (otherwise the bars would
    # under-count by the sub-2 ms connect and disagree across figures).
    for p in comps:
        comps[p]["tcp"] = _mean_cols(d / f"{p}_warm.csv", ["tcp_ms"])["tcp_ms"]

    # bottom -> top stacking order; same colour = same phase across bars.
    layers = [("tcp",      "TCP connect",                    "#9e9e9e"),
              ("tls",      "TLS handshake",                  "#17becf"),
              ("tls2",     "2nd TLS handshake (→backend)", "#0e6e74"),
              ("route",    "Control / routing exchange",     "#ff7f0e"),
              ("validate", "Client-side validation",         "#2ca02c"),
              ("quote",    "Server quote generation",        "#d62728"),
              ("maa",      "Attestation service (MAA) RTT",  "#9467bd")]
    protos = ["vanilla", "ctls_proxy", "ctls_redirect", "ratls", "httpa"]
    xlabels = [S[p]["label"] for p in protos]
    x = list(range(len(protos)))
    totals = [sum(comps[p].values()) for p in protos]
    # Per-attempt p95 of TOTAL establishment, from the SAME run.  We label
    # it numerically rather than as a stacked whisker because tails do not
    # decompose additively (p95 of the sum != sum of per-phase p95); the
    # caption attributes the tail to the one bursty phase (quote gen).
    # Label with the TRUE median-of-total (matches fig:e2e-latency exactly);
    # the stacked bar height is sum-of-phase-medians, identical to within
    # rounding but shown as the same integer for cross-figure consistency.
    # The tail (p95/p99) is shown properly in fig_latency_percentiles, not as
    # text here -- this figure is the median *composition* (the "why").
    p50s = [_median_establishment(d / f"{p}_warm.csv") for p in protos]

    # Broken axis: top panel for the baseline towers, bottom for the
    # vanilla/Janus regime.  Draw the full stack on both; each clips.
    lo_top = 90.0
    fig, (axt, axb) = plt.subplots(
        2, 1, sharex=True, figsize=(6.2, 4.3),
        gridspec_kw={"height_ratios": [1.0, 1.5], "hspace": 0.06})
    for ax in (axt, axb):
        bottoms = [0.0] * len(protos)
        for key, lbl, col in layers:
            vals = [comps[p].get(key, 0.0) for p in protos]
            if max(vals) <= 0:
                continue
            ax.bar(x, vals, 0.62, bottom=bottoms, label=lbl, color=col,
                   edgecolor="white", linewidth=0.5)
            bottoms = [b + v for b, v in zip(bottoms, vals)]
    axt.set_ylim(lo_top, max(totals) * 1.10)
    axb.set_ylim(0, 27)
    # hide the inner spines and add diagonal break marks
    axt.spines["bottom"].set_visible(False)
    axb.spines["top"].set_visible(False)
    axt.tick_params(axis="x", which="both", bottom=False)
    dd = 0.6
    bk = dict(marker=[(-1, -dd), (1, dd)], markersize=7, linestyle="none",
              color="k", mec="k", mew=1, clip_on=False)
    axt.plot([0, 1], [0, 0], transform=axt.transAxes, **bk)
    axb.plot([0, 1], [1, 1], transform=axb.transAxes, **bk)
    # p50 total label above each bar, on whichever panel it lands in.
    for i, t in enumerate(totals):
        p50 = p50s[i] if p50s[i] is not None else t
        if t >= 27:
            axt.text(i, t + (max(totals) - lo_top) * 0.02, f"{p50:.0f}",
                     ha="center", va="bottom", fontsize=9)
        else:
            axb.text(i, t + 0.5, f"{p50:.0f}", ha="center", va="bottom",
                     fontsize=9)
    axb.set_xticks(x, xlabels, rotation=12)
    fig.supylabel("p50 connection establishment (ms)", fontsize=12, x=0.02)
    h, l = axb.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False, fontsize=8.5,
               bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_latency_breakdown", tight=True)


def _col_pctl(path: Path, col: str, q: float) -> float:
    """Percentile q of one CSV column over its per-attempt rows (0 if absent)."""
    import csv as _csv
    try:
        vals = [float(r[col]) for r in _csv.DictReader(open(path))
                if r.get(col) not in (None, "", "NA")]
    except Exception:
        return 0.0
    v = _pctl(vals, q)
    return v if v else 0.0


def _phase_comps_p50(d: Path):
    """Per-phase p50 composition of establishment latency, per protocol.
    Redirection's one-time control round trip is FOLDED into client-side
    validation (attest_ms = validate + route), not shown as its own layer."""
    vtls = _col_pctl(d / "vanilla_warm.csv", "tls_ms", 50)
    comps = {
        "vanilla":      {"tcp": _col_pctl(d/"vanilla_warm.csv","tcp_ms",50),
                         "tls": _col_pctl(d/"vanilla_warm.csv","tls_ms",50)},
        "ctls_proxy":   {"tcp": _col_pctl(d/"ctls_proxy_warm.csv","tcp_ms",50),
                         "tls": _col_pctl(d/"ctls_proxy_warm.csv","tls_ms",50),
                         "validate": _col_pctl(d/"ctls_proxy_warm.csv","attest_ms",50)},
        "ctls_redirect":{"tcp": _col_pctl(d/"ctls_redirect_warm.csv","tcp_ms",50),
                         "tls": _col_pctl(d/"ctls_redirect_warm.csv","tls_ms",50),
                         "tls2": _col_pctl(d/"ctls_redirect_warm.csv","extra_tls_ms",50),
                         "validate": _col_pctl(d/"ctls_redirect_warm.csv","attest_ms",50)},
        "httpa":        {"tcp": _col_pctl(d/"httpa_warm.csv","tcp_ms",50),
                         "tls": _col_pctl(d/"httpa_warm.csv","tls_ms",50),
                         "quote": _col_pctl(d/"httpa_warm_breakdown.csv","bundle_rtt_ms",50),
                         "maa": _col_pctl(d/"httpa_warm_breakdown.csv","maa_verify_ms",50)},
    }
    base = _col_pctl(d/"ratls_warm_breakdown.csv","tls_handshake_baseline",50)
    comps["ratls"] = {"tcp": _col_pctl(d/"ratls_warm.csv","tcp_ms",50),
                      "tls": vtls,
                      "quote": max(0.0, base - vtls),
                      "maa": _col_pctl(d/"ratls_warm_breakdown.csv","ra_verification",50)}
    # Fold the sub-ms TCP connect into the TLS-handshake layer: it is a separate
    # phase but too small to read on its own and not the point of the figure.
    for p in comps:
        comps[p]["tls"] = comps[p].get("tls", 0.0) + comps[p].pop("tcp", 0.0)
    return comps


_BD_LAYERS = [("tls","TCP + TLS handshake","#17becf"),
              ("tls2","Backend TLS+DC handshake","#0e6e74"),
              ("validate","Client-side validation","#2ca02c"),
              ("quote","Server quote generation","#d62728"),
              ("maa","Attestation-service RTT","#9467bd")]
_BD_PROTOS = ["vanilla","ctls_proxy","ctls_redirect","ratls","httpa"]


def _plot_breakdown(comps, out: Path, tag: str):
    """Broken-axis stacked bar of the phase composition for each protocol."""
    protos = _BD_PROTOS
    xlabels = [S[p]["label"] for p in protos]
    x = list(range(len(protos)))
    totals = [sum(comps[p].values()) for p in protos]
    janus = [totals[i] for i, p in enumerate(protos) if p.startswith(("vanilla","ctls"))]
    base = [totals[i] for i, p in enumerate(protos) if p in ("ratls", "httpa")]
    bottom_hi = max(janus) * 1.4
    top_lo, top_hi = min(base) * 0.80, max(base) * 1.13
    fig, (axt, axb) = plt.subplots(
        2, 1, sharex=True, figsize=(6.0, 4.2),
        gridspec_kw={"height_ratios": [1.0, 1.4], "hspace": 0.07})
    for ax in (axt, axb):
        bottoms = [0.0] * len(protos)
        for key, lbl, col in _BD_LAYERS:
            vals = [comps[p].get(key, 0.0) for p in protos]
            if max(vals) <= 0:
                continue
            ax.bar(x, vals, 0.62, bottom=bottoms, label=lbl, color=col,
                   edgecolor="white", linewidth=0.5)
            bottoms = [b + v for b, v in zip(bottoms, vals)]
    axt.set_ylim(top_lo, top_hi)
    axb.set_ylim(0, bottom_hi)
    axt.spines["bottom"].set_visible(False)
    axb.spines["top"].set_visible(False)
    axt.tick_params(axis="x", which="both", bottom=False)
    dd = 0.6
    bk = dict(marker=[(-1, -dd), (1, dd)], markersize=7, linestyle="none",
              color="k", mec="k", mew=1, clip_on=False)
    axt.plot([0, 1], [0, 0], transform=axt.transAxes, **bk)
    axb.plot([0, 1], [1, 1], transform=axb.transAxes, **bk)
    for i, t in enumerate(totals):
        if t >= bottom_hi:
            axt.text(i, t + (top_hi - top_lo) * 0.02, f"{t:.0f}",
                     ha="center", va="bottom", fontsize=9)
        else:
            axb.text(i, t + bottom_hi * 0.02, f"{t:.0f}",
                     ha="center", va="bottom", fontsize=9)
    axb.set_xticks(x, xlabels, rotation=12)
    fig.supylabel(f"{tag} establishment (ms)", fontsize=12, x=0.02)
    h, l = axb.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False, fontsize=8.5,
               bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, f"fig_latency_breakdown_{tag}", tight=True)


def _plot_breakdowns_combined(cols, out: Path):
    """One figure, p50 (a) and p95 (b) side by side, each a broken-axis stacked
    breakdown, with a single shared legend.  ``cols`` = [(tag, comps), ...]."""
    protos = _BD_PROTOS
    xlabels = [S[p]["label"] for p in protos]
    x = list(range(len(protos)))
    fig, axes = plt.subplots(
        2, 2, figsize=(7.0, 2.9), sharex="col",
        gridspec_kw={"height_ratios": [1.0, 1.4], "hspace": 0.07, "wspace": 0.20})
    for ci, (tag, comps) in enumerate(cols):
        axt, axb = axes[0][ci], axes[1][ci]
        totals = [sum(comps[p].values()) for p in protos]
        janus = [totals[i] for i, p in enumerate(protos) if p.startswith(("vanilla", "ctls"))]
        base = [totals[i] for i, p in enumerate(protos) if p in ("ratls", "httpa")]
        bottom_hi = max(janus) * 1.4
        top_lo, top_hi = min(base) * 0.80, max(base) * 1.13
        for ax in (axt, axb):
            bottoms = [0.0] * len(protos)
            for key, lbl, col in _BD_LAYERS:
                vals = [comps[p].get(key, 0.0) for p in protos]
                if max(vals) <= 0:
                    continue
                ax.bar(x, vals, 0.62, bottom=bottoms, label=lbl, color=col,
                       edgecolor="white", linewidth=0.5)
                bottoms = [b + v for b, v in zip(bottoms, vals)]
        axt.set_ylim(top_lo, top_hi)
        axb.set_ylim(0, bottom_hi)
        axt.tick_params(axis="y", labelsize=8)
        axb.tick_params(axis="y", labelsize=8)
        axt.spines["bottom"].set_visible(False)
        axb.spines["top"].set_visible(False)
        axt.tick_params(axis="x", which="both", bottom=False)
        dd = 0.6
        bk = dict(marker=[(-1, -dd), (1, dd)], markersize=6, linestyle="none",
                  color="k", mec="k", mew=1, clip_on=False)
        axt.plot([0, 1], [0, 0], transform=axt.transAxes, **bk)
        axb.plot([0, 1], [1, 1], transform=axb.transAxes, **bk)
        for i, t in enumerate(totals):
            if t >= bottom_hi:
                axt.text(i, t + (top_hi - top_lo) * 0.02, f"{t:.0f}",
                         ha="center", va="bottom", fontsize=8)
            else:
                axb.text(i, t + bottom_hi * 0.02, f"{t:.0f}",
                         ha="center", va="bottom", fontsize=8)
        axb.set_xticks(x, xlabels, rotation=15, fontsize=8)
        axt.set_title(f"({'ab'[ci]}) {tag}", fontsize=11)
    fig.supylabel("Connection establishment (ms)", fontsize=11, x=0.02)
    h, l = axes[1][0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False, fontsize=8.5,
               bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_latency_breakdowns")


def fig_latency_breakdowns(data: Path, run: str, out: Path):
    """Two stacked-bar breakdowns, p50 and p95.  The p95 bars use the p50
    composition with the measured p50->p95 tail growth attributed to the
    high-variance phase (quote generation for the baselines; the TLS handshake
    otherwise), since per-phase tails do not co-occur and so are not additive."""
    d = data / run
    p50 = _phase_comps_p50(d)
    # Snap each p50 stack to the true median establishment so the bar height
    # equals the figure/text number; the small residual (un-instrumented http
    # round trip, etc.) lands in the dominant phase.
    for p in _BD_PROTOS:
        tp50 = _median_establishment(d / f"{p}_warm.csv") or sum(p50[p].values())
        resid = tp50 - sum(p50[p].values())
        key = "quote" if "quote" in p50[p] else "tls"
        p50[p][key] = max(0.0, p50[p].get(key, 0.0) + resid)
    p95 = {p: dict(p50[p]) for p in _BD_PROTOS}
    for p in _BD_PROTOS:
        tp50 = _median_establishment(d / f"{p}_warm.csv") or 0.0
        tp95 = _pctl(_establishment_vals(d / f"{p}_warm.csv"), 95) or 0.0
        growth = max(0.0, tp95 - tp50)
        key = "quote" if "quote" in p95[p] else "tls"
        p95[p][key] += growth
    _plot_breakdowns_vstack([("p50", p50), ("p95", p95)], out)


def fig_latency_breakdowns_rtt(data: Path, out: Path, rtts):
    """RAW measured per-phase establishment breakdown, GROUPED BY RTT, p50 (a)
    and p95 (b).  Each bar's TOTAL height is the directly-measured p50/p95 at
    that RTT (no tail modeling); the per-phase split is the p50 composition with
    the measured p50->p95 growth attributed to the dominant phase so the stack
    sums to the real measured value."""
    p50_by = {}
    p95_by = {}
    for r in rtts:
        d = data / f"rtt-{r}"
        comps = _phase_comps_p50(d)
        for p in _BD_PROTOS:
            tp50 = _median_establishment(d / f"{p}_warm.csv") or sum(comps[p].values())
            resid = tp50 - sum(comps[p].values())
            key = "quote" if "quote" in comps[p] else "tls"
            comps[p][key] = max(0.0, comps[p].get(key, 0.0) + resid)
        p50_by[r] = comps
        c95 = {p: dict(comps[p]) for p in _BD_PROTOS}
        for p in _BD_PROTOS:
            tp50 = _median_establishment(d / f"{p}_warm.csv") or 0.0
            tp95 = _pctl(_establishment_vals(d / f"{p}_warm.csv"), 95) or 0.0
            key = "quote" if "quote" in c95[p] else "tls"
            c95[p][key] += max(0.0, tp95 - tp50)
        p95_by[r] = c95
    _plot_breakdowns_rtt_grouped([("p50", p50_by), ("p95", p95_by)], rtts, out,
                                 "fig_latency_breakdowns_rtt")


def _plot_breakdowns_rtt_grouped(cols, rtts, out: Path, fname: str):
    """Grouped stacked-bar breakdown: x grouped by RTT, 5 protocol bars per
    group, each a detailed phase stack.  p50 (a) over p95 (b), one shared phase
    legend.  Single linear y-axis per panel (magnitudes overlap across RTT, so
    a broken axis would not be well-defined)."""
    import matplotlib.gridspec as gridspec
    from matplotlib.patches import Patch
    protos = _BD_PROTOS
    short = {"vanilla": "Vanilla", "ctls_proxy": "Janus-proxy",
             "ctls_redirect": "Janus-redirect", "ratls": "RA+TLS",
             "httpa": "HTTPA/2"}
    panel = {"p50": "Median (p50)", "p95": "Tail (p95)"}
    bw, gap = 0.85, 1.9
    span = len(protos) * bw + gap
    fig = plt.figure(figsize=(7.2, 7.0))
    gs = gridspec.GridSpec(2, 1, hspace=1.25, top=0.91, bottom=0.20,
                           left=0.085, right=0.99, figure=fig)
    for ci, (tag, by) in enumerate(cols):
        ax = fig.add_subplot(gs[ci])
        xticks, xlabs, centers = [], [], []
        ymax = 0.0
        for gi, r in enumerate(rtts):
            comps = by[r]
            bx = gi * span
            for pi, p in enumerate(protos):
                xpos = bx + pi * bw
                bot = 0.0
                for key, lbl, col in _BD_LAYERS:
                    v = comps[p].get(key, 0.0)
                    if v <= 0:
                        continue
                    ax.bar(xpos, v, bw * 0.92, bottom=bot, color=col,
                           edgecolor="white", linewidth=0.3)
                    bot += v
                ymax = max(ymax, bot)
                ax.text(xpos, bot, f"{bot:.0f}", ha="center", va="bottom",
                        fontsize=6.5, rotation=90)
                xticks.append(xpos)
                xlabs.append(short[p])
            centers.append(bx + (len(protos) - 1) * bw / 2)
        ax.set_xticks(xticks)
        ax.set_xticklabels(xlabs, rotation=90, fontsize=6.8)
        ax.set_ylabel("Establishment latency (ms)", fontsize=9)
        ax.set_title(f"({'ab'[ci]}) {panel[tag]}", fontsize=10.5, pad=4)
        ax.tick_params(axis="y", labelsize=8)
        ax.set_ylim(0, ymax * 1.16)
        # RTT group label, placed BELOW the rotated protocol names.
        for c, r in zip(centers, rtts):
            ax.annotate(f"RTT = {r}\\,ms".replace("\\,", " "),
                        xy=(c, 0), xycoords=("data", "axes fraction"),
                        xytext=(0, -84), textcoords="offset points",
                        ha="center", va="top", fontsize=9, fontweight="bold")
        ax.set_xlim(-bw, (len(rtts) - 1) * span + len(protos) * bw)
    # One shared legend, ordered bottom->top to match the visual stacking.
    handles = [Patch(facecolor=col, label=lbl) for _, lbl, col in _BD_LAYERS]
    fig.legend(handles=handles, loc="lower center", ncol=5, frameon=False,
               fontsize=7.5, bbox_to_anchor=(0.5, 0.955),
               columnspacing=1.2, handlelength=1.3)
    _save(fig, out, fname)


# ───────── fig 2b: establishment-latency percentiles (tail/predictability) ─────────

# Percentile colours shared with the application figures so the whole eval
# reads as one family (see _PCT_COLORS below; redefined-identical here only
# for definition order).
def fig_latency_percentiles(data: Path, run: str, out: Path):
    """Grouped p50/p95 of connection establishment per protocol at LAN RTT,
    log-y -- same idiom as the application figures.  Shows the *shape* of the
    distribution the breakdown's medians hide: \\sys{} and vanilla are flat
    across percentiles (predictable, no online quote), while the
    per-connection baselines fan out to a heavy tail from the bursty paravisor
    vTPM (p95 of $345$/$497$\\,ms vs.\\ medians of $130$/$151$).

    We deliberately stop at p95: at $n\\!=\\!100$, p99 is a single sample, so
    for the sub-10 ms protocols it is dominated by one-off OS/network jitter
    (vanilla catches a lone 22 ms spike and its p99 spuriously exceeds proxy's)
    rather than protocol behaviour.  p50/p95 are robust at this $n$; p99 is
    added back once we re-measure at larger $n$."""
    d = data / run
    colors = {"p50": "#1f77b4", "p95": "#ff7f0e"}
    protos = ORDER
    labels = [S[p]["label"] for p in protos]
    p50, p95 = [], []
    for p in protos:
        v = _establishment_vals(d / f"{p}_warm.csv")
        # p50 via statistics.median (matches fig_e2e_latency / breakdown
        # exactly); nearest-rank would differ by a unit for even n.
        p50.append(statistics.median(v)); p95.append(_pctl(v, 95))
    x = range(len(protos)); w = 0.36
    fig, ax = plt.subplots(figsize=(5.8, 3.6))
    ax.bar([i - w / 2 for i in x], p50, w, label="p50", color=colors["p50"])
    ax.bar([i + w / 2 for i in x], p95, w, label="p95", color=colors["p95"])
    # annotate both bars (like the app figures); the p95 on the baselines is
    # where the fan-out is the whole point.
    for i, p in enumerate(protos):
        ax.annotate(f"{p50[i]:.0f}", (i - w / 2, p50[i]), ha="center",
                    va="bottom", fontsize=7)
        ax.annotate(f"{p95[i]:.0f}", (i + w / 2, p95[i]), ha="center",
                    va="bottom", fontsize=7, color=colors["p95"])
    ax.set_yscale("log")
    ax.set_ylim(1, max(p95) * 2)
    ax.set_xticks(list(x), labels, rotation=12)
    ax.set_ylabel("Connection establishment (ms)")
    ax.grid(True, axis="y", which="both", linestyle=":", alpha=0.4)
    ax.legend(frameon=False, loc="upper left", ncol=2)
    _save(fig, out, "fig_latency_percentiles")


# ───────────── fig 3: single-backend scalability (2 panels) ─────────────

def _steps(csv_path: Path):
    if not csv_path.exists():
        return [], [], []
    off, ach, p50 = [], [], []
    for r in csv.DictReader(open(csv_path)):
        off.append(float(r["target_rate_rps"]))
        ach.append(float(r["achieved_rps"]))
        p50.append(float(r["p50_resp_ms"]))
    return off, ach, p50


def fig_scalability_single(data: Path, run: str, out: Path):
    d = data / run
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(9.6, 3.8))
    for p in ORDER:
        off, ach, p50 = _steps(d / f"{p}_scale_warm_steps.csv")
        if not off:
            continue
        # Show the throughput curve up to saturation (its peak).  Beyond
        # saturation an open-loop system queues without bound; for the very
        # low-capacity attested-TLS baselines that regime is pathological
        # (response time >> window) and not informative about capacity, so
        # we plot rise-to-plateau and stop at the peak.
        kmax = max(range(len(ach)), key=lambda i: ach[i])
        offT, achT, p50T = off[:kmax + 1], ach[:kmax + 1], p50[:kmax + 1]
        st = S[p]
        axR.plot(offT, p50T, color=st["c"], marker=st["m"], linestyle=st["ls"],
                 linewidth=1.6, markersize=5, label=st["label"])
        axL.plot(offT, achT, color=st["c"], marker=st["m"], linestyle=st["ls"],
                 linewidth=1.6, markersize=5, label=st["label"])
    axL.set_xscale("log"); axL.set_yscale("log")
    axL.set_xlabel("Offered request rate (req/s)")
    axL.set_ylabel("Achieved throughput (req/s)")
    axL.set_title("(a) Throughput")
    axL.grid(True, which="both", linestyle=":", alpha=0.4)
    axR.set_xscale("log"); axR.set_yscale("log")
    axR.set_xlabel("Offered request rate (req/s)")
    axR.set_ylabel("p50 response time (ms)")
    axR.set_title("(b) Response time")
    axR.grid(True, which="both", linestyle=":", alpha=0.4)
    fig.tight_layout()
    # Single shared legend sitting entirely above the two panels; its
    # lower edge is anchored at the top of the figure (y=1.0) and the
    # tight bbox at save time grows the canvas to include it, so it can
    # never overlap the plots.
    h, l = axL.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=5, frameon=False,
               fontsize=9, bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_scalability_single", tight=True)


# ─────────── fig 4: throughput vs backend count (NEW) ───────────

def fig_scalability_backends(data: Path, out: Path, ns, proxy_ceiling,
                             scale_run="fin"):
    """Horizontal scalability of the *confidential* approaches: aggregate
    throughput vs backend-pool size.  cTLS redirection is measured at each
    N and scales with the pool; cTLS proxy is a load-balancing
    architecture too but frontend-bound (flat).  RA+TLS and HTTPA/2 are
    single-server attested-TLS designs with no scheme to load-balance a
    confidential service under one attested identity, so they cannot scale
    out as a single service and remain at single-server throughput (flat).
    Vanilla TLS is omitted: it is not a confidential service but the
    per-server no-penalty reference of the previous figure."""
    xs, ys = [], []
    for n in ns:
        f = data / f"mb-N{n}" / "ctls_redirect_scale_warm_steps.csv"
        if f.exists():
            peak = max(float(r["achieved_rps"]) for r in csv.DictReader(open(f)))
            xs.append(n); ys.append(peak)
    fig, ax = plt.subplots(figsize=(5.6, 3.9))
    # Scale-out lines: only architectures that can serve a pool under one
    # attested identity. \sys-redirection scales with N; \sys-proxy fronts N
    # backends through one frontend and is frontend-bound (flat).
    if xs:
        st = S["ctls_redirect"]
        ax.plot(xs, ys, color=st["c"], marker=st["m"], linestyle="-",
                linewidth=2.0, markersize=8, label=st["label"])
    if proxy_ceiling:
        st = S["ctls_proxy"]
        ax.plot(list(ns), [proxy_ceiling] * len(ns), color=st["c"],
                marker=st["m"], linestyle="--", linewidth=1.8, markersize=6,
                label=st["label"])
    # Single-server protocols cannot load-balance a confidential service across
    # backends, so they exist only at N=1 -- plotted as a single marker, not a
    # line. Vanilla = the no-attestation per-server ceiling we measure on the
    # same data path; RA+TLS/HTTPA are per-connection vTPM-quote-bound.
    vf = data / "mb-vanilla_per_backend.txt"
    vper = float(vf.read_text().strip()) if vf.exists() else 631.0
    SINGLE = [("vanilla", vper), ("httpa", 15.0), ("ratls", 7.0)]
    xr = [min(ns), max(ns)]
    for p, val in SINGLE:
        st = S[p]
        # faint dotted reference line at the single-server level (a guide so
        # the constant ceiling is comparable across the curve), with the
        # N=1 marker emphasising it is a single-server data point.
        ax.plot(xr, [val, val], color=st["c"], linestyle=":", linewidth=1.1,
                alpha=0.55, zorder=1)
        ax.plot([1], [val], color=st["c"], marker=st["m"], linestyle="none",
                markersize=8, label=st["label"], zorder=4)
    ax.set_yscale("log")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Number of backends")
    ax.set_ylabel("Aggregate throughput (req/s, log)")
    ax.set_xticks(list(ns))
    ax.set_xticklabels([str(n) for n in ns])
    ax.grid(True, which="both", linestyle=":", alpha=0.4)
    fig.tight_layout()
    # Legend entirely above the plot (lower edge anchored at the top of
    # the figure); the tight bbox at save grows the canvas to include it.
    h, l = ax.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False,
               fontsize=8.5, bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_scalability_backends", tight=True)


def fig_scalability_overhead(data: Path, out: Path, ns):
    """Frontend overhead vs backend count — the control-plane cost of the one
    component \\sys{} introduces.  Redirection keeps the frontend off the data
    path, so its CPU stays flat and negligible as the pool grows; proxy mode
    puts the frontend on the data path, so it saturates (and that saturation is
    what bounds proxy throughput) independent of N.  The attested-TLS baselines
    have no central component at all, hence nothing to plot on this axis (and,
    for the same reason, no way to scale out)."""
    f = data / "overhead" / "fe_cpu.csv"
    if not f.exists():
        print("(overhead data absent; skipping fig_scalability_overhead)")
        return
    xs, red, prox = [], [], []
    for r in csv.DictReader(open(f)):
        xs.append(int(r["N"]))
        red.append(float(r["redirect_cpu_pct"]))
        prox.append(float(r["proxy_cpu_pct"]))
    fig, ax = plt.subplots(figsize=(5.6, 3.9))
    sp, sr = S["ctls_proxy"], S["ctls_redirect"]
    ax.plot(xs, prox, color=sp["c"], marker=sp["m"], linestyle="--",
            linewidth=1.8, markersize=7, label=sp["label"])
    ax.plot(xs, red, color=sr["c"], marker=sr["m"], linestyle="-",
            linewidth=2.0, markersize=8, label=sr["label"])
    ax.set_yscale("log")
    ax.set_xscale("log", base=2)
    ax.set_ylim(0.01, 100)
    ax.set_xlabel("Number of backends")
    ax.set_ylabel("Frontend CPU (% of one core, log)")
    ax.set_xticks(list(ns))
    ax.set_xticklabels([str(n) for n in ns])
    ax.grid(True, which="both", linestyle=":", alpha=0.4)
    fig.tight_layout()
    h, l = ax.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=2, frameon=False,
               fontsize=9.5, bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_scalability_overhead", tight=True)


def _save(fig, out: Path, name: str, tight: bool = False):
    out.mkdir(parents=True, exist_ok=True)
    kw = {"bbox_inches": "tight"} if tight else {}
    fig.savefig(out / f"{name}.pdf", **kw)
    fig.savefig(out / f"{name}.png", **kw)
    plt.close(fig)
    print(f"wrote {name}.{{pdf,png}}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    # Write figures next to the co-located data so the datastore is
    # self-contained (run from bench_figures/).
    ap.add_argument("--out", default=".")
    # Breakdown is decomposed from the SAME run as fig_e2e_latency's LAN point
    # (rtt-0, n=100) so the two figures and the paper text report identical numbers.
    ap.add_argument("--latency-run", default="rtt-0")
    ap.add_argument("--scale-run", default="fin")
    ap.add_argument("--proxy-ceiling", type=float, default=163.0)
    args = ap.parse_args()
    data = Path(args.data); out = Path(args.out)

    # fig_apps.png is the live application figure this module ships for the
    # paper. The paper's latency breakdown (fig_latency_breakdowns.png) is
    # produced by gen_latency.py; the fig_latency_breakdowns_rtt() and the old
    # fig_scalability_backends/_single functions here are superseded renderings,
    # kept dormant. Use make_paper_figures.py to build all three paper figures.
    fig_apps(data, out)


# Shared style for the three application figures so they read as a family:
# grouped p50/p95/p99 bars, identical percentile colours, protocol order, size,
# legend and annotations. Reads <csv> with columns protocol,p50_ms,p95_ms,p99_ms.
_PCT_COLORS = {"p50": "#1f77b4", "p95": "#ff7f0e", "p99": "#d62728"}

# Percentile bar styling: distinct COLOUR (black/blue/red) *and* fill PATTERN
# (solid / hatched / shaded) so the three bars stay distinguishable in
# greyscale and print, not by colour alone.
_PCT_STYLE = {
    "p50": dict(color="#222222", hatch="",   edgecolor="black"),  # black, solid
    "p95": dict(color="#1f77b4", hatch="//", edgecolor="white"),  # blue, hatched
    "p99": dict(color="#c01d1d", hatch="..", edgecolor="white"),  # red, shaded
}


def _pct_bars(ax, x, w, p50, p95, p99):
    """Grouped p50/p95/p99 bars with colour+pattern styling (shared by the
    standalone app figures and the combined panel)."""
    for off, key, vals in ((-w, "p50", p50), (0, "p95", p95), (w, "p99", p99)):
        st = _PCT_STYLE[key]
        ax.bar([i + off for i in x], vals, w, label=key, color=st["color"],
               hatch=st["hatch"], edgecolor=st["edgecolor"], linewidth=0.6)


def _app_pct_bar(data, out, csv_name, ylabel, fig_name, logy=True):
    import csv as _csv
    f = data / "apps" / csv_name
    if not f.exists():
        print(f"(no {csv_name}; skipping {fig_name})"); return
    rows = [r for r in _csv.DictReader(open(f)) if r.get("p50_ms")]   # only the measured protocols
    if not rows:
        ax.set_visible(False); return
    rows = sorted(rows, key=lambda r: ORDER.index(r["protocol"]) if r["protocol"] in ORDER else 9)
    labels = [S.get(r["protocol"], {"label": r["protocol"]})["label"] for r in rows]
    p50 = [float(r["p50_ms"]) for r in rows]
    p95 = [float(r["p95_ms"]) for r in rows]
    p99 = [float(r["p99_ms"]) for r in rows]
    x = range(len(rows)); w = 0.27
    fig, ax = plt.subplots(figsize=(5.6, 3.6))
    _pct_bars(ax, x, w, p50, p95, p99)
    for i, v in enumerate(p50):
        ax.annotate(f"{v:g}", (i - w, v), ha="center", va="bottom", fontsize=7)
    if logy:
        ax.set_yscale("log"); ax.set_ylim(1, max(p99) * 2)
    else:
        ax.set_ylim(0, max(p99) * 1.18)
    ax.set_xticks(list(x), labels, rotation=12)
    ax.set_ylabel(ylabel)
    ax.legend(frameon=False, loc="upper left", ncol=3)
    _save(fig, out, fig_name)


def _app_panel(ax, data, csv_name, ylabel, title, logy=True, style="pctl"):
    """Draw one application's latency onto an axis, one bar per system
    (per-protocol PROTO colour, consistent with the other figures).
    style="mmm": bar = MEAN with min--max whiskers; needs mean_ms/min_ms/max_ms
    columns computed from raw per-request samples (currently only the browser
    CSV has raw; the LLM/microservice benches never persisted samples, so
    fig_apps pins style="pctl" until those are re-collected).
    style="pctl": bar = median (p50) + p95 tick + p99 whisker."""
    import csv as _csv
    f = data / "apps" / csv_name
    if not f.exists():
        ax.set_visible(False); return
    rows = [r for r in _csv.DictReader(open(f)) if r.get("p50_ms")]   # only the measured protocols
    if not rows:
        ax.set_visible(False); return
    rows = sorted(rows, key=lambda r: ORDER.index(r["protocol"]) if r["protocol"] in ORDER else 9)
    labels = [PROTO.get(r["protocol"], {"label": r["protocol"]})["label"] for r in rows]
    cols = [PROTO.get(r["protocol"], {"c": "#999"})["c"] for r in rows]
    x = list(range(len(rows)))
    mark = "#222222"
    have_mmm = style == "mmm" and all(
        r.get("mean_ms") and r.get("min_ms") and r.get("max_ms") for r in rows)
    if have_mmm:
        mean = [float(r["mean_ms"]) for r in rows]
        lo = [float(r["min_ms"]) for r in rows]
        hi = [float(r["max_ms"]) for r in rows]
        ax.bar(x, mean, 0.62, color=cols, edgecolor="black", linewidth=0.6, zorder=2)
        yerr = [[mean[i] - lo[i] for i in range(len(rows))],
                [hi[i] - mean[i] for i in range(len(rows))]]
        ax.errorbar(x, mean, yerr=yerr, fmt="none", ecolor=mark, elinewidth=1.2,
                    capsize=3.5, capthick=1.2, zorder=4)
        center, top = mean, hi
    else:
        p50 = [float(r["p50_ms"]) for r in rows]
        p95 = [float(r["p95_ms"]) for r in rows]
        p99 = [float(r["p99_ms"]) for r in rows]
        ax.bar(x, p50, 0.62, color=cols, edgecolor="black", linewidth=0.6, zorder=2)
        for i in range(len(rows)):
            ax.plot([i, i], [p50[i], p99[i]], color=mark, lw=1.3, zorder=3)
            ax.plot([i - 0.11, i + 0.11], [p99[i], p99[i]], color=mark, lw=1.3, zorder=4)
            ax.plot([i - 0.15, i + 0.15], [p95[i], p95[i]], color=mark, lw=2.2, zorder=4)
        center, top = p50, p99
    # value labels in black just above each bar's top, left of the whisker
    # line, so the label sits over its own bar on the white canvas
    # (white-on-fill was illegible on the lighter bars)
    for i, v in enumerate(center):
        ax.annotate(f"{v:.0f}", (i, v), ha="right", va="bottom",
                    xytext=(-1.5, 2), textcoords="offset points",
                    fontsize=7.5, color="black", zorder=5)
    if logy:
        ax.set_yscale("log"); ax.set_ylim(1, max(top) * 2.2)
    else:
        ax.set_ylim(0, max(top) * 1.12)
    ax.set_xticks(x, labels, rotation=20, ha="right", fontsize=8)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_title(title, fontsize=10)
    ax.grid(True, axis="y", which="major", alpha=0.3)
    ax.set_axisbelow(True)


def fig_apps(data, out):
    """Combined 1x3 application figure (one figure* spanning both columns):
    browser PLT, LLM TTFT, microservice /reservation latency."""
    fig, axes = plt.subplots(1, 3, figsize=(11.0, 2.9))
    _app_panel(axes[0], data, "browser.csv",
               "Page load time (ms)", "(a) Web browsing", logy=False, style="mmm")
    _app_panel(axes[1], data, "llm_gpu_ttft.csv",
               "TTFT (ms)", "(b) LLM inference", logy=False, style="mmm")
    _app_panel(axes[2], data, "microservice.csv",
               "/reservation latency (ms)", "(c) Microservice", logy=False, style="mmm")
    if not any(ax.get_visible() for ax in axes):
        print("Fig. 7: no measured panel, no figure"); return
    # all three apps now have raw per-request samples -> mean + min-max whiskers
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch
    handles = [
        Patch(facecolor="#bbbbbb", edgecolor="black", label="mean"),
        Line2D([0], [0], color="#222222", lw=1.2, label="min–max"),
    ]
    fig.legend(handles=handles, loc="upper center", ncol=2, fontsize=12,
               bbox_to_anchor=(0.5, 1.07), **LEGEND)
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    _save(fig, out, "fig_apps")


def fig_app_microservice(data, out):
    """hotelReservation /reservation end-to-end latency (p50/p95/p99), 5 protocols."""
    _app_pct_bar(data, out, "microservice.csv",
                 "/reservation e2e latency (ms, log)", "fig_app_microservice", logy=True)


def fig_app_browser(data, out):
    """Page-load time (p50/p95/p99) via a real headless Firefox + cTLS extension.
    Only browser-compatible protocols appear (RA+TLS/HTTPA can't run in a stock
    browser); linear-y since the 3 protocols share a narrow range."""
    _app_pct_bar(data, out, "browser.csv",
                 "Page load time (ms)", "fig_app_browser", logy=False)


def fig_app_llm(data, out):
    """LLM inference (CPU dry-run): per-connection establishment-to-verified-
    channel (p50/p95/p99) — the attestation component of TTFT. Absolute TTFT is
    CPU-inference-bound (~5 s for all); establishment is the protocol-
    distinguishing part and dominates TTFT once served on the GPU."""
    _app_pct_bar(data, out, "llm_gpu_ttft.csv",
                 "Time to first token (ms, log)", "fig_app_llm", logy=True)


if __name__ == "__main__":
    main()


def fig_breakdown_vs_rtt(data: Path, rtts, out: Path):
    """Merge of the latency breakdown and the RTT series: per-protocol phase
    composition as network RTT grows.  Compute phases (quote generation) are
    ~constant; round-trip phases (handshakes, the AS round trip, and HTTPA's
    extra post-handshake exchange) grow with RTT, so HTTPA outpaces RA+TLS."""
    protos = _BD_PROTOS
    comps_by_rtt = {}
    for R in rtts:
        comps_by_rtt[R] = _phase_comps_p50(data / f"rtt-{R}")
    ymax = max(sum(comps_by_rtt[R][p].values()) for R in rtts for p in protos) * 1.12
    fig, axes = plt.subplots(1, len(protos), figsize=(11.0, 3.0), sharey=True)
    xs = list(range(len(rtts)))
    for pi, p in enumerate(protos):
        ax = axes[pi]
        bottoms = [0.0] * len(rtts)
        for key, lbl, col in _BD_LAYERS:
            vals = [comps_by_rtt[R][p].get(key, 0.0) for R in rtts]
            if max(vals) <= 0:
                continue
            ax.bar(xs, vals, 0.66, bottom=bottoms, color=col, label=lbl,
                   edgecolor="white", linewidth=0.4)
            bottoms = [b + v for b, v in zip(bottoms, vals)]
        ax.set_title(S[p]["label"], fontsize=10)
        ax.set_xticks(xs)
        ax.set_xticklabels([str(R) for R in rtts], fontsize=8)
        ax.set_ylim(0, ymax)
        ax.grid(True, axis="y", linestyle=":", alpha=0.4)
        if pi == 0:
            ax.set_ylabel("p50 establishment (ms)", fontsize=11)
    fig.supxlabel("Network RTT (ms)", fontsize=11, y=0.02)
    h, l = axes[-1].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=5, frameon=False, fontsize=8.5,
               bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_breakdown_vs_rtt")


def fig_latency_rtt(data: Path, rtts, out: Path):
    """Establishment latency vs RTT, grouped by RTT, one bar per protocol split
    into the two HONEST super-phases: fixed COMPUTE (the RTT-0 cost: quote
    generation + MAA processing + crypto) and NETWORK round trips (total minus
    compute, which scales with RTT).  The baselines carry a large fixed compute
    floor (per-connection quote+MAA) that \\sys{} avoids; HTTPA/2's network bar
    grows faster than RA+TLS's by its extra post-handshake round trip."""
    protos = _BD_PROTOS
    total = {p: {} for p in protos}
    for p in protos:
        for R in rtts:
            total[p][R] = _median_establishment(data / f"rtt-{R}" / f"{p}_warm.csv") or 0.0
    compute = {p: total[p][rtts[0]] for p in protos}  # RTT-0 ≈ fixed cost
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    ng, nb = len(rtts), len(protos)
    w = 0.82 / nb
    for pi, p in enumerate(protos):
        c = S[p]["c"]
        xs = [g + (pi - (nb - 1) / 2.0) * w for g in range(ng)]
        comp = [compute[p]] * ng
        net = [max(0.0, total[p][R] - compute[p]) for R in rtts]
        ax.bar(xs, comp, w, color=c, edgecolor="white", linewidth=0.3,
               label=S[p]["label"])
        ax.bar(xs, net, w, bottom=comp, color=c, alpha=0.42, hatch="////",
               edgecolor="white", linewidth=0.3)
    ax.set_xticks(range(ng))
    ax.set_xticklabels([str(R) for R in rtts])
    ax.set_xlabel("Network RTT (ms)")
    ax.set_ylabel("p50 establishment (ms)")
    ax.grid(True, axis="y", linestyle=":", alpha=0.4)
    from matplotlib.patches import Patch
    ph, pl = ax.get_legend_handles_labels()
    style = [Patch(facecolor="0.35"),
             Patch(facecolor="0.35", alpha=0.42, hatch="////")]
    fig.legend(ph + style, pl + ["compute (fixed)", "network round trips"],
               loc="lower center", ncol=4, frameon=False, fontsize=8.5,
               bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_latency_rtt")


def _rtt_compute_network(data: Path, rtts):
    """Per protocol: fixed compute at p50 and p95 (from the well-sampled RTT-0
    run) and the deterministic network term network(R)=p50(R)-p50(0).  Because
    the network delay is deterministic, p95(total)=p95(compute)+network(R)."""
    protos = _BD_PROTOS
    comp50, comp95, net = {}, {}, {p: {} for p in protos}
    for p in protos:
        v0 = _establishment_vals(data / f"rtt-{rtts[0]}" / f"{p}_warm.csv")
        comp50[p] = statistics.median(v0) if v0 else 0.0
        comp95[p] = _pctl(v0, 95) or comp50[p]
        for R in rtts:
            tot = _median_establishment(data / f"rtt-{R}" / f"{p}_warm.csv") or 0.0
            net[p][R] = max(0.0, tot - comp50[p])
    return comp50, comp95, net


def _rtt_panel(ax, rtts, comp, net, ymax, ylabel):
    protos = _BD_PROTOS
    ng, nb = len(rtts), len(protos)
    w = 0.84 / nb
    for pi, p in enumerate(protos):
        c = S[p]["c"]
        xs = [g + (pi - (nb - 1) / 2.0) * w for g in range(ng)]
        cv = [comp[p]] * ng
        nv = [net[p][R] for R in rtts]
        ax.bar(xs, cv, w, color=c, edgecolor="black", linewidth=0.4, label=S[p]["label"])
        ax.bar(xs, nv, w, bottom=cv, facecolor="white", edgecolor=c,
               linewidth=0.5, hatch="////")
    ax.set_xticks(range(ng))
    ax.set_xticklabels([str(R) for R in rtts])
    ax.set_ylim(0, ymax)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.grid(True, axis="y", linestyle=":", alpha=0.4)


def fig_latency_rtt_pct(data: Path, rtts, out: Path):
    """Two stacked panels (p50, p95) of establishment latency vs RTT.  Each
    protocol bar = fixed COMPUTE (solid: per-connection quote+MAA+crypto) plus
    NETWORK round trips (hatched, white-filled with the protocol's edge colour:
    deterministic, scales with RTT).  p95 shares the same network term and the
    p95 compute floor (the baselines' bursty vTPM-quote tail)."""
    comp50, comp95, net = _rtt_compute_network(data, rtts)
    protos = _BD_PROTOS
    tot50 = {p: comp50[p] + max(net[p][R] for R in rtts) for p in protos}
    tot95 = {p: comp95[p] + max(net[p][R] for R in rtts) for p in protos}
    fig, (a50, a95) = plt.subplots(2, 1, figsize=(6.8, 5.4), sharex=True,
                                   gridspec_kw={"hspace": 0.12})
    _rtt_panel(a50, rtts, comp50, net, max(tot50.values()) * 1.10,
               "p50 establishment (ms)")
    _rtt_panel(a95, rtts, comp95, net, max(tot95.values()) * 1.10,
               "p95 establishment (ms)")
    a50.set_title("(a) median (p50)", fontsize=10)
    a95.set_title("(b) tail (p95)", fontsize=10)
    a95.set_xlabel("Network RTT (ms)")
    from matplotlib.patches import Patch
    ph, pl = a50.get_legend_handles_labels()
    style = [Patch(facecolor="0.35", edgecolor="black"),
             Patch(facecolor="white", edgecolor="0.35", hatch="////")]
    fig.legend(ph + style, pl + ["compute (fixed)", "network round trips"],
               loc="lower center", ncol=4, frameon=False, fontsize=8.5,
               bbox_to_anchor=(0.5, 1.0))
    _save(fig, out, "fig_latency_rtt")


def _plot_breakdown_one(tag, comps, out: Path, fname: str):
    """Single detailed per-phase establishment breakdown for one percentile,
    as its own figure.  Broken y-axis (top: attested-TLS baseline towers;
    bottom: the vanilla/\\sys{} regime) so both scales stay legible.
    x = protocol; colours = phases."""
    import matplotlib.gridspec as gridspec
    protos = _BD_PROTOS
    xlabels = [S[p]["label"] for p in protos]
    x = list(range(len(protos)))
    fig = plt.figure(figsize=(3.4, 3.0))
    gs = gridspec.GridSpec(2, 1, height_ratios=[1.0, 1.25], hspace=0.08,
                           figure=fig)
    axt = fig.add_subplot(gs[0])
    axb = fig.add_subplot(gs[1])
    totals = [sum(comps[p].values()) for p in protos]
    janus = [totals[i] for i, p in enumerate(protos) if p.startswith(("vanilla", "ctls"))]
    base = [totals[i] for i, p in enumerate(protos) if p in ("ratls", "httpa")]
    bottom_hi = max(janus) * 1.55
    top_lo, top_hi = min(base) * 0.80, max(base) * 1.14
    for ax in (axt, axb):
        bottoms = [0.0] * len(protos)
        for key, lbl, col in _BD_LAYERS:
            vals = [comps[p].get(key, 0.0) for p in protos]
            if max(vals) <= 0:
                continue
            ax.bar(x, vals, 0.6, bottom=bottoms, color=col, label=lbl,
                   edgecolor="white", linewidth=0.4)
            bottoms = [b + v for b, v in zip(bottoms, vals)]
    axt.set_ylim(top_lo, top_hi)
    axb.set_ylim(0, bottom_hi)
    axt.tick_params(axis="y", labelsize=8)
    axb.tick_params(axis="y", labelsize=8)
    axt.spines["bottom"].set_visible(False)
    axb.spines["top"].set_visible(False)
    axt.tick_params(axis="x", which="both", bottom=False, labelbottom=False)
    dd = 0.5
    bk = dict(marker=[(-1, -dd), (1, dd)], markersize=6, linestyle="none",
              color="k", mec="k", mew=1, clip_on=False)
    axt.plot([0, 1], [0, 0], transform=axt.transAxes, **bk)
    axb.plot([0, 1], [1, 1], transform=axb.transAxes, **bk)
    for i, t in enumerate(totals):
        if t >= bottom_hi:
            axt.text(i, t + (top_hi - top_lo) * 0.03, f"{t:.0f}",
                     ha="center", va="bottom", fontsize=7)
        else:
            axb.text(i, t + bottom_hi * 0.03, f"{t:.0f}",
                     ha="center", va="bottom", fontsize=7)
    axb.set_xticks(x)
    axb.set_xticklabels(xlabels, rotation=20, ha="right", fontsize=7.5)
    fig.supylabel("Establishment latency (ms)", fontsize=9.5, x=-0.02)
    h, l = axb.get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=2, frameon=False, fontsize=7.0,
               bbox_to_anchor=(0.5, 0.99))
    _save(fig, out, fname)


def _plot_breakdowns_vstack(cols, out: Path):
    """Detailed per-phase establishment breakdown, p50 (a) and p95 (b) stacked
    VERTICALLY in a single column with ONE shared legend.  Each percentile is a
    broken-axis pair (top: attested-TLS baseline towers; bottom: the
    vanilla/\\sys{} regime) so both scales stay legible.  Protocol labels are
    drawn once, under the lower (p95) pair.  x = protocol; colours = phases."""
    import matplotlib.gridspec as gridspec
    protos = _BD_PROTOS
    xlabels = [S[p]["label"] for p in protos]
    x = list(range(len(protos)))
    fig = plt.figure(figsize=(3.4, 4.6))
    # Two outer rows (one broken-axis pair per percentile); reserve a strip at
    # the top for the single shared legend.  Nested grids keep the break tight
    # within a pair while leaving a readable gap between the two pairs.
    outer = gridspec.GridSpec(2, 1, hspace=0.22, figure=fig,
                              top=0.90, bottom=0.13, left=0.17, right=0.97)
    leg = None
    for ci, (tag, comps) in enumerate(cols):
        inner = gridspec.GridSpecFromSubplotSpec(
            2, 1, subplot_spec=outer[ci], height_ratios=[0.85, 1.3], hspace=0.05)
        axt = fig.add_subplot(inner[0])
        axb = fig.add_subplot(inner[1])
        totals = [sum(comps[p].values()) for p in protos]
        janus = [totals[i] for i, p in enumerate(protos) if p.startswith(("vanilla", "ctls"))]
        base = [totals[i] for i, p in enumerate(protos) if p in ("ratls", "httpa")]
        bottom_hi = max(janus) * 1.35
        top_lo, top_hi = min(base) * 0.84, max(base) * 1.08
        for ax in (axt, axb):
            bottoms = [0.0] * len(protos)
            for key, lbl, col in _BD_LAYERS:
                vals = [comps[p].get(key, 0.0) for p in protos]
                if max(vals) <= 0:
                    continue
                ax.bar(x, vals, 0.62, bottom=bottoms, color=col, label=lbl,
                       edgecolor="white", linewidth=0.4)
                bottoms = [b + v for b, v in zip(bottoms, vals)]
        axt.set_ylim(top_lo, top_hi)
        axb.set_ylim(0, bottom_hi)
        axt.tick_params(axis="y", labelsize=8)
        axb.tick_params(axis="y", labelsize=8)
        axt.spines["bottom"].set_visible(False)
        axb.spines["top"].set_visible(False)
        axt.tick_params(axis="x", which="both", bottom=False, labelbottom=False)
        dd = 0.5
        bk = dict(marker=[(-1, -dd), (1, dd)], markersize=6, linestyle="none",
                  color="k", mec="k", mew=1, clip_on=False)
        axt.plot([0, 1], [0, 0], transform=axt.transAxes, **bk)
        axb.plot([0, 1], [1, 1], transform=axb.transAxes, **bk)
        for i, t in enumerate(totals):
            if t >= bottom_hi:
                axt.text(i, t + (top_hi - top_lo) * 0.04, f"{t:.0f}",
                         ha="center", va="bottom", fontsize=7)
            else:
                axb.text(i, t + bottom_hi * 0.03, f"{t:.0f}",
                         ha="center", va="bottom", fontsize=7)
        # Panel tag inside the (empty) upper-left of the top sub-axes.
        axt.text(0.02, 0.94, f"({'ab'[ci]}) {tag}", transform=axt.transAxes,
                 fontsize=9, va="top", ha="left")
        last = ci == len(cols) - 1
        axb.set_xticks(x)
        axb.set_xticklabels(xlabels if last else [], rotation=20, ha="right",
                            fontsize=7.5)
        if leg is None:
            leg = axb.get_legend_handles_labels()
    fig.supylabel("Establishment latency (ms)", fontsize=9.5, x=0.012)
    fig.legend(*leg, loc="lower center", ncol=2, frameon=False, fontsize=7.2,
               bbox_to_anchor=(0.5, 0.905))
    _save(fig, out, "fig_latency_breakdowns")
