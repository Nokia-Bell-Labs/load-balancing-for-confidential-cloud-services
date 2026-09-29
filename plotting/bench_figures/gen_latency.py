#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Connection-establishment latency: phase breakdown at EACH network RTT.

One compact panel: the five protocols grouped at every injected RTT (LAN ->
160 ms), each bar a stacked phase breakdown whose TOTAL height is the measured
p95 establishment. A single linear y is legible here because the baselines'
bursty per-connection vTPM quote keeps every bar large at every RTT (unlike p50,
where the LAN group would collapse). The per-phase split is the median
composition with the measured p95-vs-median growth attributed to the bursty phase
(the quote for the baselines, the handshake otherwise), so each stack sums to the
real p95 -- tails do not co-occur across phases, so we do not stack per-phase
percentiles.

  tls   TCP + TLS-1.3 handshake (control)              maa  attestation service (MAA)
  tls2  backend TLS + DC handshake (redirection)       quote server hardware quote
  route frontend routing leg (redirection)             validate client-side check
"""
import csv
import os
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.transforms import blended_transform_factory

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)                       # paper_figures
sys.path.insert(0, os.path.dirname(HERE))      # janus_style
import paper_figures as pf
from janus_style import apply, PHASE, save, LEGEND, LEGEND_FS
apply()

DATA = os.path.join(HERE, "data")
RTTS = [0, 20, 40, 80, 120, 160]
PROTOS = ["vanilla", "ctls_proxy", "ctls_redirect", "ratls", "httpa"]
SHORT = {"vanilla": "TLS", "ctls_proxy": "JP", "ctls_redirect": "JR",
         "ratls": "RA", "httpa": "HA"}
BASELINES = {"ratls", "httpa"}        # attested-TLS baselines -> red bar codes
BURSTY = {"vanilla": "tls", "ctls_proxy": "tls", "ctls_redirect": "tls",
          "ratls": "quote", "httpa": "quote"}
PCTL = 95   # the percentile whose total each bar reaches

# Stacked bottom-to-top (and listed in the legend) in the order the phases
# actually happen on a connection: control handshake -> client-side validation
# (proxy) / frontend redirect (redirection) -> backend TLS+DC handshake;
# the baselines' quote is generated mid-handshake, then verified at the AS.
LAYERS = [("tls",      "TCP + TLS 1.3 handshake",    PHASE["tls"]),
          ("validate", "Client-side validation",     PHASE["validate"]),
          ("route",    "Frontend redirect",          PHASE["route"]),
          ("tls2",     "Backend TLS + DC handshake", PHASE["tls2"]),
          ("quote",    "Server quote generation",    PHASE["quote"]),
          ("maa",      "Attestation service (MAA)",  PHASE["maa"])]


def med(path, col):
    if not os.path.exists(path):
        return 0.0
    v = [float(r.get(col, 0) or 0) for r in csv.DictReader(open(path))
         if int(r.get("ok", 1) or 1) == 1]
    return statistics.median(v) if v else 0.0


def quote_constants():
    d0 = os.path.join(DATA, "rtt-0")
    van = med(os.path.join(d0, "vanilla_warm.csv"), "tcp_ms") + \
        med(os.path.join(d0, "vanilla_warm.csv"), "tls_ms")
    q_ratls = max(0.0, med(os.path.join(d0, "ratls_warm.csv"), "tcp_ms")
                  + med(os.path.join(d0, "ratls_warm.csv"), "tls_ms") - van)
    q_httpa = med(os.path.join(d0, "httpa_warm_breakdown.csv"), "bundle_rtt_ms")
    return q_ratls, q_httpa


Q_RATLS, Q_HTTPA = quote_constants()


# MAA verification is a per-connection *client->MAA* call over a pooled
# keep-alive session, so it legitimately GROWS with client RTT (~2x RTT, since a
# distant client is far from the attestation service too) -- we plot the real
# measured value, not a constant.  Quote generation is server-local -> flat (Q_*).
#
# Quote-generation burstiness is RTT-independent: the p90-vs-median tail
# growth measured once on the clean base-RTT run (no client RTT to confound it).
def _quote_burst(p):
    ev = pf._establishment_vals(Path(DATA) / "rtt-0" / f"{p}_warm.csv")
    return max(0.0, (pf._pctl(ev, 90) or 0.0) - (pf._pctl(ev, 50) or 0.0))


BURST = {"ratls": _quote_burst("ratls"), "httpa": _quote_burst("httpa")}


def median_comp(p, r):
    """Median per-phase composition (ms) for protocol p at RTT r."""
    d = os.path.join(DATA, f"rtt-{r}")
    def w(c): return med(os.path.join(d, f"{p}_warm.csv"), c)
    def bd(f, c): return med(os.path.join(d, f), c)
    if p == "vanilla":
        return {"tls": w("tcp_ms") + w("tls_ms")}
    if p == "ctls_proxy":
        return {"tls": w("tcp_ms") + w("tls_ms"), "validate": w("attest_ms")}
    if p == "ctls_redirect":
        return {"tls": w("tcp_ms") + w("tls_ms"), "route": w("attest_ms"),
                "tls2": w("extra_tcp_ms") + w("extra_tls_ms")}
    if p == "ratls":
        # RA+TLS verifies against MAA mid-handshake; attest_ms IS that
        # client->MAA verify (pooled, grows ~2x RTT).  Quote = handshake
        # inflation over vanilla (flat, server-local).
        return {"tls": max(0.0, w("tcp_ms") + w("tls_ms") - Q_RATLS),
                "quote": Q_RATLS, "maa": w("attest_ms")}
    # httpa: attest = bundle fetch (server quote gen + one client<->server
    # round trip) + MAA verify.  Split honestly: quote flat (Q_HTTPA), the
    # bundle's RTT-growth -> handshake band, MAA verify (client->MAA, pooled,
    # grows ~2x RTT) -> its own band.
    bundle = bd("httpa_warm_breakdown.csv", "bundle_rtt_ms")
    maa = bd("httpa_warm_breakdown.csv", "maa_verify_ms")
    return {"tls": w("tcp_ms") + w("tls_ms") + max(0.0, bundle - Q_HTTPA),
            "quote": Q_HTTPA, "maa": maa}


def stack_at(p, r, q):
    """Phase stack whose total == measured pq establishment.  For the baselines
    the RTT-independent quote burstiness (BURST) lands on the quote band as a
    constant; any remaining tail is network-round-trip variance and lands on the
    handshake band, so quote and MAA stay flat across RTTs."""
    comp = dict(median_comp(p, r))
    tmed = sum(comp.values())
    target = pf._pctl(pf._establishment_vals(
        Path(DATA) / f"rtt-{r}" / f"{p}_warm.csv"), q) or tmed
    growth = target - tmed
    if growth <= 0:
        if tmed > 0:
            comp = {k: v * target / tmed for k, v in comp.items()}
        return comp, target
    if p in BASELINES:
        burst = min(BURST[p], growth)        # RTT-independent quote burst
        comp["quote"] += burst
        comp["tls"] += growth - burst        # residual = network variance
    else:
        comp[BURSTY[p]] += growth
    return comp, target


JANUS = {"vanilla", "ctls_proxy", "ctls_redirect"}   # vanilla + \sys{} modes

# full approach names under each bar (rotated); no code legend needed
FULL = {"vanilla": "Vanilla TLS", "ctls_proxy": "Janus-proxy",
        "ctls_redirect": "Janus-redir.", "ratls": "RA+TLS",
        "httpa": "HTTPA/2"}
NAME_FS = 7.0   # per-bar full-name font (rotated to clear the tight bar pitch)


def panel(ax, q, title=None, rtts=None, rtt=True, rtt_y=-0.11):
    """One percentile panel: 5 approaches per RTT group, stacked by phase. Each
    bar carries its full approach name (rotated); the RTT value labels the
    group below the names."""
    rtts = RTTS if rtts is None else rtts
    bw, gap = 0.82, 1.4
    span = len(PROTOS) * bw + gap
    centers, ymax = [], 0.0
    bar_xs, bar_names = [], []
    for gi, r in enumerate(rtts):
        base = gi * span
        for pi, p in enumerate(PROTOS):
            xp = base + pi * bw
            if not os.path.exists(os.path.join(DATA, f"rtt-{r}", f"{p}_warm.csv")):
                continue   # not measured in this run
            comp, _ = stack_at(p, r, q)
            bottom = 0.0
            for key, _, col in LAYERS:
                v = comp.get(key, 0.0)
                if v <= 0:
                    continue
                ax.bar(xp, v, bw * 0.9, bottom=bottom, color=col,
                       edgecolor="white", linewidth=0.3)
                bottom += v
            ymax = max(ymax, bottom)
            bar_xs.append(xp); bar_names.append(FULL[p])
        centers.append(base + (len(PROTOS) - 1) * bw / 2)
    top = ymax * 1.1
    ax.set_ylim(0, top)
    ax.set_yticks(range(0, int(top) + 1, 200))
    ax.set_yticks(range(0, int(top) + 1, 100), minor=True)
    ax.grid(True, axis="y", which="major", linestyle="-", alpha=0.3)
    ax.grid(True, axis="y", which="minor", linestyle=":", alpha=0.2)
    ax.tick_params(axis="y", labelsize=8)
    # per-bar full name (rotated 90 deg so the names clear the tight bar pitch)
    ax.set_xticks(bar_xs)
    ax.tick_params(axis="x", length=0, pad=1.0)
    ax.set_xticklabels(bar_names, fontsize=NAME_FS, rotation=45, ha="right",
                       rotation_mode="anchor")
    if rtt:
        # RTT value as the group label, below the per-bar names
        tr = blended_transform_factory(ax.transData, ax.transAxes)
        for c, r in zip(centers, rtts):
            ax.text(c, rtt_y, str(r), transform=tr, ha="center", va="top", fontsize=8)
    ax.set_xlim(-bw, (len(rtts) - 1) * span + len(PROTOS) * bw)
    if title:
        ax.set_title(title, fontsize=9.5)


def main():
    # Single-COLUMN p50 panel: 5 approaches at RTT 0/40/80/120 ms (LAN +
    # intra-continental + transatlantic + transpacific; 20 dropped as redundant,
    # 160 measured but data-only), stacked by phase, full approach names rotated under
    # each bar and the RTT group label below them.  Phase legend on top; the
    # sub-ms client-side validation sliver stays in the stack but is omitted
    # from the legend (invisible at this scale -- the text carries it).
    rtts = [r for r in (0, 40, 80, 120) if os.path.isdir(os.path.join(DATA, f"rtt-{r}"))]
    if not rtts:
        print("Fig. 5: no measured RTT, no figure"); return
    fig, ax = plt.subplots(figsize=(3.6, 2.55))
    panel(ax, 50, rtts=rtts, rtt_y=-0.42)
    ax.set_ylabel("Median (p50) latency (ms)", fontsize=9)
    fig.subplots_adjust(left=0.15, right=0.99, top=0.80, bottom=0.315)
    fig.text(0.55, 0.012, "Network RTT (ms)", ha="center", fontsize=9)
    ph = [Patch(facecolor=c, label=l) for k, l, c in LAYERS if k != "validate"]
    fig.legend(handles=ph, loc="upper center", bbox_to_anchor=(0.52, 1.005),
               ncol=2, fontsize=7, frameon=False, handlelength=1.2,
               handletextpad=0.4, columnspacing=0.9, labelspacing=0.3,
               borderaxespad=0.05)
    save(fig, os.path.join(HERE, "fig_latency_breakdowns"))


if __name__ == "__main__":
    main()
