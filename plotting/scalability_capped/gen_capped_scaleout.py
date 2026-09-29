#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""fig:scale-backends (capped) — Janus-proxy vs Janus-redirection, sustained
throughput vs backend count N=1..32, with the single-server baseline points
(vanilla, RA+TLS, HTTPA) at N=1.  Representative per-request backend cost
c=10 req/s (CTLS_SERVICE_MS=100, CTLS_MAX_INFLIGHT=1) applied identically to
every backend.  Measured 2026-06-07.  Paper style (serif, Janus colours).

Both Janus modes scale with the pool while backend-bound; proxy then plateaus
at the single frontend's forwarding capacity C_fe~162, while redirection keeps
scaling linearly (frontend off the data path).  The baselines are single-server
(no load-balancing of a confidential service), so they exist only at N=1: under
the SAME backend cap, vanilla sits at the cap (no attestation), while RA+TLS and
HTTPA fall below it because every connection pays a fresh per-connection vTPM
quote that serialises on the paravisor.  Synthetic microbenchmark backend.
"""
import csv
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from janus_style import apply, PROTO, PCTL, PHASE, C_FE

apply()
C_PROXY, C_REDIR = PROTO["ctls_proxy"]["c"], PROTO["ctls_redirect"]["c"]   # match paper S dict
HERE = os.path.dirname(os.path.abspath(__file__))
# The presentation of the paper: logarithmic "Maximum sustained throughput" axis, single-server baselines as
# markers at N=1, the N=1 zoom-in inset at the bottom right.
STYLE = "paper"


def col(path, key):
    with open(os.path.join(HERE, path)) as f:
        return [row for row in csv.DictReader(f)]


def opt(path):
    return col(path, None) if os.path.exists(os.path.join(HERE, path)) else []

rows = [r for r in opt("capped_scaleout.csv") if r.get("proxy_rps") or r.get("redirect_rps")]   # only the measured pool sizes
if not rows:
    print("Fig. 6: no measured pool size, no figure"); sys.exit(0)
N        = [int(r["N"]) for r in rows]
proxy    = [float(r["proxy_rps"]) if r.get("proxy_rps") else float("nan") for r in rows]
redirect = [float(r["redirect_rps"]) if r.get("redirect_rps") else float("nan") for r in rows]
C_FE = 162

# Single-server baselines (N=1 only), same c=10 backend cap. Only the measured ones are drawn.
bl = {r["protocol"]: float(r["achieved_rps"]) for r in opt("capped_baselines_n1.csv") if r.get("achieved_rps")}
BASE = [(k, lab, bl[k], PROTO[k]["c"], mk) for k, lab, mk in (("vanilla", "Vanilla TLS", "o"), ("ratls", "RA+TLS", "D"), ("httpa", "HTTPA/2", "v")) if k in bl]

fig, ax = plt.subplots(figsize=(5.6, 3.9))
ax.plot(N, redirect, color=C_REDIR, marker="^", ls="-", lw=2.0, ms=8, label="Janus-redirection", zorder=5)
ax.plot(N, proxy,    color=C_PROXY, marker="s", ls="-", lw=2.0, ms=7, label="Janus-proxy", zorder=5)

# Single-server baseline points at N=1 (no scale-out).
for _, lab, y, c, mk in BASE:
    ax.plot([1], [y], marker=mk, ms=8, mfc=c, mec="black", mew=0.7,
            ls="none", label=lab, zorder=6)

ax.set_xscale("log", base=2)
ax.set_xticks(N); ax.set_xticklabels([str(n) for n in N])
ax.set_xlabel("Number of backends $N$")
if STYLE == "paper":
    ax.set_yscale("log")
    ax.set_ylabel("Maximum sustained\nthroughput (req/s)")
    ymax = max([v for v in proxy + redirect if v == v] + list(bl.values()) + [10.0]); ymin = min([v for v in proxy + redirect if v == v] + list(bl.values()) + [10.0])
    ax.set_ylim(min(4, ymin * 0.6), max(500, ymax * 1.4))
    if "httpa" in bl:
        ax.annotate("N=1", (1, bl["httpa"]), xytext=(1.25, bl["httpa"] * 0.72), fontsize=8.0, color="#333333", ha="left",
                    arrowprops=dict(arrowstyle="->", color="#333333", lw=0.8))
    ax.grid(True, which="major", axis="y", alpha=0.25)
    ax.legend(frameon=False, loc="upper left", ncol=1, handletextpad=0.4, labelspacing=0.3)
    # zoom-in on the single-server (N=1) throughputs, bottom right (as in the paper figure)
    axin = ax.inset_axes([0.56, 0.08, 0.40, 0.36])
    N1 = ([("Redir.", redirect[0], C_REDIR, "^"), ("Proxy", proxy[0], C_PROXY, "s")] if N[0] == 1 else []) + \
         [(lab, bl[k], PROTO[k]["c"], mk) for k, lab, mk in (("vanilla", "Van.", "o"), ("ratls", "RA+TLS", "D"), ("httpa", "HTTPA", "v")) if k in bl]
    if N1:
        for x, (lab, y, c, mk) in enumerate(N1):
            axin.plot([x], [y], marker=mk, ms=6.5, mfc=c, mec="black", mew=0.7, ls="none")
        axin.set_xlim(-0.6, len(N1) - 0.4); axin.set_xticks(range(len(N1))); axin.set_xticklabels([l for l, *_ in N1], fontsize=6)
        lo, hi = min(y for _, y, _, _ in N1), max(y for _, y, _, _ in N1); axin.set_ylim(min(6, lo * 0.8), max(11, hi * 1.1)); axin.set_yticks([8, 10]); axin.tick_params(labelsize=6.5); axin.grid(True, axis="y", alpha=0.25)
        axin.set_title("$N\\!=\\!1$", fontsize=7, pad=2)
    else:
        axin.set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(HERE, "fig_scale_backends.png"), dpi=200, bbox_inches="tight")
    fig.savefig(os.path.join(HERE, "fig_scale_backends.pdf"), bbox_inches="tight")
    print("wrote fig_scale_backends.{png,pdf}")
    print("pool sizes:", N, "baselines N=1:", bl)
    sys.exit(0)
ax.set_ylabel("Aggregate throughput (req/s)")
ax.set_ylim(0, 340)
ax.grid(True, which="both", axis="y", alpha=0.25)
ax.legend(frameon=False, loc="upper left", ncol=1, handletextpad=0.4, labelspacing=0.3)
ax.annotate("linear\n(no ceiling)", (32, 318), xytext=(27, 250),
            fontsize=8.0, color=C_REDIR, ha="center")
ax.annotate("plateaus at frontend", (24, 157), xytext=(9.5, 92),
            fontsize=8.5, color=C_PROXY,
            arrowprops=dict(arrowstyle="->", color=C_PROXY, lw=0.8))

# Inset: zoom on the single-server N=1 throughputs so the per-protocol ordering
# is legible. The attested baselines fall below the backend cap on their
# per-connection vTPM quote; Janus and vanilla sit at the cap (attestation is
# offline for Janus, absent for vanilla). Janus-proxy == redirection at N=1.
axin = ax.inset_axes([0.36, 0.55, 0.44, 0.40])
N1 = [("Redir.", redirect[0], C_REDIR, "^"),
      ("Proxy",  proxy[0],    C_PROXY, "s"),
      ("Van.",   bl["vanilla"], PROTO["vanilla"]["c"], "o"),
      ("RA+TLS", bl["ratls"],  PROTO["ratls"]["c"], "D"),
      ("HTTPA",  bl["httpa"],  PROTO["httpa"]["c"], "v")]
for x, (lab, y, c, mk) in enumerate(N1):
    axin.plot([x], [y], marker=mk, ms=7.5, mfc=c, mec="black", mew=0.7, ls="none")
    if x >= 3:  # label only the attested baselines, which sit below the cap
        axin.text(x, y + 0.16, f"{y:.1f}", fontsize=6.6, ha="center", va="bottom", color=c)
axin.text(1.0, 9.55, "all at cap", fontsize=6.2, color="#666666", ha="center", va="top")
# bracket the two Janus modes
axin.annotate("", (-0.0, 10.55), (1.0, 10.55),
              arrowprops=dict(arrowstyle="-", color="#666666", lw=0.8))
axin.text(0.5, 10.62, "\\sys{}".replace("\\sys{}", "Janus"), fontsize=6.6,
          ha="center", va="bottom", color="#444444")
axin.axhline(10, ls=":", color="#999999", lw=1.0)
axin.text(len(N1) - 1, 10.08, "backend cap", fontsize=6.2, color="#888888", va="bottom", ha="right")
axin.set_xlim(-0.6, len(N1) - 0.4)
axin.set_xticks(range(len(N1))); axin.set_xticklabels([l for l, *_ in N1], fontsize=6.3)
axin.set_ylim(6.4, 11.2); axin.set_yticks([7, 8, 9, 10]); axin.tick_params(labelsize=6.6)
axin.set_title("single server ($N\\!=\\!1$)", fontsize=7.6, pad=2)
axin.grid(True, axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig(os.path.join(HERE, "fig_scale_backends.png"), dpi=200, bbox_inches="tight")
fig.savefig(os.path.join(HERE, "fig_scale_backends.pdf"), bbox_inches="tight")
print("wrote fig_scale_backends.{png,pdf}")
print("baselines N=1:", bl)
print("redirect @32 / RA+TLS @1 =", round(redirect[-1] / bl["ratls"], 1), "x")
