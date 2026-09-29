#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Shared plotting style for all Janus evaluation figures.

Import from any gen_*.py under results so every figure shares one look:

    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from janus_style import apply, PROTO, PHASE, save, C_FE

`apply()` sets the rcParams. `PROTO` is the canonical per-protocol color / marker
/ hatch / label (a protocol is the SAME color in every figure). `PHASE` is the
latency-breakdown phase palette (quote=red, AS=purple, matching the paper text).
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ── rcParams (one base look) ──────────────────────────────────────────────────
RC = {
    "font.family": "serif", "font.size": 11,
    "axes.labelsize": 12, "axes.titlesize": 12, "legend.fontsize": 9.5,
    "xtick.labelsize": 10, "ytick.labelsize": 10,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.dpi": 120, "savefig.bbox": "tight", "savefig.dpi": 200,
}


def apply():
    plt.rcParams.update(RC)


# ── canonical per-protocol identity (color is consistent across ALL figures) ──
# color, line marker, bar hatch (for B/W print), display label.
PROTO = {
    "vanilla":       {"c": "#555555", "m": "o", "h": "",    "label": "Vanilla TLS"},
    "ctls_proxy":    {"c": "#2ca02c", "m": "s", "h": "//",  "label": "Janus-proxy"},
    "ctls_redirect": {"c": "#9467bd", "m": "^", "h": "\\\\", "label": "Janus-redirection"},
    "ratls":         {"c": "#8c564b", "m": "D", "h": "..",  "label": "RA+TLS"},
    "httpa":         {"c": "#ff7f0e", "m": "v", "h": "xx",  "label": "HTTPA/2"},
}
# convenient accessors
def color(p):  return PROTO[p]["c"]
def marker(p): return PROTO[p]["m"]
def hatch(p):  return PROTO[p]["h"]
def label(p):  return PROTO[p]["label"]

# canonical x-order when several protocols share an axis
ORDER = ["vanilla", "ctls_proxy", "ctls_redirect", "ratls", "httpa"]

# ── one legend look shared by every figure (so legends read the same way) ─────
# No frame, tight handles, consistent spacing. Pass `**LEGEND` to ax/fig.legend
# and override only loc/ncol/fontsize (small panels may need fontsize ~7).
LEGEND = dict(frameon=False, handlelength=1.5, handletextpad=0.5,
              labelspacing=0.3, columnspacing=1.2, borderaxespad=0.3)
LEGEND_FS = 8.0          # default legend font size (full-width figures)

# ── percentile palette for the application bar charts (per-percentile) ────────
# colour AND fill pattern so the three bars stay distinct in B/W print.
PCTL = {
    "p50": {"c": "#222222", "h": "",   "label": "p50"},   # black, solid
    "p95": {"c": "#1f77b4", "h": "//", "label": "p95"},   # blue, hatched
    "p99": {"c": "#c01d1d", "h": "..", "label": "p99"},   # red, dotted
}

# ── latency-breakdown phase palette (per-phase, not per-protocol) ─────────────
# Muted Tableau set: blues for the (handshake) phases all attested protocols
# share, then green/red/purple for the attestation-only phases. quote=red,
# AS(MAA)=purple per the paper text.
PHASE = {
    "tcp":      "#bab0ac",   # TCP connect (folded into tls in practice)
    "tls":      "#4e79a7",   # TCP + TLS-1.3 handshake
    "tls2":     "#a0cbe8",   # backend TLS + DC handshake (redirection)
    "route":    "#f1ce63",   # frontend routing / control leg
    "validate": "#59a14f",   # client-side cert / DC / JWT validation
    "quote":    "#e15759",   # server-side hardware quote
    "maa":      "#b07aa1",   # attestation-service (MAA) round trip
}

# frontend forwarding capacity used across scalability figures
C_FE = 162


def save(fig, path_noext):
    """Save <path_noext>.png and .pdf with the shared dpi/bbox."""
    fig.savefig(path_noext + ".png", dpi=200, bbox_inches="tight")
    fig.savefig(path_noext + ".pdf", bbox_inches="tight")
    print("wrote", os.path.basename(path_noext) + ".{png,pdf}")
