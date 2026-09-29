#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Draw the three evaluation figures of the paper into ./figures/ from the data of one run.

Each generator writes its PNG and PDF next to its own data directory. This
script runs the three generators and collects the copies into figures/:

  figures/fig_apps.png                  <- bench_figures/paper_figures.py (fig_apps)
  figures/fig_latency_breakdowns.png    <- bench_figures/gen_latency.py
  figures/fig_scale_backends.png        <- scalability_capped/gen_capped_scaleout.py

Needs matplotlib (the generators read CSV files with the stdlib csv module).
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")

# (generator path relative to HERE, dir to run it from, basename it writes)
JOBS = [
    ("bench_figures/paper_figures.py",            "bench_figures",      "fig_apps"),
    ("bench_figures/gen_latency.py",              "bench_figures",      "fig_latency_breakdowns"),
    ("scalability_capped/gen_capped_scaleout.py", "scalability_capped", "fig_scale_backends"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for script, subdir, base in JOBS:
        wd = os.path.join(HERE, subdir)
        print(f"== {script} ==")
        subprocess.run([sys.executable, os.path.join(HERE, script)], cwd=wd, check=True)
        n = 0
        for ext in ("png", "pdf"):
            src = os.path.join(wd, f"{base}.{ext}")
            if not os.path.exists(src):
                continue   # the generator found no measured data for this figure
            shutil.copyfile(src, os.path.join(OUT, f"{base}.{ext}"))
            print(f"   -> figures/{base}.{ext}"); n += 1
        if not n:
            print(f"   (no data for {base}: not measured in this run)")
    print(f"\nfigures written to {OUT}")


if __name__ == "__main__":
    main()
