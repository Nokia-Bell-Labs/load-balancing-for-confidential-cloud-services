#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Render eval/configs/env.yaml from eval/ae/testbed.env.

testbed.env is the single place where the addresses of the testbed live. The
measurement scripts read eval/configs/env.yaml.  Every eval/ae wrapper calls this after
it sources testbed.env, so the two can never disagree.  The env.yaml in the repository
keeps 'TBD' placeholders. This script fills in only those fields. It leaves comments and all
other settings untouched.

    python3 eval/ae/render_env.py            # uses eval/ae/testbed.env
"""
import os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
ENV_FILE = os.path.join(HERE, "testbed.env")
YAML = os.path.join(ROOT, "eval", "configs", "env.yaml")

def read_env(path):
    vals = dict(os.environ)
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.split(" #")[0].strip().strip('"').strip("'")
        v = re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda m: vals.get(m.group(1) or m.group(2), ""), v)
        vals[k.strip()] = v
    return vals

def main():
    if not os.path.exists(ENV_FILE):
        sys.exit(f"missing {ENV_FILE} (copy testbed.env.example and fill it in)")
    e = read_env(ENV_FILE)
    # yaml key under a protocol block -> value from testbed.env
    per_block = {
        "vanilla":       {"host": e.get("BACKEND_HOST"), "port": e.get("VANILLA_PORT")},
        "ctls_proxy":    {"frontend_host": e.get("FRONTEND_HOST"), "frontend_port": e.get("FRONTEND_PORT")},
        "ctls_redirect": {"frontend_host": e.get("FRONTEND_HOST"), "frontend_port": e.get("FRONTEND_PORT"),
                          "nss_helper_bin": e.get("NSS_HELPER"), "nss_db": e.get("NSS_DB")},
        "ratls":         {"host": e.get("RATLS_HOST"), "port": e.get("RATLS_PORT")},
        "httpa":         {"host": e.get("HTTPA_HOST"), "port": e.get("HTTPA_PORT")},
    }
    out, block, changed = [], None, 0
    top = None
    for line in open(YAML):
        m0 = re.match(r"^(\w+):\s*$", line)
        if m0: top = m0.group(1); block = None
        if top == "maa" and e.get("MAA_URL"):
            m1 = re.match(r"^(\s+)url:\s*(.*?)\s*$", line)
            if m1 and m1.group(2).split("#")[0].strip() != e["MAA_URL"]:
                line = f"{m1.group(1)}url: {e['MAA_URL']}\n"; changed += 1
        m = re.match(r"^  (\w+):\s*$", line)
        if m:
            block = m.group(1)
        m = re.match(r"^(\s+)(\w+):\s*(.*?)\s*$", line)
        if block in per_block and m and m.group(2) in per_block[block] and per_block[block][m.group(2)]:
            indent, key, cur = m.groups()
            val = per_block[block][key]
            if cur.split("#")[0].strip() != val:
                line = f"{indent}{key}: {val}\n"; changed += 1
        out.append(line)
    open(YAML, "w").write("".join(out))
    left = [l for l in out if "TBD" in l and not l.lstrip().startswith("#")]
    print(f"env.yaml rendered from testbed.env ({changed} field(s) updated)" + (f". Still TBD: {len(left)}" if left else ""))
    return 1 if left else 0

if __name__ == "__main__":
    sys.exit(main())
