#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""One entry point for the artifact evaluation. It wraps the per-claim scripts.

    ./ae.py -m test                       # pre-flight check: endpoints, attestation, pool
    ./ae.py -m data   [-r RUN] [-e LIST]  # run the experiments (default: all that the standing testbed supports)
    ./ae.py -m figures [-r RUN]           # figures and tables from THAT run only -> <results>/<RUN>/paper-repro/ (+ coverage.md)
    ./ae.py -m status [-r RUN]            # what the run has done so far (manifest.json)
    ./ae.py -m testbed                    # state of the testbed: frontend, pool and profile, app backend, H100, Fig. 6 window
    ./ae.py -m clean  [-r RUN]            # move the raw data of a run aside, clear netem

Every run has an id (-r). The default is the newest run, or a new one named ae-<UTC time>.
A run owns  eval/data/<RUN>-rtt-*/ and eval/data/<RUN>-scale-N*/  (raw data of the measurement scripts)
and         <results>/<RUN>/  (application benches, table outputs, manifest.json, paper-repro/).
Run `data` again with the same -r to resume it. The run skips experiments that already 'succeeded'.

Experiments for -e (comma-separated):
    table1   startup / registration latency (reference CSVs + live DC-signing cost)   ~1 min
    table3   certificate and DC sizes (live)                                           ~1 min
    table2   establishment latency at RTT 0/40/80/120 (Table 2 and Fig. 5)              ~1 h   (COLD=1 adds the cold-cache pass)
    fig6     Fig. 6 curve: N = 32, 16, 8, 4, 2, 1 (FIG6_SIZES; "current" = one point at the present size of the pool)
             + the single-server baselines at N=1. ae.py resizes the pool for each point through the
             pool-size service of the operators. This service runs during your Fig. 6 window (profile "scale")  ~1.5 h
    fig7c    microservice workload   (pool profile "hotel", pre-checked)              ~10 min
    fig7a    browser workload        (pool profile "browser", pre-checked)            ~10 min
    fig7b    LLM workload, a separate on-request option. The H100 CVM is started for your window
             (profile "gpu"). It is never part of the default                          ~20 min
Groups: -e default (= table1,table3,table2). This is the default group. It runs on the standing pool.
Every other experiment needs its own pool profile. We set the profile for your window (docs/ACCESS.md).
The groups are -e fig6 (scale: the whole curve in one run), -e fig7c (hotel), -e fig7a (browser), -e fig7b (gpu, on request).
Use the same -r for all of them, so they land in one run. --cold adds the cold-cache pass of Table 2.
"""
import argparse, csv, glob, hashlib, json, os, shutil, signal, ssl, subprocess, sys, time, urllib.request
CHILD = None
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
from render_env import read_env, ENV_FILE

DEFAULT = ["table1", "table3", "table2"]                  # phase 1: the standing pool (default)
ALL = ["table1", "table3", "table2", "fig6", "fig7c", "fig7a", "fig7b"]
# Every other experiment needs its own pool profile (scale: fig6, hotel: fig7c, browser: fig7a, gpu: fig7b). The operators set it.
# There is no "all" group on purpose. Experiments that need different profiles cannot run in one go.
GROUPS = {"default": DEFAULT, "scale": ["fig6"], "hotel": ["fig7c"], "browser": ["fig7a"], "gpu": ["fig7b"]}
EXPECTED_MIN = {"table1": 1, "table3": 1, "table2": 60, "fig6": 7, "fig6-N1": 25, "fig7c": 5, "fig7a": 3, "fig7b": 20}   # for the progress lines

FIGS = {"fig_latency_breakdowns.pdf": "figure_5.pdf", "fig_scale_backends.pdf": "figure_6.pdf", "fig_apps.pdf": "figure_7.pdf"}

def env():
    if not os.path.exists(ENV_FILE):
        sys.exit("eval/ae/testbed.env is missing (on the client VM that we provide, the file is pre-filled)")
    e = read_env(ENV_FILE)
    # The results root may use shell substitution in testbed.env. Resolve it with bash. Ignore any RUN_ROOT that is already in the environment.
    e["RESULTS"] = subprocess.check_output(["bash", "-c", f'unset RUN_ROOT; source "{ENV_FILE}"; echo -n "${{RUN_ROOT:-$HOME/ae-results}}"'], text=True)
    e["RESULTS"] = os.path.dirname(e["RESULTS"].rstrip("/")) if os.path.basename(e["RESULTS"].rstrip("/")).count("-") == 2 else e["RESULTS"]   # a dated default -> its parent
    return e

def runs(e):
    return sorted((d for d in glob.glob(os.path.join(e["RESULTS"], "*")) if os.path.isfile(os.path.join(d, "manifest.json"))), key=os.path.getmtime)

def run_dir(e, run): return os.path.join(e["RESULTS"], run)

def load_manifest(e, run):
    p = os.path.join(run_dir(e, run), "manifest.json")
    return json.load(open(p)) if os.path.exists(p) else {"run": run, "experiments": {}}

def save_manifest(e, run, m):
    os.makedirs(run_dir(e, run), exist_ok=True); json.dump(m, open(os.path.join(run_dir(e, run), "manifest.json"), "w"), indent=2)

def sh(cmd, log, extra):
    """Run a wrapper. Stream its output and tee it to `log`. Return its exit code."""
    print(f"\n$ {' '.join(cmd)}", flush=True); os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "w") as lf:
        p = subprocess.Popen(cmd, cwd=HERE, env={**os.environ, **extra, "PYTHONUNBUFFERED": "1"}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)   # its own process group: an interrupt of the driver ends the whole measurement
        global CHILD; CHILD = p
        try:
            for line in p.stdout:
                print(line, end="", flush=True); lf.write(line)
            p.wait()
        except KeyboardInterrupt:
            try: os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            p.wait(); raise
        finally:
            CHILD = None
    return p.returncode

def pool(e):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        d = json.load(urllib.request.urlopen(f"https://{e['FRONTEND_HOST']}:{e['FRONTEND_PORT']}/pool_status", context=ctx, timeout=10))
        return [{"backend": b["ip_address"] + ":" + str(b["port"]), "mode": b["cvm_mode"], "cert_fp": b.get("cert_fp", "")[:16]} for b in d["backends"]]
    except Exception as ex:
        return [{"error": str(ex)}]

def provenance():
    def out(cmd):
        try: return subprocess.check_output(cmd, cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception: return ""
    return {"source_commit": out(["git", "rev-parse", "HEAD"]), "source_dirty": bool(out(["git", "status", "--porcelain"])),
            "testbed_env_sha256": hashlib.sha256(open(ENV_FILE, "rb").read()).hexdigest(), "client": out(["hostname"]),
            "python": sys.version.split()[0], "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "frontend_mrenclave": frontend_mrenclave()}

def frontend_mrenclave():
    """The MRENCLAVE attested in the certificate of the frontend. This is the frontend that the client talked to."""
    try:
        e = read_env(ENV_FILE); sys.path.insert(0, ROOT)
        import socket
        from cryptography import x509
        from janus.client import attest
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((e["FRONTEND_HOST"], int(e["FRONTEND_PORT"])), timeout=10) as s0, ctx.wrap_socket(s0, server_hostname=e["FRONTEND_HOST"]) as ss:
            cert = x509.load_der_x509_certificate(ss.getpeercert(True))
        _, payload, _ = attest.parse_jwt(attest.extract_jwt(cert))
        return payload.get("x-ms-sgx-mrenclave", "")
    except Exception as ex:
        return f"unavailable: {ex}"

FIG6_SIZES_DEFAULT = "32,16,8,4,2,1"         # the Fig. 6 points of the paper, largest first
POOL_STATE = "/tmp/janus-pool-state"   # on the client VM. The service of the operators answers here
POOL_REQUEST = f"/tmp/janus-pool-request.{os.environ.get('USER') or os.getuid()}"   # one request file per account (/tmp is sticky)

def request_pool_size(e, n, wait_min=20):
    """Ask the pool-size service of the operators to set the pool to n backends. The service runs during a
    Fig. 6 window (docs/ACCESS.md). Then wait until the frontend reports n backends in service. The evaluator
    account writes the request file. The service polls the file from the operator side. It resizes the pool
    and writes the state file."""
    serial = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}"
    with open(POOL_REQUEST, "w") as f: f.write(f"{serial} {n}\n")
    print(f"requested pool size {n} from the pool-size service of the operators (serial {serial}). Waiting for the service to apply it", flush=True)
    t0 = time.time()
    while time.time() - t0 < wait_min * 60:
        try: st = open(POOL_STATE).read().split()
        except OSError: st = []
        if len(st) >= 3 and st[0] == serial:
            if st[2] == "ready":
                k = sum(1 for b in pool(e) if b.get("mode") == "in-service")
                if k == n: print(f"pool has {n} backends in service after {(time.time()-t0)/60:.1f} min", flush=True); return True
                print(f"service reports ready, but the frontend shows {k} in service, not {n}", flush=True); return False
            if st[2] == "failed": print(f"the pool-size service could not set {n}: {' '.join(st[3:])}", flush=True); return False
        time.sleep(10)
    print(f"no answer from the pool-size service within {wait_min} min. The Fig. 6 window is not open. Ask us in the thread to open it (docs/ACCESS.md). Then run again. The run keeps the finished sizes (resume).", flush=True)
    return False

def print_summary(run, rd, save=None):
    """Print the tables of the paper with the values of this run (summary.py). With `save`, write the Markdown
    version there and one CSV per table in tables/ next to it."""
    import summary
    txt, md, tables = summary.build(run, rd, os.path.join(ROOT, "eval", "data"))
    if not txt: return
    print("\n" + txt, end="", flush=True)
    if save:
        summary.write(save, md, tables); print(f"(saved as {save}, one CSV per table in {os.path.join(os.path.dirname(save), 'tables')})", flush=True)

def _interrupt(signum, frame):
    raise KeyboardInterrupt

def data_mode(exps, e, run, resume):
    signal.signal(signal.SIGINT, _interrupt); signal.signal(signal.SIGTERM, _interrupt)   # `ae-remote.sh stop` sends SIGTERM to this process
    rd = run_dir(e, run); os.makedirs(rd, exist_ok=True)
    lock = os.path.join(e["RESULTS"], ".lock")
    if os.path.exists(lock):
        pid = open(lock).read().strip()
        if pid and os.path.exists(f"/proc/{pid}"): sys.exit(f"another evaluation run is in progress (pid {pid}, {lock}). Run only one evaluation at a time on this testbed")
    open(lock, "w").write(str(os.getpid()))
    m = load_manifest(e, run); m.setdefault("provenance", provenance()); m.setdefault("pool_at_start", pool(e)); m.setdefault("requested", []); m["requested"] += [x for x in exps if x not in m["requested"]]; save_manifest(e, run, m)
    extra = {"AE_RUN": run, "RUN_ROOT": rd}; t_all = time.time(); rc_all = 0
    try:
        plan = []                                                  # (experiment, requested pool size or None)
        for x in exps:
            if x == "fig6":
                sizes = os.environ.get("FIG6_SIZES", FIG6_SIZES_DEFAULT)
                plan += [("fig6", None)] if sizes == "current" else [("fig6", int(n)) for n in sizes.split(",")]
            else: plan.append((x, None))
        for x, want in plan:
            if want is not None:                                   # a Fig. 6 point: the pool must be at that size first
                key = f"fig6-N{want}"
                if resume and m["experiments"].get(key, {}).get("status") == "succeeded":
                    print(f"\n===== {key}: already succeeded in run {run}, skipped (resume) ====="); continue
                have = sum(1 for b in pool(e) if b.get("mode") == "in-service")
                if have != want and not request_pool_size(e, want):
                    m["experiments"][key] = {"status": "failed", "exit_code": 3, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                             "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "log": "", "pool": pool(e), "attempt": 1,
                                             "error": f"pool could not be set to {want} backends"}; save_manifest(e, run, m); rc_all |= 1
                    print(f"===== {key}: FAILED (pool not at {want}) =====", flush=True); continue
            snapshot = pool(e); n_pool = sum(1 for b in snapshot if b.get("mode") == "in-service")
            key = f"fig6-N{n_pool}" if x == "fig6" else x        # the pool size identifies a scale point
            st = m["experiments"].get(key, {})
            if resume and st.get("status") == "succeeded":
                print(f"\n===== {key}: already succeeded in run {run}, skipped (resume) ====="); continue
            t0 = time.time(); log = os.path.join(rd, "logs", f"{key}.log")
            plan_keys = [(f"fig6-N{w}" if w is not None else x2) for x2, w in plan]
            done_n = sum(1 for k2 in plan_keys if m["experiments"].get(k2, {}).get("status") == "succeeded")
            exp_min = EXPECTED_MIN.get(key, EXPECTED_MIN.get(x, "?"))
            print(f"\n===== {key} =====  [{done_n} of {len(plan)} experiments of this run done]  started {time.strftime('%H:%M', time.gmtime())} UTC, expected about {exp_min} min", flush=True)
            if st.get("status") in ("failed", "interrupted") and os.path.exists(log):
                shutil.move(log, log + "." + st.get("finished_utc", st.get("started_utc", "prev")).replace(":", ""))   # keep the log of the failed attempt
            m["experiments"][key] = {"status": "running", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "log": log,
                                     "pool": snapshot, "attempt": st.get("attempt", 0) + 1}; save_manifest(e, run, m)
            if x == "table1":   rc = sh(["./run_table1.sh"], log, extra); shutil.copy(log, os.path.join(rd, "table_1.txt"))
            elif x == "table3": rc = sh(["./run_table3.sh"], log, extra); shutil.copy(log, os.path.join(rd, "table_3.txt"))
            elif x == "table2": rc = sh(["./run_table2_fig5.sh", "0", "40", "80", "120"], log, extra)
            elif x == "fig6":
                print(f"pool has {n_pool} backend(s) in service -> N={n_pool}")
                bl = ["--with-baselines"] if (want is None or n_pool == 1) else []       # the single-server baselines run once, at N=1 (or with a single point)
                rc = sh(["./run_fig6.sh", str(n_pool)] + bl, log, extra) if n_pool else 1
            elif x == "fig7c":  rc = sh(["./run_fig7c.sh"], log, extra)
            elif x == "fig7a":  rc = sh(["./run_fig7a.sh"], log, extra)
            elif x == "fig7b":  rc = sh(["./run_fig7b.sh"], log, extra)
            else: rc = 2
            m["experiments"][key].update({"status": "succeeded" if rc == 0 else "failed", "exit_code": rc, "minutes": round((time.time()-t0)/60, 1),
                                          "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}); save_manifest(e, run, m)
            print(f"===== {key}: {'ok' if rc == 0 else f'FAILED (exit {rc}, see {log})'} in {(time.time()-t0)/60:.1f} min =====", flush=True); rc_all |= (1 if rc else 0)
    except KeyboardInterrupt:
        for x, st in m["experiments"].items():
            if st.get("status") == "running": st["status"] = "interrupted"
        save_manifest(e, run, m); rc_all = 130
    finally:
        try: os.unlink(lock)
        except OSError: pass
    m["pool_at_end"] = pool(e); m["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()); save_manifest(e, run, m)
    print_summary(run, rd, save=os.path.join(rd, "results.md"))
    print(f"\nrun {run}: " + ", ".join(f"{k}={v['status']}" for k, v in m["experiments"].items()) + f". Total {(time.time()-t_all)/60:.1f} min. Manifest: {rd}/manifest.json")
    return rc_all

PAPER_NAMES = [("vanilla", "TLS"), ("ctls_proxy", "Proxy"), ("ctls_redirect", "Redir."), ("ratls", "RA+TLS"), ("httpa", "HTTPA/2")]   # the columns of Table 2, in the order and with the names of the paper

def table2_md(run, out):
    """Table 2 in the layout of the paper: one row per emulated RTT, one column per protocol (median establishment, ms,
    warm AS-key cache)."""
    rows = {}
    for d in sorted(glob.glob(f"{ROOT}/eval/data/{run}-rtt-*"), key=lambda p: int(p.rsplit("-", 1)[1])):
        f = os.path.join(d, "summary.csv")
        if not os.path.exists(f): continue
        rtt = int(d.rsplit("-", 1)[1])
        for r in csv.DictReader(open(f)):
            if r.get("cache_policy", "warm") != "warm": continue
            p50 = r.get("p50_total_ms") or r.get("p50_total_e2e_ms") or next((v for k, v in r.items() if k.startswith("p50")), "")
            try: rows.setdefault(rtt, {})[r.get("protocol", "?")] = float(p50)
            except ValueError: pass
    if not rows: return False
    with open(out, "w") as fh:
        fh.write(f"Table 2 (run {run}): median connection establishment in ms, warm AS-key cache\n\n")
        fh.write("| RTT (ms) | " + " | ".join(n for _, n in PAPER_NAMES) + " |\n| ---: | " + " | ".join("---:" for _ in PAPER_NAMES) + " |\n")
        for rtt in sorted(rows):
            fh.write(f"| {rtt} | " + " | ".join(f"{rows[rtt][k]:.1f}" if k in rows[rtt] else "-" for k, _ in PAPER_NAMES) + " |\n")
        fh.write("\nProtocol keys in the raw data: " + ", ".join(f"{k} = {n}" for k, n in PAPER_NAMES) + ".\n")
    return True

def figures_mode(e, run):
    rd = run_dir(e, run); dest = os.path.join(rd, "paper-repro"); log = os.path.join(rd, "logs", "figures.log")
    rc = sh(["./make_figures.sh", "--from-runs"], log, {"AE_RUN": run, "RUN_ROOT": rd})
    if rc not in (0, 3): return rc            # 3 = the run has no figure data yet (tables only); the tables are still written below
    src = os.path.join(rd, "results-repro", "figures"); os.makedirs(dest, exist_ok=True)
    for a, b in FIGS.items():
        if os.path.exists(f"{src}/{a}"): shutil.copy(f"{src}/{a}", f"{dest}/{b}")
    for t in ("table_1.txt", "table_3.txt"):
        if os.path.exists(os.path.join(rd, t)): shutil.copy(os.path.join(rd, t), os.path.join(dest, t))
    table2_md(run, os.path.join(dest, "table_2.md"))
    print_summary(run, rd, save=os.path.join(dest, "results.md"))
    for c in ("coverage.md", "coverage.json"):
        if os.path.exists(os.path.join(rd, "results-repro", c)): shutil.copy(os.path.join(rd, "results-repro", c), os.path.join(dest, c))
    m = load_manifest(e, run); m["figures"] = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "dir": dest}; save_manifest(e, run, m)
    print(f"\n{dest}/: " + ", ".join(sorted(os.listdir(dest))) + "\n(coverage.md says which elements the run measured)")
    return 0

def status_mode(e, run):
    m = load_manifest(e, run)
    if not m["experiments"]: print(f"run {run}: no experiments recorded"); return 1
    prov = m.get("provenance", {}); print(f"run {run}  (source {prov.get('source_commit') or 'n/a'}, started {prov.get('started_utc', '?')})")
    for k, v in m["experiments"].items():
        if v["status"] == "running" and v.get("started_utc"):
            el = (time.time() - time.mktime(time.strptime(v["started_utc"], "%Y-%m-%dT%H:%M:%SZ")) + time.timezone) / 60
            exp_min = EXPECTED_MIN.get(k, EXPECTED_MIN.get(k.split("-N")[0], "?"))
            bar = "#" * min(20, int(20 * el / exp_min)) + "." * max(0, 20 - int(20 * el / exp_min)) if isinstance(exp_min, int) else "" 
            print(f"  {k:8s} running      {el:5.1f} of about {exp_min} min  [{bar}]"); continue
        print(f"  {k:8s} {v['status']:12s} {'exit ' + str(v.get('exit_code')) if 'exit_code' in v else '':8s} {str(v.get('minutes', '')) + ' min' if 'minutes' in v else ''}")
    if "figures" in m: print(f"  figures generated {m['figures']['generated_utc']} -> {m['figures']['dir']}")
    return 0 if all(v["status"] == "succeeded" for v in m["experiments"].values()) else 1

def clean_mode(e, run):
    prev = f"{ROOT}/eval/data/previous"; os.makedirs(prev, exist_ok=True); stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for d in sorted(glob.glob(f"{ROOT}/eval/data/{run}-*")):
        shutil.move(d, f"{prev}/{os.path.basename(d)}-{stamp}"); print(f"moved {os.path.basename(d)} -> eval/data/previous/")
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", e.get("IFACE", "eth0"), "root"], stderr=subprocess.DEVNULL); print(f"netem cleared on {e.get('IFACE', 'eth0')}")
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-m", "--mode", required=True, choices=["test", "data", "figures", "status", "testbed", "clean"])
    ap.add_argument("-r", "--run", help="run id (default: the newest run, or for data a new run named ae-<UTC time>)")
    ap.add_argument("-e", "--experiments", help="comma-separated subset (data mode)")
    ap.add_argument("--no-resume", action="store_true", help="data mode: run again the experiments that already succeeded in this run")
    ap.add_argument("--cold", action="store_true", help="data mode: also run the cold-cache pass of Table 2 (not reported in the paper)")
    a = ap.parse_args()
    exps = [y for x in a.experiments.split(",") for y in GROUPS.get(x.strip(), [x.strip()])] if a.experiments else None
    bad = [x for x in (exps or []) if x not in ALL]
    if bad: sys.exit(f"unknown experiment(s): {', '.join(bad)}  (choose from {', '.join(ALL)} or a group: {', '.join(GROUPS)})")
    if a.cold: os.environ["COLD"] = "1"
    if a.mode == "test":
        return subprocess.call(["./check_testbed.sh"], cwd=HERE)
    if a.mode == "testbed":
        return subprocess.call(["./testbed_status.sh"], cwd=HERE)
    e = env()
    if a.mode == "data":
        run = a.run or ("ae-" + time.strftime("%Y%m%dT%H%MZ", time.gmtime()))
        return data_mode(exps or DEFAULT, e, run, resume=not a.no_resume)
    run = a.run or (os.path.basename(runs(e)[-1]) if runs(e) else None)
    if not run: sys.exit("no run found, give -r <run id>")
    if a.mode == "figures": return figures_mode(e, run)
    if a.mode == "status":  return status_mode(e, run)
    if a.mode == "clean":   return clean_mode(e, run)

if __name__ == "__main__":
    sys.exit(main())
