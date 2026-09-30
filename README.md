<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Janus Artifact

If you have any questions or need help, please don't hesitate to reach out to
the authors. We are happy to help!

## Overview

This repository is the artifact of the paper **"Janus: Practical Load
Balancing for Confidential Cloud Services"** (Qi Guo, Alice Dethise, Ruichuan
Chen, Istemi Ekin Akkus, Ivica Rimac, Lieven Trappeniers), ACM SIGOPS ATC '26.

The repository contains:

- the evaluation scripts that reproduce the tables and figures of the paper on
  the testbed we provide,
- the source code of Janus and of every system it is compared against,
- the scripts that draw the figures of the paper from the data of a run.

The repository ships no measurement data. Every number and every figure comes
from the experiments that you run. The numbers of the paper appear only in
`ARTIFACT.md`, as printed there.

### About Janus

A confidential cloud service runs inside trusted execution environments (TEEs).
Remote attestation lets the service prove this to its clients. Existing ways to
tie attestation to TLS assume one client and one server. Real services are
load-balanced: a frontend stands in front of a pool of backends. Janus is a
load-balancing architecture for such services.

In Janus, one small attested frontend holds the only TLS identity of the
service. This identity is an ordinary CA-issued certificate that also carries
the attestation evidence of the frontend. The frontend admits each backend
once, after it checks the attestation of the backend. It then gives the
backend a short-lived Delegated Credential (RFC 9345). With this credential,
the backend serves clients under the identity of the frontend. Unmodified TLS
clients and browsers work with Janus, in proxy mode and in redirection mode.

### What is in the repository

| Directory | Contents |
| --- | --- |
| `eval/ae/` | the evaluation scripts: one driver and one script for each table or figure |
| `eval/` | the measurement scripts and the application benchmarks |
| `janus/` | the Janus system: frontend (Intel SGX), backends with their TLS terminator (`dc_proxy`), clients (Python, native, Firefox extension) |
| `baselines/` | the two designs Janus is compared against: RA+TLS and HTTPA/2 |
| `apps/` | the three application workloads (web app, LLM server, microservice application) and the list of every external dependency with its pinned version |
| `plotting/` | the scripts that draw the figures of the paper from the data of a run |
| `ca/`, `gramine/` | the certificate authority of the testbed and the SGX packaging of the frontend |
| `deploy/` | scripts that build the whole testbed from scratch on other machines |
| `docs/` | testbed access (`docs/ACCESS.md`) and troubleshooting |
| `ARTIFACT.md` | every claim of the paper: the experiment, the command, the duration and the expected numbers |
| `docs/DESIGN-MAP.md` | where each design element of the paper is implemented |

## Prerequisites

**Important note**: the experiments need Intel SGX machines, AMD SEV-SNP
confidential VMs and a cloud attestation service. All scripts are written for
the **testbed we provide on Microsoft Azure**, and we tested them there. The
testbed is the environment the numbers of the paper come from (see
"Environment" below). You get an account on the client machine of the testbed.
We operate the servers. You do not configure anything on the client: the
repository is checked out there, with the testbed addresses filled in.

On your own computer you need only:

- `git`, `ssh` and `rsync`. Any Linux or macOS works. On Windows use WSL.

**What the scripts do to the machines they run on:**

- On your own computer, `eval/ae/ae-remote.sh` runs only `ssh` and `rsync`.
  It copies results into a directory that you name. It installs nothing and
  needs no privileges.
- On the client VM, the experiment scripts run `sudo tc` to add and remove a
  `netem` delay on the network interface of the VM. This delay emulates the
  RTTs. The evaluator account can run only `tc` with `sudo`. Every script
  removes the delay when it exits. Nothing else on the client changes.
- The evaluation scripts never change the servers.
- The `deploy/` scripts rebuild the testbed on your own machines. They are the
  only scripts that install packages (`apt`, `pip`, Docker images), and their
  headers say so. The `eval/staging/` scripts delete only the temporary
  directory that they create.

## How the Evaluation Works

**The testbed.** We keep the testbed of the paper up on Microsoft Azure for
the whole review period. It has four kinds of machines:

```
 your laptop ──SSH──▶ client VM ──┬──▶ frontend (Intel SGX enclave, Gramine)      :6037  registration, /route, proxy mode
 (git, ssh, rsync)   (your account) ├──▶ backend CVMs (AMD SEV-SNP), 4 to 32       :8443  dc_proxy (DC-TLS), :8444 vanilla TLS
                                    ├──▶ RA+TLS server, HTTPA/2 server              on one backend CVM (the baselines)
                                    ├──▶ H100 CVM (LLM workload)                    on request only
                                    └──▶ Azure MAA (the attestation service)        public, regional
```

- The **frontend** is the Janus frontend inside an SGX enclave. It holds the
  TLS identity of the service, admits the backends and issues their
  Delegated Credentials.
- The **backends** are SEV-SNP confidential VMs. Each runs the Janus backend
  with its DC-TLS terminator (`dc_proxy`) and the application. Four backends
  stand permanently. For Fig. 6 we start the full pool of 32.
- One backend CVM also runs the two **baseline** servers (RA+TLS and
  HTTPA/2) and the three application workloads.
- The **client VM** is your machine on the testbed. It has every client of
  the paper: the Python and native (NSS) clients, a stock Firefox with the
  Janus extension, the RA+TLS client, and `tc` to emulate the RTTs. You get
  an SSH account on it, and nothing else. This is the position of a client in
  the paper: you verify the SGX attestation of the frontend yourself.
- We operate the servers. You never log into them.

**The flow.** Every experiment of the paper is one script on the client. You
start them from your laptop with `eval/ae/ae-remote.sh`, which runs the
script over SSH and copies the results back. The steps are:

1. `test`: the pre-flight. It checks every server, verifies the attestation of
   the frontend and lists the pool (1 minute).
2. `data`: the measurements. Each experiment needs the backend pool in a
   certain state, called a *profile*. The script requests it from our profile
   service and waits until the pool is ready, so a whole run needs no message
   to us. The LLM run is the one exception: its H100 CVM is started on request.
3. `figures`: the figures and tables of the paper, drawn from your data only,
   printed in the terminal and saved as files.
4. `fetch`: everything to `./janus-ae-results/` on your laptop.

**What reproduces what.**

| Paper | Experiment | Pool profile | Time |
| --- | --- | --- | --- |
| Table 1 (startup, registration) | `table1` | `default` | 1 min |
| Table 3 (certificate and DC sizes) | `table3` | `default` | 1 min |
| Table 2 and Fig. 5 (establishment latency vs RTT) | `table2` | `default` | 1 h |
| Fig. 6 (throughput vs pool size, N = 1 to 32) | `fig6` | `scale` (32 backends, resized by our profile service) | 1.5 h |
| Fig. 7(c) (microservice application) | `fig7c` | `hotel` | 5 min |
| Fig. 7(a) (browser page load) | `fig7a` | `browser` | 3 min |
| Fig. 7(b) (LLM time to first token) | `fig7b` | `gpu` (H100 CVM, on request) | 20 min |

Every run has an id and a manifest. The manifest records the source commit,
the testbed configuration, the pool, and the status of every experiment. A
failed experiment stays failed: the scripts never fill in the data of the
paper for it. `coverage.md` next to the figures says which parts of each
figure come from your run.

**Time.** The whole evaluation takes about 3 hours, plus the optional LLM
run. `ARTIFACT.md` lists every claim of the paper with its command and the
numbers to expect.

## Configuration

### Step 1: Get testbed access

Post two items in the HotCRP artifact thread:

1. an **SSH public key**, and
2. the **IPv4 range you will connect from**. A /24 is enough, for example
   `203.0.113.0/24`. Our firewall opens SSH only to a named range. If you do
   not want to reveal your network, connect through a VPN or a small cloud
   jump host and give us that range. We can change the range at any time.

We reply in the thread with the address of the client VM. Only one evaluator
can use the testbed at a time, so please also tell us when you plan to run.
Half a day is enough for everything. See `docs/ACCESS.md` for details.

### Step 2: Configure SSH

Add the client to your `~/.ssh/config`. Use the private key that matches the
public key you posted:

```text
Host janus-client
     HostName <address we sent you>
     User ae
     IdentityFile ~/.ssh/id_ed25519      # change to your key
```

### Step 3: Get the code and check the testbed

Clone this repository on your computer, at the evaluated tag:

```sh
git clone --branch atc26-ae https://github.com/Nokia-Bell-Labs/load-balancing-for-confidential-cloud-services.git janus-artifact
cd janus-artifact
```

If the clone does not work, copy the same version from the client VM:

```sh
rsync -a janus-client:Janus/ janus-artifact/
cd janus-artifact
```

Then run the pre-flight checks:

```sh
eval/ae/ae-remote.sh janus-client test
```

This command logs into the client VM and runs the pre-flight checks there. The
checks confirm that every server answers and that the SGX attestation of the
frontend verifies from the client VM. They also list the pool of admitted
backends. The output ends with `17 checks passed, 0 failed`.

### Quick start (kick-the-tires, 5 minutes)

```sh
RUN=kick eval/ae/ae-remote.sh janus-client data -e table1,table3   # 2 min: Table 1's live part and Table 3, measured
RUN=kick eval/ae/ae-remote.sh janus-client figures                 # 1 min: tables and figures from that run, copied to ./janus-ae-results/
```

The first command prints the measured values: for Table 3, the size of the
attestation extension of the certificate and of the Delegated Credential. The second command writes `table_1.txt`,
`table_3.txt`, `results.md`, the CSV tables and `coverage.md` to
`./janus-ae-results/ae-results/kick/paper-repro/`. It draws no figure, because
this short run measures no figure data. If both commands work, every
step below works in the same way. The steps below only take longer.

## Running the Evaluation

You drive everything with `eval/ae/ae-remote.sh <host> <step>` from your
computer. The command runs the step on the client and copies the results back.
You can also log into the client and run `eval/ae/ae.py -m <step>` there. The
steps are the same.

### Step 1: Data collection (`data`)

```sh
eval/ae/ae-remote.sh janus-client data
```

**Expected duration**: about **1 hour** for the default set (Tables 1 to 3 and
Fig. 5). Fig. 6 (about 1 hour) and the application workloads (3 to 5 minutes
each) are separate runs. They need a pool profile, see below.

The run starts detached on the client, so it continues if your connection
drops or if you press `Ctrl-C`. `eval/ae/ae-remote.sh janus-client attach`
shows the log again and follows it. `eval/ae/ae-remote.sh janus-client status`
shows the progress of the run.

Every run has an id. The driver prints the id at the start, for example
`ae-20260922T1530Z`. You can choose the id: `RUN=review-01
eval/ae/ae-remote.sh janus-client data`. The manifest of the run records the
source commit, the testbed configuration, the backend pool, and the status and
exit code of every experiment. When you run `data` again with the same id, the
driver resumes the run and skips the experiments that succeeded. A failed
experiment fails the command. The driver never replaces a failed experiment
with the data of the paper.

**What it does**, in this order. These three experiments need nothing from us.
These three run on the `default` profile:

| Experiment | Reproduces | Time |
| --- | --- | --- |
| `table1` | Table 1: the startup and registration timings of the paper (reference CSVs, measured on the servers; we collect them again on request), plus the DC-issuance signing cost, measured live | 1 min |
| `table3` | Table 3: the sizes of the certificate and of the Delegated Credential, measured live | 1 min |
| `table2` | Table 2 and Fig. 5: the TLS establishment latency of the five protocols at 0/40/80/120 ms RTT (warm AS-key cache, as the paper reports; `COLD=1` adds the cold pass) | 1 h |

The other experiments each need a different profile. The script requests it
from our profile service before the experiment and waits for the switch, one
to five minutes; you do not need to ask us. Keep the same `RUN=` so that all
results land in one run:

| Experiment | Reproduces | Time |
| --- | --- | --- |
| `fig6` | Fig. 6, the whole curve in one run: the sustained throughput of proxy mode and redirection mode at N = 32, 16, 8, 4, 2 and 1 backends, plus the single-server baselines at N = 1 (rate-capped as in the paper). The 32 backend CVMs are up during your slot. The script asks our profile service for each size in turn and waits until the frontend shows that many backends in service (3 to 6 minutes per resize). You run one command. | about 1.5 h |
| `fig7c` | Fig. 7(c): the end-to-end latency of the microservice application under the five protocols (profile *hotel*) | 5 min |
| `fig7a` | Fig. 7(a): the page-load time in a real Firefox with the Janus extension, for vanilla TLS, redirection mode and proxy mode (profile *browser*) | 3 min |
| `fig7b` | Fig. 7(b): the LLM time-to-first-token on a confidential H100 VM. **Separate, on-request option**: the H100 CVM is expensive. It is not part of the standing testbed and not part of any default run. Ask in the thread and we bring it up for your window (profile *gpu*). Then run `-e fig7b`. | 20 min |

```sh
RUN=<your run id> eval/ae/ae-remote.sh janus-client data            # everything except the LLM run, about 3 h; the pool switches itself
RUN=<your run id> eval/ae/ae-remote.sh janus-client data -e fig6    # or one experiment at a time (the whole curve, about 1.5 h)
RUN=<your run id> eval/ae/ae-remote.sh janus-client data -e fig7c   # 5 min
RUN=<your run id> eval/ae/ae-remote.sh janus-client data -e fig7a   # 3 min
```

Each script checks the profile before it measures. If the profile is not in
place, the script stops with a clear message.

`-e` selects a subset. Example: `eval/ae/ae-remote.sh janus-client data -e
table1,table3` (2 minutes). `-e default` is the default set above. `COLD=1`
adds the cold-cache pass of Table 2. The paper does not report the cold pass.

**Output**: the raw per-request CSV files are on the client under
`~/Janus/eval/data/ae-*/`. The benchmark outputs are under
`~/ae-results/<run>/`. The next step copies all of them to your computer.

### Step 2: Figure and table generation (`figures`)

```sh
eval/ae/ae-remote.sh janus-client figures
```

**Expected duration**: less than **1 minute**.

**What it does**: the step regenerates the figures of the paper with the
generator scripts of the paper, from the data of one run (the newest run, or
`RUN=...`). It builds the tables, prints them in the terminal, and copies everything to
`./janus-ae-results/` on your computer. The file `coverage.md` next to the
figures states, for every RTT, every pool size and every Fig. 7 panel, whether
your run measured it. Elements that the run did not measure are left out of
the figure. A partial run is therefore never mistaken for a full one.

**Generated files** (in `./janus-ae-results/ae-results/<run>/paper-repro/`):

```text
figure_5.pdf     Fig. 5   establishment latency vs RTT, five protocols (from table2)
figure_6.pdf     Fig. 6   throughput vs number of backends (the pool sizes your run measured)
figure_7.pdf     Fig. 7   the three application workloads (the panels your run measured; coverage.md says which)
table_1.txt      Table 1  startup and registration latency
table_2.md       Table 2  median establishment latency per protocol and RTT
table_3.txt      Table 3  certificate and Delegated Credential sizes
results.md       all tables of the paper with the values of this run (the same tables are printed in the terminal at the end of `data` and `figures`)
tables/*.csv     the same tables, one CSV file per table
coverage.md      which elements of the figures your run measured
manifest.json    (one level up) source commit, configuration, pool, status and exit code of every experiment
```

## Complete Workflow Example

```sh
export RUN=ae-$(date -u +%Y%m%dT%H%M)                   # one run id for everything below
eval/ae/ae-remote.sh janus-client test                  # 1 min
eval/ae/ae-remote.sh janus-client testbed               # seconds: what is up right now (pool profile, H100, profile service)
eval/ae/ae-remote.sh janus-client data                  # about 3 h (Tables 1-3, Fig. 5, Fig. 6, Fig. 7c, Fig. 7a; the pool switches itself)
eval/ae/ae-remote.sh janus-client figures               # 1 min
```

`eval/ae/ae-remote.sh janus-client all` runs `test`, the default data set
and `figures` as one command. It stops at the first stage that fails.
**Total time**: about **3 hours**, including the profile switches, which the
script requests itself. With the optional LLM run, plan half a day.

## Watching, Stopping and Resuming a Run

- `eval/ae/ae-remote.sh janus-client testbed` prints the state of the testbed
  in a few seconds: the frontend and its attestation, the backend pool and its
  profile, the application backend, the H100 CVM, and whether our profile
  service is up.
- `data`, `run` and `attach` show the log of the run on your laptop while it
  runs. The first line is `started: ...`. Then the lines of the run appear as
  the client writes them, with a delay of at most 5 seconds. Every experiment
  prints a line when it starts: which experiment, how many of the run are
  done, the start time and the expected duration. The measurement itself
  prints one line per step (offered rate, RTT, or sample batch). A throughput
  step lasts about 20 seconds, so pauses of that length between lines are
  normal. If nothing appears for several minutes, run `... status` in a second
  terminal: it shows every experiment of the run and, for the running one,
  the elapsed time against the expected time as a bar.
- **You do not have to keep the terminal open.** As soon as a `data` command
  has printed `started: ...`, the run is detached on the client. `Ctrl-C` on
  your laptop is safe at any time: it only closes the display, and the run
  continues. `eval/ae/ae-remote.sh janus-client attach` shows the log again
  from the start of the run and then follows it, as often as you like, from
  any machine that has your key. `... status` shows the progress bar without
  the log.
- To stop the run itself, use `eval/ae/ae-remote.sh janus-client stop`. It
  interrupts the driver, ends the measurement processes, and removes the
  `netem` delay. The manifest marks the experiment as interrupted. The same
  command with the same `RUN=` resumes later: finished experiments are skipped,
  the interrupted one runs again from its start.

## If Something Fails

- `eval/ae/ae-remote.sh janus-client status` shows what the current or the
  last run has done. `... attach` joins a running run again.
- The full log of every experiment is on the client under
  `~/ae-results/<run>/logs/<experiment>.log`. The `figures` and `fetch` steps
  copy the logs. The `manifest.json` of the run records the status and the
  exit code of each experiment.
- A profile request that fails means that our profile service did not answer
  or could not switch the pool. Post in the thread, then run the same command
  again; it resumes where it stopped.
- When you run `data` again with the same `RUN=`, the driver resumes. It skips
  the experiments that succeeded and runs the failed ones again.
- `docs/TROUBLESHOOTING.md` covers the problems we have seen: a slow
  attestation service, a backend that left the pool, DNS on the client. For
  anything else, post in the thread. We answer within the day.

## Output Directories

```text
./janus-ae-results/                       on your computer, after `figures` / `fetch`
├── ae-results/<run>/manifest.json        the run: source commit, configuration digest, pool, status of each experiment
├── ae-results/<run>/paper-repro/         figure_5/6/7.pdf, table_1/2/3, coverage.md from that run
├── ae-results/<run>/fig7c/ (fig7a/, fig7b/)   benchmark output and raw samples of the application workloads
├── ae-results/<run>/table_1.txt, table_3.txt, logs/
└── raw-data/<run>-rtt-<R>/, <run>-scale-N<N>/   raw per-request CSVs and per-RTT / per-N summaries
```

## Checking a Single Claim

`ARTIFACT.md` has one row for each claim of the paper. The row gives the
experiment, the exact command, the duration and the expected numbers. Each row
is a stand-alone script in `eval/ae/` (`run_table2_fig5.sh`, `run_fig6.sh <N>`,
`run_fig7c.sh`, and so on). You can run each script on the client by itself.
The header of each script explains what it measures and how it corresponds to
the claim.

## Environment

The testbed, and the environment the numbers of the paper come from:

| Role | Machine | Software |
| --- | --- | --- |
| Frontend | Azure `Standard_DC2s_v3` (Intel SGX), Ubuntu 22.04.5, kernel 6.8.0-azure-fde | Gramine 1.7, Docker 29, Python 3.10.12 in the enclave, Pebble v2.9.0 as CA |
| Backends (up to 32) | Azure `Standard_DC2ads_v5` (AMD SEV-SNP with vTPM), Ubuntu 22.04 CVM image | Python 3.10.12, `dc_proxy` on BoringSSL `d258906c` + patch, snpguest v0.10.0 |
| LLM backend (on request) | Azure `Standard_NCC40ads_H100_v5` (confidential H100) | vLLM 0.22, Llama-3.1-8B-Instruct |
| Client | Azure `Standard_D8s_v5`, Ubuntu 22.04.5 | Python 3.10.12, NSS DC client, RA+TLS interpreter (ratls `c05b640`), Firefox 140 ESR, geckodriver 0.35.0, `tc`-netem |
| Attestation service | Azure MAA (regional shared endpoint) | no credentials needed |

A script next to each external dependency fetches it from its official
repository at a pinned version. Every change we make to a dependency is a
patch file next to that script. `docs/DEPENDENCIES.md` lists them. All raw
output of a full run is less than 1 GB. `deploy/README.md` gives one script
for each role to build the testbed from scratch on other machines.

## License

BSD 3-Clause Clear License, Copyright (c) 2026 Nokia Bell Labs (`LICENSE`).
Third-party components keep their own licenses.
