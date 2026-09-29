<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Testbed access for artifact evaluation

The evaluation of the paper needs Intel SGX, AMD SEV-SNP confidential VMs and
a remote attestation service. We do not ask evaluators to acquire these. We
keep our Azure testbed up for the review period, and we give each evaluator
an account on its **client VM**.

## What the testbed looks like

```
 evaluator ──SSH──▶ client VM ──┬──▶ frontend (Intel SGX, Gramine)     :6037 registration, /route, proxy mode
   (you)             (yours)     ├──▶ backends (AMD SEV-SNP CVMs)       :8443 dc_proxy (DC-TLS), :8444 vanilla TLS
                                 ├──▶ RA+TLS server, HTTPA/2 server      on a backend CVM
                                 └──▶ Azure MAA (attestation service)   public, regional
```

We deploy and operate the frontend, the backends and the baseline servers.
Evaluators never log into a TEE machine. Everything in the evaluation of the
paper runs from the client. The client VM already has what the measurement
scripts need:

- Python and the RA+TLS interpreter,
- the NSS-based DC client and its trust database,
- a stock Firefox with the Janus extension, and the enterprise policy that
  trusts our CA root,
- `tc` for RTT injection,
- this repository, checked out with `eval/ae/testbed.env` filled in. Every
  script renders the configuration of the measurement scripts
  (`eval/configs/env.yaml`) from that file.

The client is the position the paper measures from. `eval/ae/check_testbed.sh` verifies the SGX attestation of
the frontend from your account (the AS-signed JWT and the `REPORTDATA` binding
to the served key). It also reads the pool of admitted backends. With this
check you confirm that the running system is the artifact, without server
access.

## Getting in

1. Post two items in the HotCRP artifact thread. Post them only there:
   evaluators are anonymous to us, and HotCRP keeps it that way.
   - an SSH **public** key, and
   - the **IPv4 range you will connect from**. A /24 is enough, for example
     `203.0.113.0/24`. Our firewall opens SSH only to a named range. We
     recommend that you connect through a VPN or a small cloud jump host and
     give us that range. Then you reveal nothing about
     your network. We can change the range at any time during your
     evaluation. We use the range only for the firewall rule. The client VM
     keeps the usual sshd logs. We do not inspect them beyond the operation
     of the testbed, and the submission tells the AEC chairs about this.

   We add the key to the evaluator account on the client VM, we open SSH to
   your range, and we reply with the address of the client VM, a read-only
   access token for the repository, and the clone command.
2. Get the code: this repository is private. Our reply gives a read-only
   access token for the repository and the clone command (read access to this repository only; it expires on
   31 October 2026). The client VM has the same version in `~/Janus`.
3. Connect: `ssh ae@<client-vm-address>`. The repository is at `~/Janus`.
4. Run `eval/ae/check_testbed.sh` (or `eval/ae/ae.py -m test`).

You do not have to keep a terminal open on the client. Run
`eval/ae/ae-remote.sh ae@<client-vm-address> all` on your laptop, from the
copy that you cloned (README, Step 3). It does the whole evaluation over SSH and copies
the figures, the tables and the raw data to `./janus-ae-results/` on your
machine. The run is detached on the client, so a dropped connection does not
stop it.

## One evaluator at a time

The benchmarks measure a shared system, so only one evaluator can use the
testbed at a time. Please announce an intended window in the HotCRP thread
before you start. Half a day covers everything except the optional GPU
experiment. Tell us when you are done. Between evaluators we remove the
previous key and reset the client (results directories and netem rules).

Four rate-capped backends stand in the default deployment (Tables 1 to 3,
Fig. 5). For Fig. 6 we open a window: we start the full pool of 32 CVMs of the
paper and we run our pool-size service. With this service, `-e fig6` measures
the whole curve (32, 16, 8, 4, 2, 1) in one command. The service resizes the
pool for you between the points. We start the H100 CVM for Fig. 7(b) on
request, because of its cost.

The backend pool has a *profile*. We set the profile for your window. Only one
evaluator uses the testbed at a time, so the switch is one message in the
thread, not a wait:

| Profile | Pool | For |
| --- | --- | --- |
| `default` (standing) | 4 capped backends on the test application | Tables 1 to 3, Fig. 5 |
| `scale` (the Fig. 6 window) | the 32 backend CVMs up and provisioned, the single-server baseline servers rate-capped as in the Fig. 6 runs of the paper, and our *pool-size service* running. `-e fig6` asks the service for 32, 16, 8, 4, 2 and 1 backends in turn. The service registers the pool again at each size (3 to 6 min). The script measures each point. | Fig. 6 |
| `hotel` | the application backend registered on its hotelReservation front. Proxy mode relays to it through the forwarding path of the frontend inside the enclave. Redirection sends the client to the same front. | Fig. 7(c) |
| `browser` | the application backend registered under its DNS name on its web-app front. Proxy mode forwards to it. Redirection sends the browser to it. | Fig. 7(a) |
| `gpu` (on request) | the H100 CVM started and registered, the baseline servers relaying to it. This is a separate option, never part of a default run. | Fig. 7(b) |

Tell us which profiles your window needs, in this order. The default run
(`-e default`) uses the standing profile. Every other experiment has its own
profile: ask for the Fig. 6 window (*scale*) and run `fig6`, ask for *hotel*
and run `fig7c`, ask for *browser* and run `fig7a`. If you asked for the H100
CVM, ask for *gpu* and run `fig7b`. The scripts check the profile before they
measure, and they tell you if it is not in place.

## What you may and may not do

- Do run any script in `eval/ae/`, the measurement scripts, or the
  application benchmarks. They only read from the servers.
- Do apply `tc netem` on the interface of the client. The scripts do this for
  you, and they clean up on exit.
- Please do not scan or load-test the servers outside the measurement
  scripts. Do not try to reach the TEE machines over SSH. The account has no
  access to them.
- Nothing you run changes the state of the servers, except the pool contents
  that you see in `/pool_status`. We do the registration.

## Contact

Problems with access, or a server that stopped answering: post in the HotCRP
thread. During the kick-the-tires period (until 29 September 2026) we answer
within the day. The testbed stays up, with the same access, until the
decisions on 14 October 2026.
