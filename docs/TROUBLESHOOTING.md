<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Troubleshooting

This page lists the problems that occurred on this testbed. It explains what each problem means.

**`check_testbed.sh` fails the frontend attestation check.** The frontend
certificate carries an AS JWT. MAA issues the JWT with an 8-hour lifetime.
The frontend re-attests and re-issues the JWT automatically one hour before
expiry. Clients reject an expired JWT. If the check reports "JWT expired",
the renewal watchdog on the frontend stalled. Tell us in the HotCRP thread.

We restart the frontend on our side. A restart keeps the same certificate
(design §4.2). Thus the restart does not invalidate the numbers you measured.

**`/pool_status` shows fewer backends than announced, or none in service.**
A backend that rebooted re-registers with a fresh key. We must mark this
backend in service. A backend whose DC lapsed re-registers on its own when
it restarts. Ask us to reset the pool for your window.

**Proxy-mode requests return 502, or `/pool_status` lists a backend twice.**
A backend CVM that restarted registers again under a fresh key. Its old row
stays in the pool. Only the owner key can retire a row through `/mark_cvm`. The
frontend keeps picking the stale row, and its pinned relay fails.

Ask us to reset the pool for your window. Note: the reset does not affect
the numbers you measured before.

**A `/forward` request returns 503 "no pinned certificate".** The frontend
holds no certificate pin for that backend. The frontend refuses to relay to
such a backend (design §4.4, proxy mode). This happens only with a backend
that an older client registered. We re-register the backend.

**Latency numbers are high at every RTT, including 0.** Run
`sudo tc qdisc show dev <IFACE>`. A previous run can leave a `netem` delay
installed. The `eval/ae` scripts remove the delay on exit. A killed run does
not remove it. Run `sudo tc qdisc del dev <IFACE> root` to clear the delay.

**RA+TLS runs fail with an import error.** RA+TLS needs the interpreter with
the RA+TLS bridge. This interpreter is `RATLS_PYTHON` in `testbed.env` and
the `RATLS_PYTHON` variable of the Makefile. RA+TLS cannot work under the
system `python3`.

**The browser benchmark reports `attested=0` for some loads, or cannot start
Firefox.** Firefox must be the copy under `FIREFOX`. This copy carries the
enterprise policy that trusts our CA root. The names `janus-fe.local` and
`janus-be.local` must resolve to the testbed addresses. Set them in
`/etc/hosts` on the client VM. A load with `attested=0` means the extension
did not validate that navigation. The benchmark counts only attested loads.

**MAA is slow or bimodal.** The response time of the attestation service
alternates between roughly 100 ms and 230 ms. This affects only the
cold-cache pass and the registration numbers. It never affects the warm
path. The headline numbers of the paper use the warm path. For this reason,
`run_table2_fig5.sh` runs warm and cold separately.

**`make eval` says "refuses to overwrite".** The scripts never overwrite raw
CSVs silently. The `eval/ae` wrappers move an earlier run of the same id to
`eval/data/previous/` before they start. Thus you can re-run a wrapper. If
you call `make` directly, use a new `RUN_ID` or delete `eval/data/<RUN_ID>`.

**Something on the server side looks wrong.** By design, you cannot fix the
server side from the client. Post the script and the output in the HotCRP
thread. We look at it the same day.
