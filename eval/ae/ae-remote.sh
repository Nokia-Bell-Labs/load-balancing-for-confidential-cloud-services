#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Run the artifact evaluation from YOUR laptop. This script drives eval/ae/ae.py on the
# client VM over SSH and copies the results back. The run is detached, so a dropped
# connection does not kill a multi-hour run. You need only ssh and rsync here.
#
#   ./ae-remote.sh ae@<client-address> test            # pre-flight check on the client                  (1 min)
#   ./ae-remote.sh ae@<client-address> data [-e LIST]  # run the experiments, detached. Shows the log     (~1 h)
#      RUN=<id> ... data      resumes or names a run (default: a new one). The exit code is the exit code of the run
#      COLD=1 ... data        adds the cold-cache pass of Table 2.
#   ./ae-remote.sh ae@<client-address> figures         # figures and tables from your runs, then fetch    (1 min)
#   ./ae-remote.sh ae@<client-address> all             # test -> data -> figures -> fetch        (~1 h)
#   ./ae-remote.sh ae@<client-address> attach          # join a running evaluation again (follow its log)
#   ./ae-remote.sh ae@<client-address> status          # progress of the run (done, running with elapsed time)
#   ./ae-remote.sh ae@<client-address> testbed         # state of the testbed: frontend, pool and profile, app backend, H100, profile service
#   ./ae-remote.sh ae@<client-address> stop            # stop the run in progress cleanly (the netem delay is removed; the same RUN resumes later)
#   ./ae-remote.sh ae@<client-address> fetch           # copy ~/ae-results + raw eval/data/ae-* -> ./janus-ae-results/
#   ./ae-remote.sh ae@<client-address> run <ae.py args>   # any other ae.py invocation, detached
#
# We sent you the address after you posted your public key. If you use a key,
# give it with -i or with an ssh_config Host entry.
set -euo pipefail
TARGET="${1:?ae@<client-address>}"; CMD="${2:-all}"; shift 2 || shift $#
REMOTE_DIR="${AE_REMOTE_DIR:-~/Janus/eval/ae}"   # the checkout of the repository on the client
LOG='~/ae-results/ae-remote.log'                  # the output of the detached run on the client (+ .exit for its exit code)
LOCAL="${LOCAL:-./janus-ae-results}"              # the directory where fetch puts the results on this machine
S() { ssh -o ServerAliveInterval=30 "$TARGET" "$@"; }
start() {   # $@ = ae.py arguments. Detached under setsid, output to $LOG, exit code to $LOG.exit
  # (the check is a separate ssh call, because the command line of the starting shell contains "ae.py -m")
  if S "pgrep -u \$USER -f '[a]e.py -m' >/dev/null"; then echo "a run is already in progress (use attach)"; exit 1; fi
  S "mkdir -p ~/ae-results; rm -f $LOG.exit; cd $REMOTE_DIR && setsid nohup bash -c './ae.py $* ; echo \$? > $LOG.exit' > $LOG 2>&1 < /dev/null & sleep 1; echo \"started: ./ae.py $* (log: $LOG)\""
}
follow() {   # print the log as it grows until the remote run exits (polling, no background job over ssh). Return ITS exit code
  S "last=0; while :; do n=\$(wc -l < $LOG 2>/dev/null || echo 0); if [ \"\$n\" -gt \"\$last\" ]; then sed -n \"\$((last+1)),\${n}p\" $LOG; last=\$n; fi; pgrep -u \$(id -un) -f '[a]e.py -m' >/dev/null || break; sleep 5; done; n=\$(wc -l < $LOG 2>/dev/null || echo 0); [ \"\$n\" -gt \"\$last\" ] && sed -n \"\$((last+1)),\${n}p\" $LOG; exit \$(cat $LOG.exit 2>/dev/null || echo 1)"
}
case "$CMD" in
  all)   # every stage must succeed before the next one runs. The exit code is the exit code of the first failure
    S "cd $REMOTE_DIR && ./ae.py -m test" || { echo "pre-flight check failed. Fix that first"; exit 1; }
    RUN="${RUN:-ae-$(date -u +%Y%m%dT%H%MZ)}"; echo "run id: $RUN  (run again with RUN=$RUN ... data to resume)"
    start -m data -r "$RUN" ${COLD:+--cold} "$@"; follow || { echo "data collection FAILED in run $RUN (see status or attach). This script skips the figures"; "$0" "$TARGET" fetch; exit 1; }
    S "cd $REMOTE_DIR && ./ae.py -m figures -r $RUN" || exit 1
    "$0" "$TARGET" fetch ;;
  test)   S "cd $REMOTE_DIR && ./ae.py -m test" ;;
  data)   start -m data ${RUN:+-r $RUN} ${COLD:+--cold} "$@"; follow ;;
  figures) S "cd $REMOTE_DIR && ./ae.py -m figures ${RUN:+-r $RUN}"; "$0" "$TARGET" fetch ;;
  run)    start "$@"; follow ;;
  attach) follow ;;   # Ctrl-C here stops only this display; the run continues on the client
  testbed) S "cd $REMOTE_DIR && ./ae.py -m testbed" ;;
  stop)   S "p=\$(cat ~/ae-results/.lock 2>/dev/null); if [ -n \"\$p\" ] && kill -0 \$p 2>/dev/null; then kill -TERM \$p && echo 'stop requested (the driver ends the measurement and marks the experiment interrupted)'; for i in 1 2 3 4 5 6; do kill -0 \$p 2>/dev/null || break; sleep 2; done; else echo 'no run in progress'; fi; pkill -u \$(id -un) -f '[r]unner.py|[_]bench.py' 2>/dev/null; sudo tc qdisc del dev \$(cd $REMOTE_DIR && . ./testbed.env && echo \$IFACE) root 2>/dev/null; cd $REMOTE_DIR && ./ae.py -m status ${RUN:+-r $RUN} | tail -8" ;;
  status) if S "pgrep -u \$USER -f '[a]e.py -m' >/dev/null"; then echo "a run is in progress"; else echo "no run in progress"; fi
          S "cd $REMOTE_DIR && ./ae.py -m status ${RUN:+-r $RUN}" 2>&1 | tail -12 ;;
  fetch)  mkdir -p "$LOCAL"; rsync -az --exclude "results-repro/" "$TARGET:ae-results/" "$LOCAL/ae-results/" || { echo "fetching ~/ae-results failed"; exit 1; }
          rsync -az "$TARGET:$REMOTE_DIR/../data/" "$LOCAL/raw-data/" || { echo "fetching the raw data of the measurement scripts ($REMOTE_DIR/../data) failed"; exit 1; }
          echo; echo "results in $LOCAL/:"; find "$LOCAL/ae-results" -maxdepth 3 \( -name "figure_*.pdf" -o -name "table_*" \) | sort ;;
  *) echo "unknown command $CMD (test|data|figures|all|attach|status|testbed|stop|fetch|run)"; exit 2 ;;
esac
