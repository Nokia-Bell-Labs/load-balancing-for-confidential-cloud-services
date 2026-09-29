#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Line counts behind the code-size statements in the paper. They cover the Pebble CA patch and the Janus system itself.
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; cd "$ROOT"
echo "Pebble CA patch (ca/pebble-janus.patch): $(wc -l < ca/pebble-janus.patch) lines total. Per file:"
grep -E "^\+\+\+ b/" ca/pebble-janus.patch | sed 's|+++ b/||' | while read f; do printf "   %-45s %s\n" "$f" "$(awk -v f="$f" '/^\+\+\+ b\//{cur=$0; sub(/^\+\+\+ b\//,"",cur)} /^\+[^+]/ && cur==f {n++} END{print n+0}' ca/pebble-janus.patch) added lines"; done
echo "Janus system (janus/, without the tests and without the dependencies of the browser extension):"
for d in janus/frontend janus/backend janus/common janus/client/native janus/client/browser_extension/src; do printf "   %-40s %6s lines (%s)\n" "$d" "$(find $d -type f \( -name '*.py' -o -name '*.c' -o -name '*.js' \) -not -path '*/node_modules/*' -not -path '*/boringssl/*' -not -path '*/pebble/*' -not -path '*/ratls-external/*' -not -path '*/python-ratls/*' -exec cat {} + | wc -l)" "$(find $d -type f \( -name '*.py' -o -name '*.c' -o -name '*.js' \) -not -path '*/node_modules/*' -not -path '*/boringssl/*' -not -path '*/pebble/*' -not -path '*/ratls-external/*' -not -path '*/python-ratls/*' | wc -l) files"; done
