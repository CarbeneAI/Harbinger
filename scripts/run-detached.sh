#!/bin/bash
# Run a long Harbinger job detached and report where the output landed.
#
# Why this exists
# ---------------
# srv-apps has no direct ssh; it is reached via
#   ssh prox 'qm guest exec 110 -- /bin/su - cgarrison -c "..."'
# `qm guest exec` enforces its own timeout and KILLS THE CHILD when it fires.
# Anything slower than ~1-2 minutes (weekly synthesis takes ~4) dies at the
# transport layer with an empty result, which looks exactly like an app hang.
# That cost two misdiagnosed runs on 2026-09-23.
#
# This wrapper detaches the work with nohup so the guest-exec timeout can only
# end the *observer*, never the job.
#
# Usage:
#   run-detached.sh weekly            # weekly strategic brief -> JSON
#   run-detached.sh daily             # daily brief -> JSON
#   run-detached.sh status            # check the last detached run
#   run-detached.sh <name> <curl-args...>   # arbitrary job
#
# Then poll:  run-detached.sh status
set -uo pipefail

API="${HARBINGER_API:-http://localhost:4004}"
OUTDIR="${HOME}/.harbinger/detached"
mkdir -p "$OUTDIR"

job="${1:-}"; shift || true

start() {
  local name="$1"; shift
  local out="$OUTDIR/${name}.json"
  local log="$OUTDIR/${name}.log"
  : > "$log"
  nohup curl -sS -m 1800 "$@" -o "$out" >> "$log" 2>&1 &
  local pid=$!
  echo "$pid" > "$OUTDIR/${name}.pid"
  echo "started: $name (pid $pid)"
  echo "  result: $out"
  echo "  log:    $log"
  echo "  poll:   $0 status"
}

case "$job" in
  weekly)
    start weekly -X POST "$API/briefs/weekly-strategic" \
      -H 'Content-Type: application/json' -d '{}'
    ;;
  daily)
    start daily -X POST "$API/briefs/daily" \
      -H 'Content-Type: application/json' -d '{}'
    ;;
  status)
    shopt -s nullglob
    found=0
    for pidfile in "$OUTDIR"/*.pid; do
      found=1
      name="$(basename "$pidfile" .pid)"
      pid="$(cat "$pidfile")"
      out="$OUTDIR/${name}.json"
      if kill -0 "$pid" 2>/dev/null; then
        echo "$name: RUNNING (pid $pid)"
      elif [ -s "$out" ]; then
        echo "$name: done — $(wc -c < "$out") bytes in $out"
        python3 - "$out" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print("  success:", d.get("success"))
    if d.get("error"):
        print("  error:", d["error"])
    c = d.get("content") or ""
    if c:
        print("  content:", len(c), "chars")
        print("  first line:", c.splitlines()[0][:90])
except Exception as e:
    print("  (not JSON:", e, ")")
PY
      else
        echo "$name: FAILED — no output. See $OUTDIR/${name}.log"
        tail -3 "$OUTDIR/${name}.log" 2>/dev/null | sed 's/^/    /'
      fi
    done
    [ "$found" -eq 0 ] && echo "no detached runs found in $OUTDIR"
    ;;
  "")
    echo "usage: $0 {weekly|daily|status|<name> <curl-args...>}" >&2
    exit 2
    ;;
  *)
    start "$job" "$@"
    ;;
esac
