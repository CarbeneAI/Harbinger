#!/bin/bash
# Wrapper for the SendWeeklyStrategicBrief.ts cron job.
# Loads PAI env + Harbinger env, ensures Bun is on PATH, then sends
# the weekly strategic synthesis email. No chained hunt â weekly is
# trend/strategy, not tactical IOC scope.
#
# 2026-07-31: same alerting rewrite as the daily wrapper. This one failed
# silently on 2026-07-27 for the same $0-credit-balance reason and nothing
# said so. Failure is now loud, success is quiet.
set -uo pipefail
export PATH=/home/cgarrison/.bun/bin:$PATH
PAI_ENV=/home/cgarrison/PAI/.claude/.env
HARBINGER_ENV=/home/cgarrison/Dev/Harbinger/.env
[ -f "$PAI_ENV" ] && set -a && . "$PAI_ENV" && set +a
[ -f "$HARBINGER_ENV" ] && set -a && . "$HARBINGER_ENV" && set +a
mkdir -p /home/cgarrison/.harbinger/logs

# 2026-09-22 (DellAI -> srv-apps): Ollama did NOT move -- it stays on DellAI with
# the A5000. SendWeeklyStrategicBrief.ts defaults OLLAMA_URL to localhost:11434,
# which resolves to nothing on this host, so the Ollama fallback would fail with
# a connection error instead of generating. Point it at DellAI explicitly.
export OLLAMA_URL="${OLLAMA_URL:-http://192.168.2.81:11434}"
export HARBINGER_API="${HARBINGER_API:-http://localhost:4004}"

NOTIFY=/home/cgarrison/scripts/notify.sh

alert() {
  local title="$1" msg="$2" prio="${3:-high}" tags="${4:-rotating_light}"
  [ -x "$NOTIFY" ] && "$NOTIFY" -t briefs -T "$title" -p "$prio" -g "$tags" "$msg" \
    >/dev/null 2>&1 || true
}

diagnose() {
  case "$1" in
    *"credit balance"*|*"Credit balance"*)
      echo "Anthropic credits are exhausted. Weekly should be on local Ollama: check BRIEF_PROVIDER. Do NOT buy credits." ;;
    *"timed out"*|*"timeout"*|*"AbortError"*)
      echo "Generation timed out. Check Ollama on DellAI: 'systemctl status ollama'." ;;
    *"ECONNREFUSED"*|*"fetch failed"*)
      echo "Harbinger API unreachable on :4004. Run 'systemctl --user status harbinger'." ;;
    *)
      echo "See /home/cgarrison/.harbinger/logs/weekly-strategic-email.log" ;;
  esac
}

OUT="$(mktemp)"
RC=0
bun /home/cgarrison/PAI/.claude/skills/EmailManager/tools/SendWeeklyStrategicBrief.ts \
  > "$OUT" 2>&1 || RC=$?
cat "$OUT"

if [ "$RC" -ne 0 ]; then
  TAIL="$(tail -c 500 "$OUT" | tr '\n' ' ')"
  alert "DOWN - Weekly Strategic Brief" \
        "Weekly brief did NOT send (rc=$RC). $(diagnose "$TAIL")" high rotating_light
  rm -f "$OUT"
  exit "$RC"
fi
rm -f "$OUT"

LATEST="/home/cgarrison/.harbinger/latest-weekly-brief.md"
if [ ! -s "$LATEST" ] || [ "$(wc -c < "$LATEST")" -lt 1500 ]; then
  alert "Weekly Strategic Brief - suspiciously short" \
        "Weekly reported success but the archive is missing or under 1500 bytes." high warning
else
  alert "Weekly Strategic Brief sent" \
        "Sent OK ($(wc -c < "$LATEST") bytes)." low white_check_mark
fi
