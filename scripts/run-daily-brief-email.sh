#!/bin/bash
# Wrapper for the SendDailyBrief.ts cron job + chained morning IOC hunt.
# Loads PAI env + Harbinger env, ensures Bun is on PATH, then:
#  1. Sends the daily threat brief email
#  2. Runs the Wazuh IOC hunt against the brief contents
#  3. Notifies ntfy + email with hunt result (CLEAN or HITS)
# Brief failure aborts the chain. Hunt failure logs but does NOT abort,
# because the user-visible brief has already shipped.
#
# 2026-07-31 ALERTING REWRITE.
# This wrapper used to notify only on SUCCESS and exit silently on failure.
# That is how the 2026-07-25 -> 07-31 outage stayed invisible for seven days:
# the API credit balance hit $0, every run failed, and nothing ever said so.
# Clint found it by noticing an absence. Rules now:
#   - FAILURE is loud (high priority) and carries a diagnosis, not just an rc.
#   - SUCCESS is quiet (low priority) so a failure actually stands out.
#   - "Sent" is not trusted on its own; the archived brief is size-checked.
# A silent green is worse than a red. See also: watchdog-brief-freshness.sh,
# which catches the case where this script never runs at all.
set -uo pipefail
export PATH=/home/cgarrison/.bun/bin:$PATH
PAI_ENV=/home/cgarrison/PAI/.claude/.env
HARBINGER_ENV=/home/cgarrison/Dev/Harbinger/.env
[ -f "$PAI_ENV" ] && set -a && . "$PAI_ENV" && set +a
[ -f "$HARBINGER_ENV" ] && set -a && . "$HARBINGER_ENV" && set +a
mkdir -p /home/cgarrison/.harbinger/logs

NOTIFY=/home/cgarrison/scripts/notify.sh

# Best-effort alert. A notification failure must never mask the real error.
alert() {
  local title="$1" msg="$2" prio="${3:-high}" tags="${4:-rotating_light}"
  [ -x "$NOTIFY" ] && "$NOTIFY" -t briefs -T "$title" -p "$prio" -g "$tags" "$msg" \
    >/dev/null 2>&1 || true
}

# Map a raw error tail onto something actionable at 7am.
diagnose() {
  case "$1" in
    *"credit balance"*|*"Credit balance"*)
      echo "Hit the metered Anthropic API instead of the Claude Max subscription. Briefs run BRIEF_PROVIDER=claude via the CLI on the Studio, which bills no credits. An ANTHROPIC_API_KEY leaking into the remote env is the usual cause. Do NOT buy credits." ;;
    *"timed out"*|*"timeout"*|*"AbortError"*)
      echo "Generation timed out. Check Ollama: 'systemctl status ollama' and 'ollama ps' on DellAI." ;;
    *"ECONNREFUSED"*|*"fetch failed"*|*"Unable to connect"*)
      echo "Harbinger API unreachable on :4004. Run 'systemctl --user status harbinger' HERE on srv-apps (Harbinger moved off DellAI 2026-09-22)." ;;
    *"is Ollama running"*)
      echo "Ollama is down or the model is missing. Run 'ollama ps' and 'ollama list' on DellAI." ;;
    *"Claude CLI"*|*"BatchMode"*|*"Host key"*|*"Permission denied (publickey"*)
      echo "ssh to the Studio failed, so the Claude CLI could not run. Check the Studio is awake and on Tailscale, then: ssh cgarrison@100.73.131.1 true" ;;
    *"invalid_grant"*|*"oauth"*|*"OAuth"*|*"401"*)
      echo "Gmail OAuth rejected. Re-auth the EmailManager workspace token." ;;
    *"No IOCs"*)
      echo "No IOCs in the 24h window. Feeds may have stopped: curl localhost:4004/health HERE on srv-apps and check iocCount." ;;
    *)
      echo "See /home/cgarrison/.harbinger/logs/daily-brief-email.log" ;;
  esac
}

# Hunt-path diagnosis. Deliberately NOT folded into diagnose(): there,
# "Unable to connect" maps to the Harbinger API on :4004, which is the wrong
# answer for a hunt failure. Same string, different subsystem.
diagnose_hunt() {
  case "$1" in
    *192.168.2.76*|*console/proxy*|*ConnectionRefused*|*ECONNREFUSED*|*"Unable to connect"*)
      echo "Wazuh SIEM host (192.168.2.76 / Wazuh-EQ) is unreachable. Check the box is powered on, then wazuh-indexer + wazuh-dashboard." ;;
    *WAZUH_DASHBOARD_PASSWORD*)
      echo "WAZUH_DASHBOARD_PASSWORD missing from /home/cgarrison/PAI/.claude/.env." ;;
    *"wrote no report"*)
      echo "Hunt exited clean but produced no report. That is a hunt bug, not a SIEM outage." ;;
    *circuit_breaking_exception*|*heap*)
      echo "Indexer heap circuit breaker tripped. Too many IOCs in one query: chunk the pack." ;;
    *ENOENT*)
      echo "A stage is missing an input file. Look at the stage ABOVE it, not this one." ;;
    *)
      echo "See /home/cgarrison/.harbinger/logs/daily-brief-email.log" ;;
  esac
}

# ---- 1. brief -------------------------------------------------------------
OUT="$(mktemp)"
RC=0
bun /home/cgarrison/PAI/.claude/skills/EmailManager/tools/SendDailyBrief.ts \
  > "$OUT" 2>&1 || RC=$?
cat "$OUT"

if [ "$RC" -ne 0 ]; then
  TAIL="$(tail -c 500 "$OUT" | tr '\n' ' ')"
  alert "DOWN - Daily Threat Brief" \
        "Brief did NOT send (rc=$RC). $(diagnose "$TAIL")" high rotating_light
  rm -f "$OUT"
  exit "$RC"
fi
rm -f "$OUT"

# ---- 1b. trust but verify -------------------------------------------------
# The sender reporting success is not proof the brief had content. Check the
# archive it just wrote. A healthy brief runs 8k-24k chars depending on model.
TODAY="$(date +%F)"
ARCHIVE="/home/cgarrison/.harbinger/briefs/${TODAY}.md"
if [ ! -s "$ARCHIVE" ]; then
  alert "Daily Threat Brief - archive missing" \
        "Sender reported success but ${ARCHIVE} is missing or empty. Brief may have shipped empty." high warning
elif [ "$(wc -c < "$ARCHIVE")" -lt 2000 ]; then
  alert "Daily Threat Brief - suspiciously short" \
        "Brief archived at only $(wc -c < "$ARCHIVE") bytes (expected 8000+). Model may have truncated." high warning
else
  alert "Daily Threat Brief sent" \
        "Sent OK ($(wc -c < "$ARCHIVE") bytes). Wazuh IOC hunt running." low white_check_mark
fi

# ---- 2. chained IOC hunt (non-fatal) --------------------------------------
HOUT="$(mktemp)"
HRC=0
bun /home/cgarrison/PAI/.claude/skills/WazuhDashboard/tools/RunMorningHunt.ts --days 365 \
  > "$HOUT" 2>&1 || HRC=$?
cat "$HOUT"
if [ "$HRC" -ne 0 ]; then
  echo "[$(date -Iseconds)] morning-hunt FAILED (brief already sent; hunt error above)"
  # The LAST 300 bytes is almost always the innermost stack trace of a
  # downstream VICTIM, not the cause. On 2026-08-21 that shipped an alert
  # blaming a missing hunt-report.md when the real fault was a dead SIEM.
  # Prefer the orchestrator FATAL line, then the first failure line, then tail.
  CAUSE="$(grep -m1 -F '[morning-hunt] FATAL:' "$HOUT" | cut -c1-300)"
  [ -z "$CAUSE" ] && CAUSE="$(grep -m1 -E 'FAILED:|Error:|error:' "$HOUT" | cut -c1-300)"
  [ -z "$CAUSE" ] && CAUSE="$(tail -c 300 "$HOUT" | tr '\n' ' ')"
  alert "IOC hunt failed" \
        "Daily brief shipped, but the Wazuh IOC hunt failed (rc=$HRC). $CAUSE $(diagnose_hunt "$CAUSE")" default warning
fi
rm -f "$HOUT"
