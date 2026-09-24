#!/bin/bash
# watchdog-brief-freshness.sh â independent staleness check for Harbinger briefs.
#
# WHY THIS EXISTS, SEPARATELY FROM THE WRAPPERS.
# The wrappers alert when a run FAILS. They cannot alert when a run never
# HAPPENS: cron disabled, machine rebooted, systemd user session not lingering,
# crontab edited badly, wrapper killed. That is a real gap, and the 2026-07-25
# outage proved the cost of an absence nobody is watching for.
# This runs on its own schedule and asserts one thing: a fresh brief exists.
#
# Runs 08:30 daily (90 min after the 07:00 daily brief, which takes ~10 min).
# On Mondays it also checks the weekly, which fires at 08:00.
set -uo pipefail

NOTIFY=/home/cgarrison/scripts/notify.sh
BRIEFS=/home/cgarrison/.harbinger/briefs
WEEKLY=/home/cgarrison/.harbinger/weekly-briefs
MIN_DAILY_BYTES=2000
MIN_WEEKLY_BYTES=1500
# Daily threat-hunt brief retired 2026-08-21 (focus shift to CISO/Fractional).
# Cron passes DAILY_ENABLED=0 so the watchdog stops alerting on an absence we chose.
DAILY_ENABLED="${DAILY_ENABLED:-1}"

alert() {
  [ -x "$NOTIFY" ] && "$NOTIFY" -t briefs -T "$1" -p high -g rotating_light "$2" \
    >/dev/null 2>&1 || true
}

TODAY="$(date +%F)"
PROBLEMS=""

# ---- daily ----------------------------------------------------------------
if [ "$DAILY_ENABLED" = "1" ]; then
DAILY="$BRIEFS/${TODAY}.md"
if [ ! -f "$DAILY" ]; then
  # Name the most recent one we do have, so the alert says how far behind we are.
  LAST="$(ls -1 "$BRIEFS" 2>/dev/null | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}\.md$' | tail -1)"
  LAST="${LAST%.md}"
  if [ -n "$LAST" ]; then
    DAYS=$(( ( $(date +%s) - $(date -d "$LAST" +%s) ) / 86400 ))
    PROBLEMS="No brief for ${TODAY}. Last one is ${LAST} (${DAYS} days ago)."
  else
    PROBLEMS="No brief for ${TODAY} and no archived briefs at all."
  fi
elif [ "$(wc -c < "$DAILY")" -lt "$MIN_DAILY_BYTES" ]; then
  PROBLEMS="Brief for ${TODAY} is only $(wc -c < "$DAILY") bytes (expected ${MIN_DAILY_BYTES}+)."
fi
fi

# ---- weekly (Mondays only) ------------------------------------------------
if [ "$(date +%u)" = "1" ]; then
  W="$WEEKLY/${TODAY}.md"
  if [ ! -f "$W" ]; then
    PROBLEMS="${PROBLEMS} Weekly strategic brief for ${TODAY} is missing."
  elif [ "$(wc -c < "$W")" -lt "$MIN_WEEKLY_BYTES" ]; then
    PROBLEMS="${PROBLEMS} Weekly brief is only $(wc -c < "$W") bytes."
  fi
fi

# ---- report ---------------------------------------------------------------
if [ -n "$PROBLEMS" ]; then
  alert "Harbinger brief STALE" \
        "${PROBLEMS} Check: 'systemctl --user status harbinger', 'ollama ps', and /home/cgarrison/.harbinger/logs/daily-brief-email.log on DellAI."
  echo "[$(date -Iseconds)] WATCHDOG ALERT: ${PROBLEMS}"
  exit 1
fi

if [ "$DAILY_ENABLED" = "1" ]; then
  echo "[$(date -Iseconds)] watchdog OK: ${TODAY} brief present ($(wc -c < "$DAILY") bytes)"
else
  echo "[$(date -Iseconds)] watchdog OK: weekly checked, daily retired"
fi
