#!/usr/bin/env bash
# Runs the Greenbone push once a week at a fixed local day and time, for machines
# with neither systemd nor cron (most containers). deploy.sh starts it in the
# background there; on a normal server it installs a systemd timer instead.
#
# Usage: push_weekly.sh DAY HH:MM COMMAND...
#   push_weekly.sh Sun 06:00 .venv/bin/python gvm_siem_push.py --env-file .env
set -uo pipefail

usage="usage: push_weekly.sh DAY HH:MM COMMAND...   (DAY: Mon, Tue, ... Sun)"
day="${1:?$usage}"
at="${2:?$usage}"
shift 2
[[ "${day,,}" =~ ^(mon|tue|wed|thu|fri|sat|sun) ]] || { echo "Day must be Mon..Sun (got: $day)" >&2; exit 2; }
[[ "$at" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || { echo "Time must be HH:MM (got: $at)" >&2; exit 2; }
(( $# )) || { echo "$usage" >&2; exit 2; }

stamp() { date '+%Y-%m-%d %H:%M:%S'; }

while true; do
  now="$(date +%s)"
  # "sun 06:00" is this coming Sunday, or today if it is Sunday.
  next="$(date -d "$day $at" +%s)"
  (( next <= now )) && next="$(date -d "next $day $at" +%s)"
  echo "$(stamp) [INFO] Next Greenbone push at $(date -d "@$next" '+%a %Y-%m-%d %H:%M')"
  sleep $(( next - now ))
  echo "$(stamp) [INFO] Starting the weekly Greenbone push"
  if "$@"; then
    echo "$(stamp) [INFO] Push finished"
  else
    echo "$(stamp) [ERROR] Push failed (exit $?); the next run retries it in full"
  fi
done
