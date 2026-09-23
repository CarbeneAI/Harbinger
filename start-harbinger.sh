#!/usr/bin/env bash
# Foreground launcher for Harbinger (server + client) under systemd.
# systemd Type=simple tracks this PID; KillMode=control-group reaps both children.
set -uo pipefail
DIR=/home/cgarrison/Dev/Harbinger
set -a
[ -f "$DIR/.env" ] && . "$DIR/.env"
set +a
PORT="${PORT:-4004}"
CLIENT_PORT="${CLIENT_PORT:-5175}"
export PATH="/home/cgarrison/.bun/bin:$PATH"

cd "$DIR/apps/server"
bun run dev &

cd "$DIR/apps/client"
bun ./node_modules/.bin/vite --port "$CLIENT_PORT" --host 0.0.0.0 &

# Exit (and let systemd restart) if either process dies.
wait -n
