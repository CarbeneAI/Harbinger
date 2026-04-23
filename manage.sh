#!/bin/bash
# Harbinger Threat Intelligence Platform
# Manages both server (Bun) and client (Vite) processes

DASHBOARD_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${HOME}/.harbinger/logs"
mkdir -p "$LOG_DIR"

SERVER_PID_FILE="/tmp/harbinger-server.pid"
CLIENT_PID_FILE="/tmp/harbinger-client.pid"

start() {
  echo "Starting Harbinger..."

  # Start server
  cd "$DASHBOARD_DIR/apps/server"
  bun run dev >> "$LOG_DIR/server.log" 2>&1 &
  echo $! > "$SERVER_PID_FILE"
  echo "  Server PID: $(cat $SERVER_PID_FILE)"

  # Wait for server
  for i in {1..15}; do
    curl -s http://localhost:4001/health >/dev/null 2>&1 && break
    sleep 1
  done

  # Start client
  cd "$DASHBOARD_DIR/apps/client"
  ./node_modules/.bin/vite --port 5174 --host 0.0.0.0 >> "$LOG_DIR/client.log" 2>&1 &
  echo $! > "$CLIENT_PID_FILE"
  echo "  Client PID: $(cat $CLIENT_PID_FILE)"

  echo ""
  echo "Harbinger is running:"
  echo "  Dashboard: http://localhost:5174"
  echo "  API:       http://localhost:4001"
  echo "  Health:    http://localhost:4001/health"
}

stop() {
  echo "Stopping Harbinger..."
  for pid_file in "$SERVER_PID_FILE" "$CLIENT_PID_FILE"; do
    if [ -f "$pid_file" ]; then
      pid=$(cat "$pid_file")
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        echo "  Stopped PID $pid"
      fi
      rm -f "$pid_file"
    fi
  done
  # Clean up any stragglers
  pkill -f "harbinger.*server" 2>/dev/null
  pkill -f "vite.*5174" 2>/dev/null
  echo "Done."
}

status() {
  local running=0
  for pid_file in "$SERVER_PID_FILE" "$CLIENT_PID_FILE"; do
    if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      running=$((running + 1))
    fi
  done
  if [ "$running" -eq 2 ]; then
    echo "Harbinger is running (server + client)"
    curl -s http://localhost:4001/health | python3 -m json.tool 2>/dev/null
  elif [ "$running" -gt 0 ]; then
    echo "Harbinger is partially running ($running/2 processes)"
  else
    echo "Harbinger is stopped"
  fi
}

logs() {
  echo "=== Server Log (last 30 lines) ==="
  tail -30 "$LOG_DIR/server.log" 2>/dev/null || echo "No server logs"
  echo ""
  echo "=== Client Log (last 10 lines) ==="
  tail -10 "$LOG_DIR/client.log" 2>/dev/null || echo "No client logs"
}

case "${1:-}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 1; start ;;
  status)  status ;;
  logs)    logs ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
