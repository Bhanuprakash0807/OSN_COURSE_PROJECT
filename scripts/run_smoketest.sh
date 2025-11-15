#!/usr/bin/env bash
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Kill previous processes if any
pkill -f nameserver || true
pkill -f storageserver || true
sleep 0.2

# Build
echo "Building..."
make clean && make all

# Start nameserver
NS_PORT=8000
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
./nameserver $NS_PORT > "$LOG_DIR/nameserver.log" 2>&1 &
NS_PID=$!
sleep 0.5

echo "Started nameserver PID=$NS_PID"

# Wait for port to be listening (5s timeout)
for i in {1..10}; do
  if ss -ltnp | grep -q ":$NS_PORT "; then
    echo "nameserver listening on port $NS_PORT"
    break
  fi
  sleep 0.5
done

# Simple client registration test (non-interactive)
printf "smoketest_user\nexit\n" | ./client 127.0.0.1 $NS_PORT > "$LOG_DIR/client_out.txt" 2>&1 || true

echo "Client output:"
cat "$LOG_DIR/client_out.txt"

# Show recent nameserver log
echo
echo "---- nameserver.log (last 200 lines) ----"
tail -n 200 "$LOG_DIR/nameserver.log" || true

# Clean up
kill $NS_PID || true
wait $NS_PID 2>/dev/null || true

echo "Smoke test finished."