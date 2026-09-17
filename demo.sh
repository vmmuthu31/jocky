#!/usr/bin/env bash
# JOCKY Demo Launcher — builds compiler, starts server, opens dashboard,
# then runs a showcase compile + approve + verify sequence.
# Usage: ./demo.sh [--port 8080] [--no-browser]

set -euo pipefail

PORT=8080
OPEN_BROWSER=1
for arg in "$@"; do
  case "$arg" in
    --port) shift; PORT="$1" ;;
    --no-browser) OPEN_BROWSER=0 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPILER="$ROOT/compiler"
SERVER="$ROOT/server"
COMPILER_BIN="$COMPILER/target/release/jocky-compile"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  JOCKY Digital Forensics Platform — Demo Launcher   ║"
echo "║  NTRO Hackathon 26148 (Smart India Hackathon)        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Build compiler ────────────────────────────────────────────────────
echo "[1/4] Building Rust compiler (release)…"
(cd "$COMPILER" && cargo build --release --quiet 2>&1) || {
  echo "  ERROR: cargo build failed. Ensure Rust toolchain is installed (rustup)."
  exit 1
}
echo "  ✓ Compiler built: $COMPILER_BIN"

# ── Step 2: Dry-run smoke test ────────────────────────────────────────────────
echo ""
echo "[2/4] Compiler dry-run smoke test…"
JOCKY_ALLOW_DEV_KEY=1 "$COMPILER_BIN" run \
  --target linux \
  --dry-run \
  "$ROOT/examples/forensic_investigation.jocky" 2>&1 | sed 's/^/  /'
echo "  ✓ Smoke test complete"


# ── Step 3: Start Go server ───────────────────────────────────────────────────
echo ""
echo "[3/4] Starting JOCKY server on port $PORT…"
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo ""
    echo "Stopping server (PID $SERVER_PID)…"
    kill "$SERVER_PID"
  fi
}
trap cleanup EXIT INT TERM

(
  cd "$SERVER"
  JOCKY_ALLOW_DEV_KEY=1 \
  JOCKY_COMPILER_PATH="$COMPILER_BIN" \
  JOCKY_WEB_DIR="$ROOT/web" \
    go run . --port "$PORT" &
  echo $! > /tmp/jocky_server.pid
)
sleep 2
SERVER_PID=$(cat /tmp/jocky_server.pid 2>/dev/null || echo "")
rm -f /tmp/jocky_server.pid

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "  ERROR: Server failed to start. Check logs above."
  exit 1
fi
echo "  ✓ Server running (PID $SERVER_PID) → http://localhost:$PORT/dashboard/"

# ── Step 4: Open browser ──────────────────────────────────────────────────────
if [ "$OPEN_BROWSER" -eq 1 ]; then
  echo ""
  echo "[4/4] Opening dashboard in browser…"
  sleep 1
  if command -v open &>/dev/null; then
    open "http://localhost:$PORT/dashboard/"
  elif command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:$PORT/dashboard/"
  fi
  echo "  ✓ Dashboard: http://localhost:$PORT/dashboard/"
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo " JOCKY is running. Press Ctrl+C to stop."
echo " Dashboard → http://localhost:$PORT/dashboard/"
echo "══════════════════════════════════════════════════════"

# Keep running until Ctrl+C
wait "$SERVER_PID" 2>/dev/null || true
