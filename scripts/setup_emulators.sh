#!/usr/bin/env bash
set -euo pipefail

# Simple local emulator launcher for Redis and Firestore
# - Prefers Homebrew services for Redis, falls back to Docker if not installed
# - Prefers gcloud beta emulators for Firestore, falls back to Firebase CLI if available

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
LOG_DIR="$ROOT_DIR/server/logs"
mkdir -p "$LOG_DIR"

# Defaults
: "${GOOGLE_CLOUD_PROJECT:=local-dev}"
: "${EMULATOR_REDIS_URL:=redis://127.0.0.1:6379}"
: "${FIRESTORE_EMULATOR_HOST:=127.0.0.1:8080}"

export USE_EMULATORS=1
export GOOGLE_CLOUD_PROJECT
export EMULATOR_REDIS_URL
export FIRESTORE_EMULATOR_HOST

echo "[setup] USE_EMULATORS=$USE_EMULATORS"
echo "[setup] GOOGLE_CLOUD_PROJECT=$GOOGLE_CLOUD_PROJECT"
echo "[setup] EMULATOR_REDIS_URL=$EMULATOR_REDIS_URL"
echo "[setup] FIRESTORE_EMULATOR_HOST=$FIRESTORE_EMULATOR_HOST"

start_redis() {
  echo "[redis] starting..."
  if command -v brew >/dev/null 2>&1; then
    if brew list --formula | grep -q '^redis$'; then
      brew services start redis >/dev/null 2>&1 || true
    else
      echo "[redis] Homebrew installed but redis not found; attempting temporary launch"
      if command -v redis-server >/dev/null 2>&1; then
        redis-server --daemonize yes >>"$LOG_DIR/redis.log" 2>&1 || true
      fi
    fi
  elif command -v docker >/dev/null 2>&1; then
    docker run -d --name bas-redis -p 6379:6379 redis:7-alpine >/dev/null 2>&1 || true
  else
    echo "[redis] WARNING: neither Homebrew nor Docker found; ensure redis is running at $EMULATOR_REDIS_URL"
  fi

  # Health check
  if command -v redis-cli >/dev/null 2>&1; then
    for i in {1..10}; do
      if redis-cli -u "$EMULATOR_REDIS_URL" PING >/dev/null 2>&1; then
        echo "[redis] ready"
        return 0
      fi
      sleep 0.5
    done
    echo "[redis] WARNING: ping failed; continuing"
  fi
}

start_firestore() {
  echo "[firestore] starting emulator..."
  if command -v gcloud >/dev/null 2>&1; then
    (gcloud beta emulators firestore start --host-port="$FIRESTORE_EMULATOR_HOST" \
      --project="$GOOGLE_CLOUD_PROJECT" >>"$LOG_DIR/firestore-emulator.log" 2>&1 &)
  elif command -v firebase >/dev/null 2>&1; then
    (firebase emulators:start --only firestore --project "$GOOGLE_CLOUD_PROJECT" \
      --host $(echo "$FIRESTORE_EMULATOR_HOST" | cut -d: -f1) \
      --port $(echo "$FIRESTORE_EMULATOR_HOST" | cut -d: -f2) >>"$LOG_DIR/firestore-emulator.log" 2>&1 &)
  else
    echo "[firestore] WARNING: neither gcloud nor firebase CLI found; ensure emulator running at $FIRESTORE_EMULATOR_HOST"
    return 0
  fi

  # Health probe
  for i in {1..20}; do
    if curl -s "http://$FIRESTORE_EMULATOR_HOST" >/dev/null 2>&1; then
      echo "[firestore] emulator ready"
      return 0
    fi
    sleep 0.5
  done
  echo "[firestore] WARNING: health probe failed; continuing"
}

start_redis
start_firestore

echo "[setup] emulators launched. Environment exported for current shell."
echo "[setup] logs: $LOG_DIR"


