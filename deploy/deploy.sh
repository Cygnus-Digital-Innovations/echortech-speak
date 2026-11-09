#!/usr/bin/env bash
# Builds and restarts the Say It container on the shared server.
# Uses a named volume, so the database survives every deploy.
set -euo pipefail

SERVER="${SERVER:-health-monitor}"
cd "$(dirname "$0")/.."

git archive --format=tar HEAD | ssh "$SERVER" 'set -e
  rm -rf ~/echortech-speak-build
  mkdir -p ~/echortech-speak-build
  tar -xf - -C ~/echortech-speak-build
  cd ~/echortech-speak-build
  sudo docker build -q -t echortech-speak:latest .
  sudo docker rm -f echortech-speak >/dev/null 2>&1 || true
  sudo docker run -d --name echortech-speak --restart unless-stopped \
    -p 127.0.0.1:3200:3000 \
    -v echortech-speak-data:/data \
    --env-file "$HOME/.sayit.env" \
    --memory 256m \
    echortech-speak:latest
  sleep 4
  if ! curl -fsS -o /dev/null http://127.0.0.1:3200/; then
    echo "Say It failed to start"
    sudo docker logs --tail 20 echortech-speak
    exit 1
  fi
  rm -rf ~/echortech-speak-build
  sudo docker image prune -f >/dev/null'
