#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

cleanup() {
    echo ""
    echo "=== Shutting down ==="
    kill $(jobs -p) 2>/dev/null || true
    wait $(jobs -p) 2>/dev/null || true
    docker compose -f docker-compose.ttp.yml --project-name ttp down 2>/dev/null || true
    docker compose -f docker-compose.server.yml --project-name server down 2>/dev/null || true
    echo "=== All services stopped ==="
}
trap cleanup EXIT INT TERM

# Ensure clean state — remove any leftover manually-created network
docker compose -f docker-compose.ttp.yml --project-name ttp down 2>/dev/null || true
docker compose -f docker-compose.server.yml --project-name server down 2>/dev/null || true
docker network rm secure-exchange-net 2>/dev/null || true

docker compose -f docker-compose.ttp.yml --project-name ttp up -d

echo "Waiting for TTP to be healthy..."
for i in $(seq 1 30); do
    if docker compose -f docker-compose.ttp.yml --project-name ttp ps | grep -q 'healthy'; then
        echo "TTP is ready."
        break
    fi
    sleep 1
done

docker compose -f docker-compose.server.yml --project-name server up -d

(docker compose -f docker-compose.ttp.yml --project-name ttp logs -f --tail=10 2>&1 | sed 's/^/  [TTP]  /') &
(docker compose -f docker-compose.server.yml --project-name server logs -f --tail=10 2>&1 | sed 's/^/[SERVER]  /') &

sleep 2

(go run ./cmd/user 2>&1 | sed 's/^/  [USER]  /') &

echo "=== All services running. Press Ctrl+C to stop. ==="
echo "    User web UI: http://localhost:9000"
echo "    MITM test:   go run ./cmd/mitm      (then click 'Symuluj atak MITM' in UI)"

wait
