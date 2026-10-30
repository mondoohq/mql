#!/usr/bin/env bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Runs the clickhouse provider integration tests end to end: starts a throwaway
# ClickHouse container with SQL-driven access management, loads testdata/seed.sql,
# runs the env-gated integration tests against it, and tears the container down.
#
# Usage:
#   providers/clickhousedb/resources/testdata/integration.sh
#
# The container password is generated at runtime (nothing sensitive is committed).
# Override the image or port with CLICKHOUSE_IMAGE / CLICKHOUSE_PORT.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# HERE is providers/clickhousedb/resources/testdata; the provider dir is two up.
PROVIDER_DIR="$(cd "$HERE/../.." && pwd)"
IMAGE="${CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:latest}"
PORT="${CLICKHOUSE_PORT:-9000}"
NAME="clickhouse-integration-$$"
PASSWORD="$(openssl rand -hex 16)"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> starting $IMAGE as $NAME on :$PORT"
docker run -d --name "$NAME" -p "$PORT:9000" \
	-e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
	-e CLICKHOUSE_PASSWORD="$PASSWORD" \
	"$IMAGE" >/dev/null

echo "==> waiting for ClickHouse to accept queries"
for _ in $(seq 1 60); do
	if docker exec "$NAME" clickhouse-client --query "SELECT 1" >/dev/null 2>&1; then
		ready=1
		break
	fi
	sleep 2
done
if [ "${ready:-}" != "1" ]; then
	echo "ClickHouse did not become ready in time" >&2
	docker logs "$NAME" 2>&1 | tail -20 >&2
	exit 1
fi

echo "==> loading seed fixtures"
docker exec -i "$NAME" clickhouse-client --password "$PASSWORD" --multiquery < "$HERE/seed.sql"

echo "==> running integration tests"
cd "$PROVIDER_DIR"
CGO_ENABLED=0 \
	CLICKHOUSE_TEST_HOST="127.0.0.1:$PORT" \
	CLICKHOUSE_TEST_USER="default" \
	CLICKHOUSE_TEST_PASSWORD="$PASSWORD" \
	CLICKHOUSE_TEST_SEEDED=1 \
	go test ./resources/ -run TestIntegration -count=1 -v

echo "==> done"
