#!/usr/bin/env bash
# Seed fixtures for the elasticsearch provider integration test.
#
# All credentials are taken from the environment so no secrets are committed:
#   ES_URL           cluster URL (default http://localhost:9200)
#   ES_USER          admin user (default elastic)
#   ES_PASSWORD      admin password (required)
#   ES_APP_PASSWORD  password for the seeded appuser (required)
#
# Usage: ES_PASSWORD=... ES_APP_PASSWORD=... ./seed.sh
set -euo pipefail

URL="${ES_URL:-http://localhost:9200}"
USER="${ES_USER:-elastic}"
PASS="${ES_PASSWORD:?set ES_PASSWORD}"
APP_PASS="${ES_APP_PASSWORD:?set ES_APP_PASSWORD}"
auth=(-u "${USER}:${PASS}" -H "Content-Type: application/json")

# A custom role scoped to read a log index pattern (a least-privilege posture
# to audit against the broad built-in roles). Field- and document-level
# security are a licensed feature, so they are not set here; the schema still
# exposes hasFieldSecurity/hasDocumentSecurity for clusters that use them.
curl -sf "${auth[@]}" -X PUT "${URL}/_security/role/reader" -d '{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["logs-*"],
    "privileges": ["read"]
  }]
}' >/dev/null

# A native user holding the custom role. The password comes from the
# environment so no credential is committed.
curl -sf "${auth[@]}" -X PUT "${URL}/_security/user/appuser" \
  -d '{"password":"'"${APP_PASS}"'","roles":["reader"],"full_name":"App User"}' >/dev/null

# An API key with an expiration set (a key without one never expires, a finding).
curl -sf "${auth[@]}" -X POST "${URL}/_security/api_key" -d '{
  "name": "ci-key",
  "expiration": "1d"
}' >/dev/null

echo "seed complete"
