#!/usr/bin/env bash
# Seed fixtures for the opensearch provider integration test.
#
# All credentials come from the environment so no secrets are committed:
#   OS_URL           cluster URL (default https://localhost:9250)
#   OS_USER          admin user (default admin)
#   OS_PASSWORD      admin password (required)
#   OS_APP_PASSWORD  password for the seeded appuser (required)
#
# Usage: OS_PASSWORD=... OS_APP_PASSWORD=... ./seed.sh
set -euo pipefail

URL="${OS_URL:-https://localhost:9250}"
USER="${OS_USER:-admin}"
PASS="${OS_PASSWORD:?set OS_PASSWORD}"
APP_PASS="${OS_APP_PASSWORD:?set OS_APP_PASSWORD}"
# -k: the default OpenSearch demo certificate is self-signed.
auth=(-sk -u "${USER}:${PASS}" -H "Content-Type: application/json")

# A custom role scoped to read a log index pattern (a least-privilege posture
# to audit against the broad built-in all_access role).
curl "${auth[@]}" -X PUT "${URL}/_plugins/_security/api/roles/readers" -d '{
  "cluster_permissions": ["cluster_monitor"],
  "index_permissions": [{
    "index_patterns": ["logs-*"],
    "allowed_actions": ["read"]
  }]
}' >/dev/null

# An internal user holding the custom role. The password comes from the
# environment so no credential is committed.
curl "${auth[@]}" -X PUT "${URL}/_plugins/_security/api/internalusers/appuser" \
  -d '{"password":"'"${APP_PASS}"'","backend_roles":[],"description":"App user"}' >/dev/null

# Map the internal user to the custom role.
curl "${auth[@]}" -X PUT "${URL}/_plugins/_security/api/rolesmapping/readers" \
  -d '{"users":["appuser"]}' >/dev/null

echo "seed complete"
