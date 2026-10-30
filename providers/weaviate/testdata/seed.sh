#!/usr/bin/env bash
# Seed fixtures for the weaviate provider integration test.
#
# Usage: WEAVIATE_URL=http://localhost:8085 WEAVIATE_KEY=root-user-key ./seed.sh
set -euo pipefail

URL="${WEAVIATE_URL:-http://localhost:8085}"
KEY="${WEAVIATE_KEY:-root-user-key}"
auth=(-H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json")

# A collection with multi-tenancy enabled and auto-tenant-creation on (which
# weakens tenant isolation, a posture signal worth auditing).
curl -sf "${auth[@]}" -X POST "${URL}/v1/schema" -d '{
  "class": "Article",
  "description": "News articles",
  "vectorizer": "none",
  "multiTenancyConfig": { "enabled": true, "autoTenantCreation": true },
  "replicationConfig": { "factor": 1 }
}' >/dev/null

# A custom role scoped to read the Article collection and its data.
curl -sf "${auth[@]}" -X POST "${URL}/v1/authz/roles" -d '{
  "name": "articleReader",
  "permissions": [
    { "action": "read_collections", "collections": { "collection": "Article" } },
    { "action": "read_data", "data": { "collection": "Article" } }
  ]
}' >/dev/null

# Assign the custom role to the built-in viewer user so assignedUsers is testable.
curl -sf "${auth[@]}" -X POST "${URL}/v1/authz/users/viewer-user/assign" -d '{
  "roles": ["articleReader"]
}' >/dev/null

echo "seed complete"
