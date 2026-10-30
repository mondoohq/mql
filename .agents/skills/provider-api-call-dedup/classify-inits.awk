# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Sorts a provider's resource init functions by whether they call the API.
#
#   awk -f classify-inits.awk providers/<name>/resources/*.go | sort
#
# Output: <bucket>\t<file>:<line>\t<func>
#
#   ARGS-ONLY  fills args and returns; no I/O. Fine as-is.
#   FROM-LIST  reads a parent resource's list accessor. The target state.
#   API-CALL   builds a client and fetches one resource itself. Candidate for
#              migration -- costs one call per asset of that type.
#   API+LIST   does both; read it by hand, it is usually a partial migration.
#
# BLIND SPOT: this reads init functions only. A typed-reference accessor that
# builds a client and fetches inline never calls NewResource, never enters an
# init, and so does not appear here at all. An audit that runs only this script
# will look complete while missing them: aws has 41 such accessors, azure 38,
# github 16, ms365 14, gcp 10, k8s none. Enumerate them with the companion
# script, classify-accessors.awk, and split the result by fan-in: most are
# owned sub-objects with exactly one parent and nothing to dedupe.
#
# The buckets are a triage heuristic, not a verdict: confirm by reading the
# function before migrating it. In particular, an API-CALL init that is not a
# discovery target is reached through typed accessors rather than once per
# asset, so it is much cheaper than one that is.

/^func init[A-Z]/ {
  inFunc = 1
  name = $2
  sub(/\(.*/, "", name)
  start = FNR
  body = ""
  next
}

inFunc && /^}/ {
  # builds a client, or reads a single record, or walks a pager
  api = (body ~ /New[A-Za-z]*Client\(/) || (body ~ /\.Get\(ctx/) || (body ~ /NextPage\(/)
  # calls a generated list accessor on a parent resource, e.g. GetVms()
  lst = (body ~ /\.Get[A-Z][A-Za-z]*\(\)/)

  if (api && lst)       bucket = "API+LIST"
  else if (api)         bucket = "API-CALL"
  else if (lst)         bucket = "FROM-LIST"
  else                  bucket = "ARGS-ONLY"

  printf "%s\t%s:%d\t%s\n", bucket, FILENAME, start, name
  inFunc = 0
  next
}

inFunc { body = body "\n" $0 }
