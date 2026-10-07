#!/usr/bin/env bash
#
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# test-iam-permissions.sh — have each cloud itself accept the permission
# manifests, the way a customer's role or policy would.
#
# This is the second half of `make providers/permissions/check`. The first half,
# providers-sdk/v1/util/permissions/validate, asks each cloud's published list of
# permissions about every manifest entry. This script then hands the whole
# manifest to the cloud's own validator:
#
#   AWS    IAM Access Analyzer validates identity policies built from the
#          manifest (creates nothing).
#   GCP    a custom role is created from the manifest on a project (and, for
#          org_level_permissions, on an organization) and deleted again;
#          `gcloud iam roles create` refuses a permission IAM does not know.
#   Azure  a custom role is created from the manifest at a scope and deleted
#          again; Azure refuses an unregistered operation with
#          InvalidActionOrNotAction.
#
# Every command exits non-zero when the cloud rejects something, so the
# commands can gate. The manifests are read from the provider directories:
#   providers/aws/resources/aws.permissions.json
#   providers/gcp/resources/gcp.permissions.json   (permissions + org_level_permissions)
#   providers/azure/resources/azure.permissions.json
#
# Requirements: bash, jq, and the authenticated CLI of the cloud (aws / gcloud / az).
#
# Usage:
#   scripts/test-iam-permissions.sh aws-check               # Access Analyzer over the AWS manifest (creates nothing)
#   scripts/test-iam-permissions.sh aws-create              # create role mql-perms-test + managed policies
#   scripts/test-iam-permissions.sh aws-delete              # tear them down
#
#   GCP_PROJECT=<id> GCP_ORGANIZATION=<id> ...
#   scripts/test-iam-permissions.sh gcp-check               # create + delete the project and organization custom roles
#   scripts/test-iam-permissions.sh gcp-create              # create the project-level custom role
#   scripts/test-iam-permissions.sh gcp-create-org          # create the org-level custom role
#   scripts/test-iam-permissions.sh gcp-delete              # delete the project-level custom role
#   scripts/test-iam-permissions.sh gcp-delete-org          # delete the org-level custom role
#
#   scripts/test-iam-permissions.sh azure-check <SCOPE>     # create + delete a custom role from the manifest
#   scripts/test-iam-permissions.sh azure-create <SCOPE>    # create it (e.g. /subscriptions/<id>)
#   scripts/test-iam-permissions.sh azure-delete <SCOPE>    # delete it
#
set -euo pipefail

# Resolve repo root from this script's location so it runs from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

AWS_PERMS="$REPO_ROOT/providers/aws/resources/aws.permissions.json"
GCP_PERMS="$REPO_ROOT/providers/gcp/resources/gcp.permissions.json"
AZURE_PERMS="$REPO_ROOT/providers/azure/resources/azure.permissions.json"

AWS_ROLE="mql-perms-test"
AWS_POLICY_PREFIX="mql-readonly"
AWS_CHUNK=150          # actions per managed policy (keeps each under the 6,144-char limit)

GCP_ROLE_ID="mqlReadonlyCheck"
GCP_ORG_ROLE_ID="mqlReadonlyCheckOrg"

AZURE_ROLE_NAME="mql-readonly-check"

TMP="${TMPDIR:-/tmp}"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found in PATH"; }
manifest() { [[ -f "$1" ]] || die "missing $1"; }

# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

# Emit one policy JSON file per chunk; echoes the number of chunks written.
aws_build_policies() {
  need jq; manifest "$AWS_PERMS"
  local total chunk start n=0
  total=$(jq '.permissions | length' "$AWS_PERMS")
  chunk=$AWS_CHUNK
  rm -f "$TMP"/mql_aws_policy_*.json
  for start in $(seq 0 "$chunk" $((total - 1))); do
    n=$((n + 1))
    jq -c --argjson s "$start" --argjson c "$chunk" \
      '{Version:"2012-10-17",Statement:[{Sid:"mqlReadOnly",Effect:"Allow",Action:.permissions[$s:($s+$c)],Resource:"*"}]}' \
      "$AWS_PERMS" > "$TMP/mql_aws_policy_$n.json"
  done
  echo "$n"
}

# Validate every action with IAM Access Analyzer. Only ERROR findings count:
# an action IAM does not know is one (INVALID_ACTION). The warnings and
# suggestions the analyzer also emits (Resource "*", and so on) are about the
# policy's shape, not the manifest, and are not reported here.
aws_check() {
  need aws; need jq
  local count i findings total=0
  count=$(aws_build_policies)
  echo ">> Validating $(jq '.permissions | length' "$AWS_PERMS") actions in $count policies with IAM Access Analyzer (creates nothing) ..."
  for i in $(seq 1 "$count"); do
    findings=$(aws accessanalyzer validate-policy \
      --policy-type IDENTITY_POLICY \
      --policy-document "file://$TMP/mql_aws_policy_$i.json" \
      --query 'findings[?findingType==`ERROR`].[issueCode, findingDetails]' \
      --output text)
    if [[ -n "$findings" ]]; then
      echo "--- policy $i: Access Analyzer rejects"
      echo "$findings" | sed 's/^/   /'
      total=$((total + $(echo "$findings" | grep -c .)))
    fi
  done
  if [[ $total -gt 0 ]]; then
    die "$total ERROR finding(s): the AWS manifest names actions IAM does not know"
  fi
  echo ">> Access Analyzer accepted every action. ✓"
}

aws_create() {
  need aws
  local acct count i arn
  acct=$(aws sts get-caller-identity --query Account --output text)

  cat > "$TMP/mql-trust.json" <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"AWS":"arn:aws:iam::${acct}:root"},"Action":"sts:AssumeRole"}]}
JSON

  echo ">> Creating role $AWS_ROLE in account $acct ..."
  aws iam create-role --role-name "$AWS_ROLE" \
    --assume-role-policy-document "file://$TMP/mql-trust.json" >/dev/null

  count=$(aws_build_policies)
  echo ">> Attaching $count managed policies ..."
  for i in $(seq 1 "$count"); do
    arn=$(aws iam create-policy \
            --policy-name "${AWS_POLICY_PREFIX}-$i" \
            --policy-document "file://$TMP/mql_aws_policy_$i.json" \
            --query 'Policy.Arn' --output text)
    aws iam attach-role-policy --role-name "$AWS_ROLE" --policy-arn "$arn"
    echo "   attached $arn"
  done
  echo ">> Created role $AWS_ROLE with $count managed policies."
}

aws_delete() {
  need aws
  local acct count i arn
  acct=$(aws sts get-caller-identity --query Account --output text)
  # Recompute chunk count the same way create did, so we delete exactly what we made.
  count=$(aws_build_policies)
  echo ">> Detaching/deleting $count managed policies ..."
  for i in $(seq 1 "$count"); do
    arn="arn:aws:iam::${acct}:policy/${AWS_POLICY_PREFIX}-$i"
    aws iam detach-role-policy --role-name "$AWS_ROLE" --policy-arn "$arn" 2>/dev/null || true
    aws iam delete-policy --policy-arn "$arn" 2>/dev/null || true
  done
  echo ">> Deleting role $AWS_ROLE ..."
  aws iam delete-role --role-name "$AWS_ROLE" 2>/dev/null || true
  echo ">> AWS teardown complete."
}

# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------

gcp_project() { [[ -n "${GCP_PROJECT:-}" ]] || die "set GCP_PROJECT to the project to check against"; echo "$GCP_PROJECT"; }
gcp_organization() { [[ -n "${GCP_ORGANIZATION:-}" ]] || die "set GCP_ORGANIZATION to the organization to check against"; echo "$GCP_ORGANIZATION"; }

# $1 = jq filter selecting the permission array (.permissions or .org_level_permissions)
# $2 = output yaml path  ;  $3 = role title
gcp_build_role_yaml() {
  need jq; manifest "$GCP_PERMS"
  jq -r --arg title "$3" \
    "\"title: \" + \$title + \"\ndescription: Read-only permissions required by mql (permission manifest check)\nstage: GA\nincludedPermissions:\n\" + ($1 | map(\"- \" + .) | join(\"\n\"))" \
    "$GCP_PERMS" > "$2"
}

# Create the project-level custom role from every project-level permission.
# `gcloud iam roles create` is IAM's own validation: it refuses a permission IAM
# does not know, and one that is NOT_SUPPORTED in custom roles. The latter are
# real permissions no custom role can carry (today: domains.registrations.list),
# so they are left out of the role here and reported.
gcp_create() {
  need gcloud; need jq
  local project
  project=$(gcp_project)
  jq -r '.permissions[]' "$GCP_PERMS" > "$TMP/gcp_all.txt"
  echo ">> Fetching the project's testable permissions to leave out the NOT_SUPPORTED ones ..."
  gcloud iam list-testable-permissions "//cloudresourcemanager.googleapis.com/projects/$project" --format=json > "$TMP/gcp_testable.json"
  jq -r '.[] | select(.customRolesSupportLevel == "NOT_SUPPORTED") | .name' "$TMP/gcp_testable.json" | sort -u > "$TMP/gcp_ns.txt"
  if grep -Fxf "$TMP/gcp_ns.txt" "$TMP/gcp_all.txt" > "$TMP/gcp_skipped.txt"; then
    echo ">> Left out (real, but no custom role may carry them; grant through a predefined role):"
    sed 's/^/   - /' "$TMP/gcp_skipped.txt"
  fi
  grep -vFxf "$TMP/gcp_ns.txt" "$TMP/gcp_all.txt" > "$TMP/gcp_role_perms.txt" || true
  {
    echo "title: mql readonly check"
    echo "description: Read-only permissions required by mql (permission manifest check)"
    echo "stage: GA"
    echo "includedPermissions:"
    sed 's/^/- /' "$TMP/gcp_role_perms.txt"
  } > "$TMP/mql_gcp_role.yaml"
  echo ">> Creating project-level custom role $GCP_ROLE_ID in $project ($(wc -l < "$TMP/gcp_role_perms.txt" | tr -d ' ') permissions) ..."
  gcp_apply_role "$GCP_ROLE_ID" "--project=$project" "$TMP/mql_gcp_role.yaml"
  echo ">> Created. IAM accepted every permission. ✓"
}

# Create the role, or bring one an interrupted run left behind up to date
# (GCP soft-deletes a role and reserves its id for ~7 days, so a leftover is
# either live or deleted). `roles update` validates the permissions exactly as
# `roles create` does.
gcp_apply_role() { # <role id> <--project=X | --organization=Y> <yaml>
  local id="$1" where="$2" file="$3" deleted
  if deleted=$(gcloud iam roles describe "$id" "$where" --format='value(deleted)' 2>/dev/null); then
    if [[ "$deleted" == "True" ]]; then
      echo ">> $id exists soft-deleted from an earlier run; undeleting it"
      gcloud iam roles undelete "$id" "$where" --quiet >/dev/null
    else
      echo ">> $id already exists from an earlier run; updating it"
    fi
    gcloud iam roles update "$id" "$where" --file="$file" --quiet >/dev/null
  else
    gcloud iam roles create "$id" "$where" --file="$file" --quiet >/dev/null
  fi
}

gcp_create_org() {
  need gcloud
  local org
  org=$(gcp_organization)
  gcp_build_role_yaml ".org_level_permissions" "$TMP/mql_gcp_org_role.yaml" "mql readonly check (organization)"
  echo ">> Creating org-level custom role $GCP_ORG_ROLE_ID in organization $org ($(jq '.org_level_permissions | length' "$GCP_PERMS") permissions) ..."
  gcp_apply_role "$GCP_ORG_ROLE_ID" "--organization=$org" "$TMP/mql_gcp_org_role.yaml"
  echo ">> Created. IAM accepted every permission. ✓"
}

gcp_delete() {
  need gcloud
  local project
  project=$(gcp_project)
  echo ">> Deleting project-level custom role $GCP_ROLE_ID in $project ..."
  gcloud iam roles delete "$GCP_ROLE_ID" --project="$project" --quiet >/dev/null
  echo ">> Done (the role is soft-deleted; GCP purges it after ~7 days, and the id stays reserved until then)."
}

gcp_delete_org() {
  need gcloud
  local org
  org=$(gcp_organization)
  echo ">> Deleting org-level custom role $GCP_ORG_ROLE_ID in organization $org ..."
  gcloud iam roles delete "$GCP_ORG_ROLE_ID" --organization="$org" --quiet >/dev/null
  echo ">> Done."
}

# The GCP check: IAM accepts both manifest lists as custom roles, project and
# organization, cleaned up again. If a step fails, whatever was created is
# removed on the way out (best effort) so the next run starts clean.
gcp_check() {
  trap 'rc=$?; trap - EXIT; gcp_cleanup; exit $rc' EXIT
  gcp_create;     gcp_delete
  gcp_create_org; gcp_delete_org
  trap - EXIT
}

gcp_cleanup() {
  [[ -z "${GCP_PROJECT:-}" ]]      || gcloud iam roles delete "$GCP_ROLE_ID" --project="$GCP_PROJECT" --quiet >/dev/null 2>&1 || true
  [[ -z "${GCP_ORGANIZATION:-}" ]] || gcloud iam roles delete "$GCP_ORG_ROLE_ID" --organization="$GCP_ORGANIZATION" --quiet >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

# Create a custom role from every operation in the manifest, at the given scope
# (a subscription, resource group or management group id). Azure validates
# every action against the provider operation registry and refuses the whole
# role with InvalidActionOrNotAction naming the first operation no provider
# registers. Nothing is created when it fails. The caller needs
# Microsoft.Authorization/roleDefinitions/write at the scope.
azure_create() {
  need az; need jq
  local scope="${1:-}"
  [[ -n "$scope" ]] || die "usage: $0 azure-create <SCOPE>  (e.g. /subscriptions/<id>)"
  manifest "$AZURE_PERMS"
  # Every manifest entry is a control-plane operation (the generator derives
  # them from ARM URL paths), so they all go in Actions. A data-plane
  # operation (Microsoft.Storage/.../blobs/read and the like) belongs in
  # DataActions and would need its own list in the manifest first.
  jq --arg name "$AZURE_ROLE_NAME" --arg scope "$scope" \
    '{Name: $name, Description: "Read-only operations required by mql (permission manifest check)", Actions: .permissions, NotActions: [], AssignableScopes: [$scope]}' \
    "$AZURE_PERMS" > "$TMP/mql_azure_role.json"
  echo ">> Creating custom role $AZURE_ROLE_NAME at $scope ($(jq '.permissions | length' "$AZURE_PERMS") operations) ..."
  if [[ -n "$(az role definition list --name "$AZURE_ROLE_NAME" --scope "$scope" --query '[0].id' -o tsv)" ]]; then
    # Left behind by an interrupted run; an update validates the actions too.
    echo ">> $AZURE_ROLE_NAME already exists at $scope from an earlier run; updating it"
    az role definition update --role-definition "$TMP/mql_azure_role.json" -o none
  else
    az role definition create --role-definition "$TMP/mql_azure_role.json" -o none
  fi
  echo ">> Created. Azure accepted every operation. ✓"
}

azure_delete() {
  need az
  local scope="${1:-}"
  [[ -n "$scope" ]] || die "usage: $0 azure-delete <SCOPE>"
  echo ">> Deleting custom role $AZURE_ROLE_NAME at $scope ..."
  az role definition delete --name "$AZURE_ROLE_NAME" --scope "$scope" -o none
  echo ">> Done."
}

# Create and delete, removing the role on the way out if a step fails.
azure_check() {
  AZURE_CLEANUP_SCOPE="${1:-}"
  trap 'rc=$?; trap - EXIT; azure_cleanup; exit $rc' EXIT
  azure_create "$@"
  azure_delete "$@"
  trap - EXIT
}

azure_cleanup() {
  [[ -z "${AZURE_CLEANUP_SCOPE:-}" ]] || az role definition delete --name "$AZURE_ROLE_NAME" --scope "$AZURE_CLEANUP_SCOPE" -o none >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------

usage() {
  cat >&2 <<'USG'
Usage: test-iam-permissions.sh <command>

AWS:
  aws-check               validate every action with IAM Access Analyzer (creates nothing); fails on ERROR findings
  aws-create              create role mql-perms-test + managed policies
  aws-delete              tear the AWS role + policies back down

GCP (GCP_PROJECT and GCP_ORGANIZATION must be set):
  gcp-check               create + delete the project and organization custom roles
  gcp-create              create project-level custom role mqlReadonlyCheck
  gcp-create-org          create org-level custom role mqlReadonlyCheckOrg
  gcp-delete              delete the project-level custom role
  gcp-delete-org          delete the org-level custom role

Azure:
  azure-check <SCOPE>     create + delete a custom role from the manifest at a scope; Azure refuses any unregistered operation
  azure-create <SCOPE>    create that custom role
  azure-delete <SCOPE>    delete it
USG
  exit 1
}

case "${1:-}" in
  aws-check)       aws_check ;;
  aws-create)      aws_create ;;
  aws-delete)      aws_delete ;;
  gcp-check)       gcp_check ;;
  gcp-create)      gcp_create ;;
  gcp-create-org)  gcp_create_org ;;
  gcp-delete)      gcp_delete ;;
  gcp-delete-org)  gcp_delete_org ;;
  azure-check)     azure_check "${2:-}" ;;
  azure-create)    azure_create "${2:-}" ;;
  azure-delete)    azure_delete "${2:-}" ;;
  *)               usage ;;
esac
