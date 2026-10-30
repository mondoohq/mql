#!/usr/bin/env bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Determine base branch for the provider version-bump PR opened after
# an mql release.
#
# For a release with major N, the PR opens against the v{N} support
# branch iff one exists on the repo; otherwise it opens against main.
# So today (v13 branch exists, main tracks v14 unversioned): a v13.x
# release routes to v13, a v14.x release routes to main. When main
# later moves to v15 and a v14 support branch is cut, v14 tags start
# routing to v14 automatically -- no config bump needed.
#
# Inputs:
#   $1 (required)     incoming release tag (e.g. v13.35.1)
#   $EXISTS_BRANCHES  space-separated list of branch names known to
#                     exist. If unset, fetched via `gh api` using
#                     $GH_REPO and $GH_TOKEN. Tests set this to run
#                     without touching the network.
#
# Output: prints "main" or "v{major}".
set -euo pipefail

TAG="${1:?release tag required as first argument}"

V="${TAG#v}"
RELEASE_MAJOR="${V%%.*}"

# Guard against malformed tags: the major must be a positive integer.
if [[ ! "$RELEASE_MAJOR" =~ ^[0-9]+$ ]]; then
  echo "Could not extract a numeric major from tag: $TAG" >&2
  exit 1
fi

BRANCH="v${RELEASE_MAJOR}"

# Determine whether the support branch exists.
if [ -n "${EXISTS_BRANCHES+set}" ]; then
  # Test mode: check against the caller-provided list.
  BRANCH_EXISTS=0
  for b in $EXISTS_BRANCHES; do
    if [ "$b" = "$BRANCH" ]; then
      BRANCH_EXISTS=1
      break
    fi
  done
else
  # Live mode: query GitHub. 200 -> exists, 404 -> does not.
  : "${GH_REPO:?GH_REPO or EXISTS_BRANCHES required}"
  if gh api "/repos/${GH_REPO}/branches/${BRANCH}" --silent >/dev/null 2>&1; then
    BRANCH_EXISTS=1
  else
    BRANCH_EXISTS=0
  fi
fi

if [ "$BRANCH_EXISTS" = "1" ]; then
  echo "$BRANCH"
else
  echo main
fi
