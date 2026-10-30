#!/usr/bin/env bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Work out the next weekly minor release tag, and the commit it would be cut on.
#
# The release is the highest stable tag with its minor bumped (v14.2.0 ->
# v14.3.0). Pre-release tags (v14.3.0-rc.1) are ignored when finding the
# previous release, so an rc never advances the number.
#
# The commit is the tip of the branch that carries that major, as decided by
# determine-provider-release-base.sh: v<major> if that support branch exists,
# else main. The rule lives there and is not repeated here.
#
# Runs inside a git repo with every tag and every remote branch fetched.
#
# Inputs (environment):
#   REMOTE            git remote holding the branches (default origin)
#   EXISTS_BRANCHES   passed through to determine-provider-release-base.sh
#   GH_REPO, GH_TOKEN passed through likewise, when EXISTS_BRANCHES is unset
#
# Output on stdout, one key=value per line, suitable for >> "$GITHUB_OUTPUT":
#   prev     previous stable tag
#   next     tag to create
#   major    major version of both
#   base     branch the release is cut from (main or v<major>)
#   sha      tip commit of that branch on the remote
#   commits  number of commits in prev..sha
#   skip     true when commits is 0 (nothing to release), else false
#
# Errors go to stderr as ::error:: lines and the exit status is non-zero. Two
# situations are refused rather than guessed at:
#   - prev is not an ancestor of the branch: the routing picked the wrong branch.
#   - the branch already carries a tag of a later major: it has moved on, and a
#     support branch for the current major must be cut before releasing again.
set -euo pipefail

REMOTE="${REMOTE:-origin}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() {
  echo "::error::$*" >&2
  exit 1
}

PREV=$(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)
[ -n "$PREV" ] || fail "No stable tag (vX.Y.Z) found; fetch all tags first."

VERSION="${PREV#v}"
MAJOR="${VERSION%%.*}"
REST="${VERSION#*.}"
MINOR="${REST%%.*}"
NEXT="v${MAJOR}.$((MINOR + 1)).0"

BASE=$(bash "$HERE/determine-provider-release-base.sh" "$PREV")
REF="${REMOTE}/${BASE}"
git rev-parse --verify --quiet "${REF}^{commit}" >/dev/null \
  || fail "Branch ${REF} does not exist; fetch the remote branches first."

if git rev-parse --verify --quiet "refs/tags/${NEXT}" >/dev/null; then
  fail "Tag ${NEXT} already exists."
fi

git merge-base --is-ancestor "$PREV" "$REF" \
  || fail "${PREV} is not an ancestor of ${REF}: ${REF} is the wrong branch for major ${MAJOR}."

# Stable and pre-release tags alike: a v15 rc on the branch means it has moved on.
while read -r tag; do
  [ -n "$tag" ] || continue
  tag_major="${tag#v}"
  tag_major="${tag_major%%.*}"
  if [ "$tag_major" -gt "$MAJOR" ]; then
    fail "${REF} already contains ${tag}, so it has moved on to v${tag_major}. Cut a v${MAJOR} support branch before releasing v${MAJOR} again."
  fi
done < <(git tag --merged "$REF" --list 'v[0-9]*' | grep -E '^v[0-9]+\.' || true)

SHA=$(git rev-parse "${REF}^{commit}")
COMMITS=$(git rev-list --count "${PREV}..${REF}")
SKIP=false
[ "$COMMITS" -gt 0 ] || SKIP=true

echo "prev=${PREV}"
echo "next=${NEXT}"
echo "major=${MAJOR}"
echo "base=${BASE}"
echo "sha=${SHA}"
echo "commits=${COMMITS}"
echo "skip=${SKIP}"
