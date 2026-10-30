#!/usr/bin/env bats
# Tests for .github/scripts/next-minor-release.sh
#
# Each test builds a throwaway git repo in $BATS_TEST_TMPDIR. Remote branches
# are faked with `git update-ref refs/remotes/origin/<name>`, so no network or
# second repo is needed. EXISTS_BRANCHES tells determine-provider-release-base.sh
# which support branches exist, so it does not call gh.

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../next-minor-release.sh"
  REPO="$BATS_TEST_TMPDIR/repo"
  mkdir -p "$REPO"
  cd "$REPO"
  git init -q -b main .
  git config user.email test@example.com
  git config user.name test
  git config core.hooksPath /dev/null
  git config commit.gpgsign false
  git config tag.gpgsign false
}

# commit [message]: add an empty commit to the current HEAD.
commit() {
  git commit -q --allow-empty -m "${1:-c}"
}

# tag NAME: lightweight tag on HEAD.
tag() {
  git tag "$1"
}

# remote_branch NAME: point refs/remotes/origin/NAME at HEAD.
remote_branch() {
  git update-ref "refs/remotes/origin/$1" HEAD
}

# out KEY: value of KEY in the script's stdout.
out() {
  printf '%s\n' "$output" | sed -n "s/^$1=//p"
}

@test "today's world: v13 branch holds v13.39.0, main has v14.2.0 and an rc" {
  commit v13
  tag v13.39.0
  git update-ref refs/remotes/origin/v13 HEAD
  commit v14-start
  commit v14.2.0
  tag v14.2.0
  commit rc
  tag v14.3.0-rc.1
  commit more
  remote_branch main
  expected_sha=$(git rev-parse HEAD)

  EXISTS_BRANCHES='v13' run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$(out prev)" = "v14.2.0" ]
  [ "$(out next)" = "v14.3.0" ]
  [ "$(out major)" = "14" ]
  [ "$(out base)" = "main" ]
  [ "$(out sha)" = "$expected_sha" ]
  [ "$(out commits)" = "2" ]
  [ "$(out skip)" = "false" ]
}

@test "v13 is current: main has only v14 rcs, v13 branch has v13.39.0" {
  commit v13
  tag v13.39.0
  git update-ref refs/remotes/origin/v13 HEAD
  commit v13-next
  git update-ref refs/remotes/origin/v13 HEAD
  v13_sha=$(git rev-parse HEAD)
  commit rc
  tag v14.0.0-rc.1
  remote_branch main

  EXISTS_BRANCHES='v13' run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$(out prev)" = "v13.39.0" ]
  [ "$(out next)" = "v13.40.0" ]
  [ "$(out base)" = "v13" ]
  [ "$(out sha)" = "$v13_sha" ]
  [ "$(out commits)" = "1" ]
  [ "$(out skip)" = "false" ]
}

@test "main moved to a v15 rc without a v14 branch is refused" {
  commit v14
  tag v14.2.0
  commit rc
  tag v15.0.0-rc.1
  remote_branch main

  EXISTS_BRANCHES='' run bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"::error::"* ]]
  [[ "$output" == *"v15.0.0-rc.1"* ]]
  [[ "$output" == *"Cut a v14 support branch"* ]]
}

@test "v14 branch cut, main at a v15 rc: release goes from v14" {
  commit v14
  tag v14.2.0
  git update-ref refs/remotes/origin/v14 HEAD
  commit v14-fix
  git update-ref refs/remotes/origin/v14 HEAD
  v14_sha=$(git rev-parse HEAD)
  commit rc
  tag v15.0.0-rc.1
  remote_branch main

  EXISTS_BRANCHES='v14' run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$(out prev)" = "v14.2.0" ]
  [ "$(out next)" = "v14.3.0" ]
  [ "$(out base)" = "v14" ]
  [ "$(out sha)" = "$v14_sha" ]
  [ "$(out commits)" = "1" ]
  [ "$(out skip)" = "false" ]
}

@test "previous tag not on the routed branch is refused" {
  commit base
  remote_branch main
  commit elsewhere
  tag v14.2.0

  EXISTS_BRANCHES='' run bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"::error::"* ]]
  [[ "$output" == *"v14.2.0 is not an ancestor of origin/main"* ]]
}

@test "next tag appearing after the tag listing is refused" {
  commit v14
  tag v14.2.0
  commit more
  remote_branch main
  # NEXT can only exist if it was created after the tags were listed (else it
  # would be the highest stable tag itself). Simulate that race by making the
  # existence check for refs/tags/v14.3.0 succeed.
  git() {
    if [ "$1" = "rev-parse" ] && [ "${*: -1}" = "refs/tags/v14.3.0" ]; then
      return 0
    fi
    command git "$@"
  }
  export -f git
  EXISTS_BRANCHES='' run bash "$SCRIPT"
  unset -f git
  [ "$status" -ne 0 ]
  [[ "$output" == *"Tag v14.3.0 already exists"* ]]
}

@test "no commits since the previous tag sets skip=true" {
  commit v14
  tag v14.2.0
  remote_branch main
  expected_sha=$(git rev-parse HEAD)

  EXISTS_BRANCHES='' run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$(out prev)" = "v14.2.0" ]
  [ "$(out next)" = "v14.3.0" ]
  [ "$(out sha)" = "$expected_sha" ]
  [ "$(out commits)" = "0" ]
  [ "$(out skip)" = "true" ]
}

@test "no stable tags is refused, pre-releases do not count" {
  commit rc
  tag v14.0.0-rc.1
  remote_branch main

  EXISTS_BRANCHES='' run bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"::error::No stable tag"* ]]
}

@test "missing remote branch is refused" {
  commit v14
  tag v14.2.0

  EXISTS_BRANCHES='' run bash "$SCRIPT"
  [ "$status" -ne 0 ]
  [[ "$output" == *"origin/main does not exist"* ]]
}

@test "REMOTE selects the remote whose branches are used" {
  commit v14
  tag v14.2.0
  commit more
  git update-ref refs/remotes/upstream/main HEAD

  REMOTE=upstream EXISTS_BRANCHES='' run bash "$SCRIPT"
  [ "$status" -eq 0 ]
  [ "$(out commits)" = "1" ]
}
