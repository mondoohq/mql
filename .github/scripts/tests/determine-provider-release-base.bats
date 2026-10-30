#!/usr/bin/env bats
# Tests for .github/scripts/determine-provider-release-base.sh
#
# Each test sets EXISTS_BRANCHES to the space-separated list of branch
# names the script should treat as existing, so the script runs without
# calling gh api. See the script's header for the input contract.

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../determine-provider-release-base.sh"
}

@test "v13 tag routes to v13 when v13 branch exists" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" v13.35.1
  [ "$status" -eq 0 ]
  [ "$output" = "v13" ]
}

@test "v13 tag routes to main when no v13 branch exists" {
  EXISTS_BRANCHES='' run bash "$SCRIPT" v13.35.1
  [ "$status" -eq 0 ]
  [ "$output" = "main" ]
}

@test "v14 tag routes to main when only v13 branch exists (today's world)" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" v14.0.0
  [ "$status" -eq 0 ]
  [ "$output" = "main" ]
}

@test "v14 tag routes to v14 when a v14 branch has been cut (post-v15)" {
  EXISTS_BRANCHES='v13 v14' run bash "$SCRIPT" v14.5.0
  [ "$status" -eq 0 ]
  [ "$output" = "v14" ]
}

@test "no v prefix on tag still resolves to the right branch" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" 13.35.1
  [ "$status" -eq 0 ]
  [ "$output" = "v13" ]
}

@test "pre-release suffix does not change routing" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" v13.35.1-rc.1
  [ "$status" -eq 0 ]
  [ "$output" = "v13" ]
}

@test "pre-release v14 tag with only v13 branch routes to main" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" v14.0.0-rc.1
  [ "$status" -eq 0 ]
  [ "$output" = "main" ]
}

@test "future v15 tag when only v13 exists routes to main" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" v15.0.0
  [ "$status" -eq 0 ]
  [ "$output" = "main" ]
}

@test "does not confuse v1 branch with a v13 tag" {
  # v1 is a substring of v13; the loop compares whole strings.
  EXISTS_BRANCHES='v1' run bash "$SCRIPT" v13.35.1
  [ "$status" -eq 0 ]
  [ "$output" = "main" ]
}

@test "malformed tag (no numeric major) fails loudly" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" hello.world
  [ "$status" -ne 0 ]
  [[ "$output" == *"Could not extract a numeric major"* ]]
}

@test "empty tag fails loudly" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT" ''
  [ "$status" -ne 0 ]
}

@test "missing tag argument errors out" {
  EXISTS_BRANCHES='v13' run bash "$SCRIPT"
  [ "$status" -ne 0 ]
}
