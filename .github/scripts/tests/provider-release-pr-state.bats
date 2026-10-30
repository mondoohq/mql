#!/usr/bin/env bats
# Tests for .github/scripts/provider-release-pr-state.sh
#
# Each test starts from an approved, green, mergeable PR (base_state) and
# applies a jq filter that breaks one thing, then sets PR_STATE_JSON so the
# script runs without calling gh. See the script's header for the contract.

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../provider-release-pr-state.sh"
  HEAD_SHA="1111111111222222222233333333334444444444"
  OLD_SHA="9999999999888888888877777777776666666666"
}

# A CheckRun entry as printed by `gh pr view --json statusCheckRollup`.
check_run() { # name status conclusion startedAt [workflow]
  jq -n --arg n "$1" --arg s "$2" --arg c "$3" --arg t "$4" --arg w "${5:-CI}" \
    '{__typename:"CheckRun",name:$n,workflowName:$w,status:$s,conclusion:$c,startedAt:$t}'
}

# An approved, green, mergeable PR with both required checks passed.
base_state() {
  jq -n \
    --arg h "$HEAD_SHA" \
    --argjson a "$(check_run go-test COMPLETED SUCCESS 2026-01-01T10:00:00Z)" \
    --argjson b "$(check_run go-test-providers COMPLETED SUCCESS 2026-01-01T10:00:00Z)" \
    '{
      state: "OPEN",
      isDraft: false,
      mergeable: "MERGEABLE",
      headRefOid: $h,
      reviews: [{
        user: {login: "mondoo-code-review[bot]", id: 260646430, type: "Bot"},
        state: "APPROVED",
        submitted_at: "2026-01-01T10:05:00Z",
        commit_id: $h
      }],
      statusCheckRollup: [$a, $b]
    }'
}

# decide <jq filter applied to base_state>
decide() {
  PR_STATE_JSON="$(base_state | jq -c "$1")"
  export PR_STATE_JSON
  run bash "$SCRIPT"
}

@test "approved on head with green checks merges" {
  decide '.'
  [ "$status" -eq 0 ]
  [ "$output" = "merge" ]
}

@test "already merged PR reports merged" {
  decide '.state = "MERGED"'
  [ "$status" -eq 0 ]
  [ "$output" = "merged" ]
}

@test "closed PR fails" {
  decide '.state = "CLOSED"'
  [ "$status" -eq 0 ]
  [ "$output" = "fail PR was closed without merging" ]
}

@test "merge conflict fails" {
  decide '.mergeable = "CONFLICTING"'
  [ "$status" -eq 0 ]
  [ "$output" = "fail merge conflict with the base branch" ]
}

@test "failed check fails with its name and conclusion" {
  run_json="$(check_run go-test COMPLETED FAILURE 2026-01-01T10:00:00Z)"
  decide ".statusCheckRollup[0] = $run_json"
  [ "$output" = "fail check go-test FAILURE" ]
}

@test "timed out check fails" {
  run_json="$(check_run go-test-providers COMPLETED TIMED_OUT 2026-01-01T10:00:00Z)"
  decide ".statusCheckRollup[1] = $run_json"
  [ "$output" = "fail check go-test-providers TIMED_OUT" ]
}

@test "failed check fails even while the review bot has not approved" {
  run_json="$(check_run go-test COMPLETED FAILURE 2026-01-01T10:00:00Z)"
  decide ".reviews = [] | .statusCheckRollup[0] = $run_json"
  [ "$output" = "fail check go-test FAILURE" ]
}

@test "stale cancelled run superseded by a later success is not a failure" {
  cancelled="$(check_run go-test COMPLETED CANCELLED 2026-01-01T09:00:00Z)"
  decide ".statusCheckRollup = [$cancelled] + .statusCheckRollup"
  [ "$output" = "merge" ]
}

@test "stale success superseded by a later failure fails" {
  failed="$(check_run go-test COMPLETED FAILURE 2026-01-01T11:00:00Z)"
  decide ".statusCheckRollup += [$failed]"
  [ "$output" = "fail check go-test FAILURE" ]
}

@test "same check name in another workflow is not deduped away" {
  failed="$(check_run go-test COMPLETED FAILURE 2026-01-01T09:00:00Z Other)"
  decide ".statusCheckRollup += [$failed]"
  [ "$output" = "fail check go-test FAILURE" ]
}

@test "failed status context fails" {
  decide '.statusCheckRollup += [{__typename:"StatusContext",context:"ci/other",state:"FAILURE",createdAt:"2026-01-01T10:00:00Z"}]'
  [ "$output" = "fail check ci/other FAILURE" ]
}

@test "status context superseded by a later success is not a failure" {
  decide '.statusCheckRollup += [
    {__typename:"StatusContext",context:"ci/other",state:"FAILURE",createdAt:"2026-01-01T09:00:00Z"},
    {__typename:"StatusContext",context:"ci/other",state:"SUCCESS",createdAt:"2026-01-01T10:00:00Z"}]'
  [ "$output" = "merge" ]
}

@test "review bot requesting changes fails" {
  decide '.reviews[0].state = "CHANGES_REQUESTED"'
  [ "$output" = "fail review bot requested changes" ]
}

@test "review bot comment without approval fails" {
  decide '.reviews[0].state = "COMMENTED"'
  [ "$output" = "fail review bot did not approve" ]
}

@test "dismissed review bot approval fails" {
  decide '.reviews[0].state = "DISMISSED"'
  [ "$output" = "fail review bot did not approve" ]
}

@test "latest review wins over an earlier approval on the same commit" {
  decide '.reviews += [{user:{login:"mondoo-code-review[bot]",id:260646430,type:"Bot"},state:"CHANGES_REQUESTED",submitted_at:"2026-01-01T10:30:00Z",commit_id:.headRefOid}]'
  [ "$output" = "fail review bot requested changes" ]
}

@test "approval of an older commit waits" {
  decide ".reviews[0].commit_id = \"$OLD_SHA\""
  [ "$output" = "wait review bot has not approved 111111111" ]
}

@test "no review at all waits" {
  decide '.reviews = []'
  [ "$output" = "wait review bot has not approved 111111111" ]
}

@test "approval by someone else does not count" {
  decide '.reviews[0].user = {login:"someone-else",id:1,type:"User"}'
  [ "$output" = "wait review bot has not approved 111111111" ]
}

@test "approval by a user account with the bot login does not count" {
  decide '.reviews[0].user.type = "User"'
  [ "$output" = "wait review bot has not approved 111111111" ]
}

@test "approval by a bot with another id does not count" {
  decide '.reviews[0].user.id = 123'
  [ "$output" = "wait review bot has not approved 111111111" ]
}

@test "approval by the bot id and type counts under a different login" {
  decide '.reviews[0].user.login = "renamed-review-app[bot]"'
  [ "$output" = "merge" ]
}

@test "REVIEW_BOT_ID overrides the bot id" {
  PR_STATE_JSON="$(base_state | jq -c '.reviews[0].user.id = 42')"
  export PR_STATE_JSON
  REVIEW_BOT_ID=42 run bash "$SCRIPT"
  [ "$output" = "merge" ]
}

@test "draft PR waits" {
  decide '.isDraft = true'
  [ "$output" = "wait PR is a draft" ]
}

@test "running checks wait and are listed" {
  running="$(check_run go-test IN_PROGRESS '' 2026-01-01T10:00:00Z)"
  lint="$(check_run golangci-lint QUEUED '' 2026-01-01T10:00:00Z)"
  decide ".statusCheckRollup[0] = $running | .statusCheckRollup += [$lint]"
  [ "$output" = "wait checks pending: go-test, golangci-lint" ]
}

@test "pending status context waits" {
  decide '.statusCheckRollup += [{__typename:"StatusContext",context:"ci/other",state:"PENDING",createdAt:"2026-01-01T10:00:00Z"}]'
  [ "$output" = "wait checks pending: ci/other" ]
}

@test "missing required check waits" {
  decide '.statusCheckRollup |= map(select(.name != "go-test-providers"))'
  [ "$output" = "wait required check go-test-providers not reported" ]
}

@test "required check that finished neutral waits" {
  neutral="$(check_run go-test COMPLETED NEUTRAL 2026-01-01T10:00:00Z)"
  decide ".statusCheckRollup[0] = $neutral"
  [ "$output" = "wait required check go-test not reported" ]
}

@test "REQUIRED_CHECKS overrides the required list" {
  PR_STATE_JSON="$(base_state | jq -c '.statusCheckRollup |= map(select(.name != "go-test-providers"))')"
  export PR_STATE_JSON
  REQUIRED_CHECKS="go-test" run bash "$SCRIPT"
  [ "$output" = "merge" ]
}

@test "neutral and skipped checks that are not required are fine" {
  neutral="$(check_run optional-a COMPLETED NEUTRAL 2026-01-01T10:00:00Z)"
  skipped="$(check_run optional-b COMPLETED SKIPPED 2026-01-01T10:00:00Z)"
  decide ".statusCheckRollup += [$neutral, $skipped]"
  [ "$output" = "merge" ]
}

@test "unknown mergeability waits" {
  decide '.mergeable = "UNKNOWN"'
  [ "$output" = "wait mergeability unknown" ]
}

@test "null rollup waits for the required checks" {
  decide '.statusCheckRollup = null'
  [ "$output" = "wait required check go-test not reported" ]
}

@test "malformed JSON is a usage error" {
  PR_STATE_JSON='not json'
  export PR_STATE_JSON
  run bash "$SCRIPT"
  [ "$status" -ne 0 ]
}
