#!/usr/bin/env bash
# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1
#
# Decide what to do next with an open provider release PR: merge it, keep
# waiting, or give up and ask a human. Used by the merge-release-pr job in
# release-providers.yml, which polls this script.
#
# The PR may only be merged when the review bot has approved the PR's
# current head commit and CI is green. The repo has no required status
# checks and auto-merge is disabled, so this script is the gate.
#
# Inputs:
#   $PR_STATE_JSON    PR state as one JSON object: the output of
#                       gh pr view <n> --json state,isDraft,mergeable,headRefOid,statusCheckRollup
#                     plus a "reviews" array in the shape of the REST API
#                     (GET /repos/{owner}/{repo}/pulls/{n}/reviews).
#                     If set, used as is (tests set this to run offline).
#   $1                PR number; used when $PR_STATE_JSON is unset. The state
#                     is fetched with `gh pr view` and `gh api` ($GH_REPO,
#                     $GH_TOKEN).
#   $REQUIRED_CHECKS  space-separated check run names that must be present
#                     and successful (default: "go-test go-test-providers")
#   $REVIEW_BOT_ID    numeric account id of the review bot (default:
#                     260646430, the user mondoo-code-review[bot])
#
# The bot is identified by account id and type "Bot", not by login. The
# reviews in `gh pr view --json reviews` (GraphQL) carry only a login, which
# a user account could share, so they cannot tell the bot from an impostor.
# The REST review has user.id and user.type, which only the real App bot has.
# A renamed app keeps its id, so the match survives a rename.
#
# Output: exactly one line on stdout, exit 0:
#   merge             approved on head, checks green: merge now
#   merged            the PR is already merged
#   wait <reason>     not ready yet, poll again
#   fail <reason>     will not become ready without a human
# Non-zero exit only for bad input.
set -euo pipefail

REQUIRED_CHECKS="${REQUIRED_CHECKS-go-test go-test-providers}"
REVIEW_BOT_ID="${REVIEW_BOT_ID:-260646430}"

if [ -n "${PR_STATE_JSON+set}" ]; then
  STATE="$PR_STATE_JSON"
else
  PR="${1:?PR number required as first argument (or set PR_STATE_JSON)}"
  PR_VIEW=$(gh pr view "$PR" --json state,isDraft,mergeable,headRefOid,statusCheckRollup)
  REVIEWS=$(gh api --paginate "repos/{owner}/{repo}/pulls/$PR/reviews" --jq '.[]' | jq -s .)
  STATE=$(jq -c --argjson reviews "$REVIEWS" '.reviews = $reviews' <<<"$PR_VIEW")
fi

if ! jq -e 'type == "object" and has("state")' >/dev/null 2>&1 <<<"$STATE"; then
  echo "invalid PR state JSON" >&2
  exit 1
fi

jq -r --arg required "$REQUIRED_CHECKS" --arg bot_id "$REVIEW_BOT_ID" '
  def failing: . as $c | ["FAILURE","CANCELLED","TIMED_OUT","ACTION_REQUIRED","STARTUP_FAILURE"] | index($c) != null;

  # The rollup keeps stale runs of the same check (a cancelled earlier run
  # next to a later success), so keep only the latest run per check.
  def latest(key; ts): group_by(key) | map(max_by(ts));

  (.statusCheckRollup // []) as $rollup
  | ($rollup | map(select(.__typename == "CheckRun"))
      | latest((.workflowName // "") + "/" + .name; .startedAt // "")) as $runs
  | ($rollup | map(select(.__typename == "StatusContext"))
      | latest(.context; .startedAt // .createdAt // "")) as $ctxs
  | [ $runs[] | select(.status == "COMPLETED" and (.conclusion | failing))
      | "check \(.name) \(.conclusion)" ] as $failed_runs
  | [ $ctxs[] | select(.state == "FAILURE" or .state == "ERROR")
      | "check \(.context) \(.state)" ] as $failed_ctxs
  | ([ $runs[] | select(.status != "COMPLETED") | .name ]
      + [ $ctxs[] | select(.state == "PENDING" or .state == "EXPECTED") | .context ]) as $pending
  | [ ($required | split(" ")[] | select(length > 0)) as $r
      | select(([$runs[] | select(.name == $r and .conclusion == "SUCCESS")] | length) == 0)
      | $r ] as $missing
  | .headRefOid as $head
  | ([ (.reviews // [])[]
       | select(.user.type == "Bot" and .user.id == ($bot_id | tonumber))
       | select(.commit_id == $head) ]
     | sort_by(.submitted_at) | last) as $review

  | if .state == "MERGED" then "merged"
    elif .state == "CLOSED" then "fail PR was closed without merging"
    elif .mergeable == "CONFLICTING" then "fail merge conflict with the base branch"
    elif ($failed_runs + $failed_ctxs | length) > 0 then "fail " + ($failed_runs + $failed_ctxs)[0]
    elif $review.state == "CHANGES_REQUESTED" then "fail review bot requested changes"
    elif $review.state == "COMMENTED" or $review.state == "DISMISSED" then "fail review bot did not approve"
    elif $review.state != "APPROVED" then "wait review bot has not approved \($head[0:9])"
    elif .isDraft == true then "wait PR is a draft"
    elif ($pending | length) > 0 then "wait checks pending: " + ($pending | join(", "))
    elif ($missing | length) > 0 then "wait required check \($missing[0]) not reported"
    elif .mergeable != "MERGEABLE" then "wait mergeability unknown"
    else "merge"
    end
' <<<"$STATE"
