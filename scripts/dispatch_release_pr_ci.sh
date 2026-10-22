#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${RELEASE_PR:?RELEASE_PR must be set}"

release_branch="$(jq -er '
  if type == "string" then fromjson else . end
  | .headBranchName
  | select(type == "string" and length > 0)
' <<< "$RELEASE_PR")"
if ! git check-ref-format --branch "$release_branch" >/dev/null; then
  echo "Release Please returned an invalid headBranchName: $release_branch" >&2
  exit 1
fi

gh api --method POST "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/dispatches" \
  --field "ref=$release_branch" > /dev/null
