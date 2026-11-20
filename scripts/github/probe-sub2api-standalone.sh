#!/usr/bin/env bash
# Safe experiment: create a standalone repository; keep the fork unchanged.
set -euo pipefail

SOURCE='agent-teams-ai/sub2api'
DEST='agent-teams-ai/sub2api-standalone'
BRANCH='sync/wei-shaw-upstream-20261120'


fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
for bin in git gh; do command -v "$bin" >/dev/null || fail "Missing $bin"; done
gh auth status >/dev/null || fail 'GitHub CLI is not authenticated'
[[ "$(gh repo view "$SOURCE" --json isFork --jq '.isFork')" == true ]] || fail 'Source is not a fork'
# Resolve immutable source identities at invocation time (the source branch can advance).
EXPECTED_MAIN="$(gh api "repos/$SOURCE/branches/main" --jq '.commit.sha')"
EXPECTED_HEAD="$(gh pr view 106 --repo "$SOURCE" --json headRefOid --jq '.headRefOid')"
[[ -n "$EXPECTED_MAIN" && -n "$EXPECTED_HEAD" ]] || fail 'Source refs unavailable'
if gh repo view "$DEST" >/dev/null 2>&1; then
  fail "Destination already exists: $DEST (inspect before changing)"
fi

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
mirror="$workdir/source.git"
git clone --bare "https://github.com/$SOURCE.git" "$mirror"
[[ "$(git --git-dir="$mirror" rev-parse refs/heads/main)" == "$EXPECTED_MAIN" ]] || fail 'Source main SHA moved; refresh migration plan'
[[ "$(git --git-dir="$mirror" rev-parse "refs/heads/$BRANCH")" == "$EXPECTED_HEAD" ]] || fail 'Source PR SHA moved; refresh migration plan'

gh repo create "$DEST" --public --disable-wiki --description 'Standalone Sub2API with upstream Wei-Shaw/sub2api tracked explicitly'
git --git-dir="$mirror" remote add standalone "https://github.com/$DEST.git"
git --git-dir="$mirror" push standalone refs/heads/main:refs/heads/main
gh repo edit "$DEST" --default-branch main
git --git-dir="$mirror" push standalone "refs/heads/$BRANCH:refs/heads/$BRANCH"

[[ "$(gh repo view "$DEST" --json isFork --jq '.isFork')" == false ]] || fail 'Destination unexpectedly reports fork=true'
[[ "$(git ls-remote "https://github.com/$DEST.git" refs/heads/main | cut -f1)" == "$EXPECTED_MAIN" ]] || fail 'Destination main SHA mismatch'
[[ "$(git ls-remote "https://github.com/$DEST.git" "refs/heads/$BRANCH" | cut -f1)" == "$EXPECTED_HEAD" ]] || fail 'Destination PR SHA mismatch'
local_tree="$(git --git-dir="$mirror" rev-parse "$EXPECTED_HEAD^{tree}")"
remote_tree="$(gh api "repos/$DEST/git/commits/$EXPECTED_HEAD" --jq '.tree.sha')"
[[ "$local_tree" == "$remote_tree" ]] || fail 'Destination Git tree differs from source'

gh pr create --repo "$DEST" --base main --head "$BRANCH" \
  --title 'chore(sync): integrate Wei-Shaw upstream with fork features preserved' \
  --body "Standalone CI experiment using exact Sub2API PR #106 HEAD $EXPECTED_HEAD. Source review: https://github.com/$SOURCE/pull/106. Do not merge until full native/backend/frontend/security E2E on this exact SHA, independent review, and postmerge checks."

printf '\nCreated %s as an independent repository with matching main and PR source SHAs.\n' "$DEST"
printf 'Next: verify that GitHub created real CI / Security Scan / Account Gateway Native workflow runs.\n'
printf 'Do NOT treat queued/skipped as success; do NOT deprecate old fork before full qualification.\n'
printf 'Other branches, tags, GitHub issues, secrets and settings were NOT migrated.\n'
printf 'Tags are intentionally deferred: pushing version tags can trigger releases.\n'
printf 'For local clones, use: git remote add upstream https://github.com/Wei-Shaw/sub2api.git\n'
