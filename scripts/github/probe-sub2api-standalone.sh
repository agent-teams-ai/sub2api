#!/usr/bin/env bash
# Safe, resumable experiment: mirror exact source refs to a standalone repo.
# Does not merge, delete, archive, tag, or change either source repository ref.
set -euo pipefail

SOURCE='agent-teams-ai/sub2api'
DEST='agent-teams-ai/sub2api-standalone'
BRANCH='sync/wei-shaw-upstream-20261120'
DESCRIPTION='Standalone Sub2API with upstream Wei-Shaw/sub2api tracked explicitly'

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
for bin in git gh; do command -v "$bin" >/dev/null || fail "Missing $bin"; done
export GIT_TERMINAL_PROMPT=0
gh auth status >/dev/null || fail 'GitHub CLI is not authenticated'
# gh auth alone does not configure credentials for Git HTTPS pushes.
gh auth setup-git --hostname github.com >/dev/null || fail 'Cannot configure GitHub Git credentials'
[[ "$(gh repo view "$SOURCE" --json isFork --jq '.isFork')" == true ]] || fail 'Source is not a fork'

# Resolve live source refs; never assume a fixed SHA after another agent pushes.
EXPECTED_MAIN="$(gh api "repos/$SOURCE/branches/main" --jq '.commit.sha')"
EXPECTED_HEAD="$(gh pr view 106 --repo "$SOURCE" --json headRefOid --jq '.headRefOid')"
[[ "$EXPECTED_MAIN" =~ ^[a-f0-9]{40}$ && "$EXPECTED_HEAD" =~ ^[a-f0-9]{40}$ ]] || fail 'Invalid source SHA'

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
mirror="$workdir/source.git"
git clone --bare "https://github.com/$SOURCE.git" "$mirror"
[[ "$(git --git-dir="$mirror" rev-parse refs/heads/main)" == "$EXPECTED_MAIN" ]] || fail 'Source main moved; rerun on fresh source'
[[ "$(git --git-dir="$mirror" rev-parse "refs/heads/$BRANCH")" == "$EXPECTED_HEAD" ]] || fail 'Source PR head moved; rerun on fresh source'
git --git-dir="$mirror" merge-base --is-ancestor "$EXPECTED_MAIN" "$EXPECTED_HEAD" || fail 'PR head does not contain source main'
LOCAL_TREE="$(git --git-dir="$mirror" rev-parse "$EXPECTED_HEAD^{tree}")"
[[ "$LOCAL_TREE" =~ ^[a-f0-9]{40}$ ]] || fail 'Invalid local Git tree'
# Re-read after cloning, before any remote creation or writes.
[[ "$(gh api "repos/$SOURCE/branches/main" --jq '.commit.sha')" == "$EXPECTED_MAIN" ]] || fail 'Source main advanced during preflight'
[[ "$(gh pr view 106 --repo "$SOURCE" --json headRefOid --jq '.headRefOid')" == "$EXPECTED_HEAD" ]] || fail 'Source PR advanced during preflight'

remote="https://github.com/$DEST.git"
# Recover only a recognizable, unmodified previous trial. Never overwrite an
# unrelated existing repository or unknown branch/tag, and never force-push.
if gh repo view "$DEST" >/dev/null 2>&1; then
  [[ "$(gh repo view "$DEST" --json isFork --jq '.isFork')" == false ]] || fail 'Destination is a fork; refusing to reuse'
  [[ "$(gh repo view "$DEST" --json isPrivate --jq '.isPrivate')" == false ]] || fail 'Destination is not the expected public trial'
  [[ "$(gh repo view "$DEST" --json description --jq '.description')" == "$DESCRIPTION" ]] || fail 'Existing destination description differs; refusing to reuse'
  git ls-remote --heads --tags "$remote" > "$workdir/dest-refs" || fail 'Cannot inspect existing destination refs'
  while IFS=$'\t' read -r sha ref; do
    [[ -z "$ref" ]] && continue
    case "$ref" in
      refs/heads/main)
        [[ "$sha" == "$EXPECTED_MAIN" ]] || fail 'Existing destination main differs; refusing to overwrite'
        ;;
      "refs/heads/$BRANCH")
        [[ "$sha" == "$EXPECTED_HEAD" ]] || fail 'Existing destination PR head differs; refusing to overwrite'
        ;;
      *) fail "Unexpected destination ref $ref; refusing to overwrite" ;;
    esac
  done < "$workdir/dest-refs"
  printf 'Resuming a verified standalone trial.\n'
else
  gh repo create "$DEST" --public --disable-wiki --description "$DESCRIPTION" || fail 'Cannot create standalone repository'
fi

git --git-dir="$mirror" remote add standalone "$remote"
git --git-dir="$mirror" push standalone refs/heads/main:refs/heads/main
gh repo edit "$DEST" --default-branch main
git --git-dir="$mirror" push standalone "refs/heads/$BRANCH:refs/heads/$BRANCH"

[[ "$(gh repo view "$DEST" --json isFork --jq '.isFork')" == false ]] || fail 'Destination unexpectedly reports fork=true'
[[ "$(git ls-remote "$remote" refs/heads/main | cut -f1)" == "$EXPECTED_MAIN" ]] || fail 'Destination main SHA mismatch'
[[ "$(git ls-remote "$remote" "refs/heads/$BRANCH" | cut -f1)" == "$EXPECTED_HEAD" ]] || fail 'Destination PR SHA mismatch'
REMOTE_TREE="$(gh api "repos/$DEST/git/commits/$EXPECTED_HEAD" --jq '.tree.sha')"
[[ "$LOCAL_TREE" == "$REMOTE_TREE" ]] || fail 'Destination tree differs from source'

# If a previous invocation created the PR and crashed, accept only the matching
# still-open PR; a closed PR requires manual inspection, not recreation.
pr_count="$(gh pr list --repo "$DEST" --base main --head "$BRANCH" --state all --json number --jq 'length')"
case "$pr_count" in
  0)
    gh pr create --repo "$DEST" --base main --head "$BRANCH" \
      --title 'chore(sync): integrate Wei-Shaw upstream with fork features preserved' \
      --body "Standalone CI experiment using exact Sub2API PR #106 HEAD $EXPECTED_HEAD. Source review: https://github.com/$SOURCE/pull/106. Do not merge until full native/backend/frontend/security E2E on this exact SHA, independent review, and postmerge checks."
    ;;
  1)
    pr_state="$(gh pr list --repo "$DEST" --base main --head "$BRANCH" --state all --json state --jq '.[0].state')"
    [[ "$pr_state" == OPEN ]] || fail "Existing trial PR is $pr_state; inspect it manually"
    printf 'Matching standalone PR already open.\n'
    ;;
  *) fail 'Multiple existing standalone PRs; inspect manually' ;;
esac

printf '\nIndependent repository %s verified at main %s and PR %s.\n' "$DEST" "$EXPECTED_MAIN" "$EXPECTED_HEAD"
printf 'Now check real CI / Security Scan / Account Gateway Native runs (queued/skipped is not PASS).\n'
printf 'Do not deprecate or merge the old fork before full qualification.\n'
printf 'Other branches, tags, secrets, issues, reviews and settings were not migrated.\n'
printf 'Add/set local upstream remote: https://github.com/Wei-Shaw/sub2api.git\n'
