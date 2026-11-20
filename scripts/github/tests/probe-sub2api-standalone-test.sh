#!/usr/bin/env bash
set -euo pipefail
PROBE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/probe-sub2api-standalone.sh"
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/github.com/agent-teams-ai" "$ROOT/mockbin"
export ROOT
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="url.file://$ROOT/github.com/.insteadOf"
export GIT_CONFIG_VALUE_0='https://github.com/'
export PATH="$ROOT/mockbin:$PATH"
sourcegit="$ROOT/github.com/agent-teams-ai/sub2api.git"
destgit="$ROOT/github.com/agent-teams-ai/sub2api-standalone.git"
git init -q --bare "$sourcegit"
git init -q "$ROOT/seed"
(
 cd "$ROOT/seed"
 git config user.name Test; git config user.email test@example.com
 echo base > base; git add base; git commit -qm 'base'
 git branch -M main; git remote add source "$sourcegit"; git push -q source main
 echo feature > feature; git add feature; git commit -qm 'feature'
 git branch sync/wei-shaw-upstream-20261120
 git push -q source sync/wei-shaw-upstream-20261120
)
cat >"$ROOT/mockbin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
sourcegit="$ROOT/github.com/agent-teams-ai/sub2api.git"
destgit="$ROOT/github.com/agent-teams-ai/sub2api-standalone.git"
case "${1-} ${2-}" in
 'auth status') exit 0;;
 'auth setup-git') if [[ -e "$ROOT/reject-auth" ]]; then exit 22; fi; exit 0;;
 'repo view')
   if [[ $3 == 'agent-teams-ai/sub2api-standalone' ]] && [[ ! -e $destgit ]]; then exit 1; fi
   if [[ $3 == 'agent-teams-ai/sub2api' ]]; then echo true; exit 0; fi
   if [[ " $* " == *" .isFork "* ]]; then echo false
   elif [[ " $* " == *" .isPrivate "* ]]; then echo false
   elif [[ " $* " == *" .description "* ]]; then echo 'Standalone Sub2API with upstream Wei-Shaw/sub2api tracked explicitly'
   else echo 'repo'; fi
   ;;
 'api repos/agent-teams-ai/sub2api/branches/main')
   git --git-dir="$sourcegit" rev-parse refs/heads/main
   ;;
 'api repos/agent-teams-ai/sub2api-standalone/git/commits/'*)
   sha="${2##*/}"
   git --git-dir="$destgit" rev-parse "$sha^{tree}"
   ;;
 'pr view')
   # Verify the probe reads the exact source PR, not an unrelated branch or PR.
   [[ $# -eq 9 && ${3-} == 106 && ${4-} == --repo && ${5-} == agent-teams-ai/sub2api && ${6-} == --json && ${7-} == headRefOid && ${8-} == --jq && ${9-} == .headRefOid ]] || { echo "Unexpected gh pr view: $*" >&2; exit 12; }
   git --git-dir="$sourcegit" rev-parse refs/heads/sync/wei-shaw-upstream-20261120
   ;;
 'repo create')
   [[ ! -e "$destgit" ]] || exit 1
   git init -q --bare "$destgit"
   echo created >> "$ROOT/create-calls"
   ;;
 'repo edit')
   if [[ -f "$ROOT/fail-once" ]]; then rm -f "$ROOT/fail-once"; exit 21; fi
   exit 0
   ;;
 'pr list')
   if [[ " $* " == *" length "* ]]; then if [[ -f "$ROOT/pr-created" ]]; then echo 1; else echo 0; fi
   elif [[ " $* " == *" .[0].state "* ]]; then echo OPEN
   else exit 9; fi
   ;;
 'pr create')
   # Fail if the trial PR is created in the wrong repo, on the wrong base/head,
   # or without a traceable reference to source PR #106 and the current SHA.
   [[ $# -eq 12 && ${3-} == --repo && ${4-} == agent-teams-ai/sub2api-standalone && ${5-} == --base && ${6-} == main && ${7-} == --head && ${8-} == sync/wei-shaw-upstream-20261120 && ${9-} == --title && -n ${10-} && ${11-} == --body ]] || { echo "Unexpected gh pr create arguments: $*" >&2; exit 13; }
   expected_head="$(git --git-dir="$sourcegit" rev-parse refs/heads/sync/wei-shaw-upstream-20261120)"
   [[ ${12-} == *"Sub2API PR #106 HEAD $expected_head"* && ${12-} == *"https://github.com/agent-teams-ai/sub2api/pull/106"* ]] || { echo 'Missing exact source reference in trial PR' >&2; exit 14; }
   touch "$ROOT/pr-created"
   echo pr-created >> "$ROOT/pr-calls"
   ;;
 *) echo "Unexpected gh call: $*" >&2; exit 10;;
esac
GH
chmod +x "$ROOT/mockbin/gh"
# 0: Git credential setup failure stops before any remote write.
touch "$ROOT/reject-auth"
if bash "$PROBE" >"$ROOT/auth-fail.log" 2>&1; then echo 'FAIL accepted bad credentials'; exit 2; fi
[[ ! -e "$destgit" ]] || { echo 'FAIL created destination without Git authentication'; exit 2; }
rm -f "$ROOT/reject-auth"
echo 'PASS invalid Git credentials rejected before repo creation'
# 1: A failure after creation but before both pushes must not claim success.
touch "$ROOT/fail-once"
if bash "$PROBE" >"$ROOT/fail.log" 2>&1; then echo 'FAIL unexpected success on injected failure'; exit 2; fi
[[ -e "$destgit" ]] && [[ ! -e "$ROOT/pr-created" ]] || { echo 'FAIL partial setup not captured'; exit 2; }
# 2: Safely resume without repo recreation or loss of Git history.
bash "$PROBE" >"$ROOT/resume.log" 2>&1
[[ -f "$ROOT/pr-created" ]] && [[ $(wc -l <"$ROOT/create-calls") == 1 ]] || { echo 'FAIL resume side effects'; cat "$ROOT/resume.log"; exit 2; }
[[ $(git --git-dir="$destgit" rev-parse refs/heads/main) == $(git --git-dir="$sourcegit" rev-parse refs/heads/main) ]]
[[ $(git --git-dir="$destgit" rev-parse refs/heads/sync/wei-shaw-upstream-20261120) == $(git --git-dir="$sourcegit" rev-parse refs/heads/sync/wei-shaw-upstream-20261120) ]]
echo 'PASS interrupted standalone repo resumed exact refs and PR without recreation'
# 3: Rerun reuses open PR.
bash "$PROBE" >"$ROOT/rerun.log" 2>&1
[[ $(wc -l <"$ROOT/pr-calls") == 1 ]] || { echo 'FAIL duplicate PR'; exit 2; }
echo 'PASS repeat invocation does not duplicate PR'
# 4: Do not modify a repository with unrelated branch.
git --git-dir="$destgit" update-ref refs/heads/unrelated $(git --git-dir="$destgit" rev-parse refs/heads/main)
if bash "$PROBE" >"$ROOT/unknown-ref.log" 2>&1; then echo 'FAIL reused unfamiliar repo'; exit 2; fi
grep -q 'Unexpected destination ref' "$ROOT/unknown-ref.log"
echo 'PASS unrelated branch rejected without modification'
# 5: A new source SHA cannot overwrite old trial ref.
git --git-dir="$destgit" update-ref -d refs/heads/unrelated
(
 cd "$ROOT/seed"; echo new >> feature; git add feature; git commit -qm 'new feature'; git push -q source HEAD:refs/heads/sync/wei-shaw-upstream-20261120
)
if bash "$PROBE" >"$ROOT/sha-mismatch.log" 2>&1; then echo 'FAIL accepted incompatible remote SHA'; exit 2; fi
grep -q 'Existing destination PR head differs' "$ROOT/sha-mismatch.log"
echo 'PASS new source head does not overwrite old trial ref'
