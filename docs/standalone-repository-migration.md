# Sub2API standalone repository: safe CI experiment and cutover

**Status: experiment prepared, not executed.** Do not deprecate or archive `agent-teams-ai/sub2api` until the new repository has passed full exact-source qualification and consumers have migrated.

## Why test this

- The existing `agent-teams-ai/sub2api` repository is a GitHub fork of `Wei-Shaw/sub2api` (`fork: true`). GitHub documents that Actions on newly forked repositories require explicit enablement.
- The fork **previously ran** ordinary Actions until 2026-11-04. Therefore `fork: true` alone is **not proof** of the cause of missing runs since that date. Check Actions policies and workflow enablement if the experiment fails.
- `agent-teams-ai/account-gateway` is non-fork and runs Actions successfully, but its previously qualified native source is not the exact current PR #106 HEAD.

## Trial identity and immutable history

| Item | Value |
| --- | --- |
| Source repository | `agent-teams-ai/sub2api` |
| Original upstream | `Wei-Shaw/sub2api` |
| Proposed non-fork experiment | `agent-teams-ai/sub2api-standalone` |
| Audited source `main` | `14f500eb4db78b47b5d028a8a811ec62b348ac92` |
| Source feature branch | `sync/wei-shaw-upstream-20261120` |
| Audited PR #106 baseline | `2318cc715088c9573c96096ef40ecb7781e7e70c` (before probe-script commits) |

The exact **current** branch HEAD must be read from GitHub at execution time. PR #106 already contains the PR #103 main merge and the full Git-tree audit preserving both upstream and fork changes, including `apimart.jpg` and `lanox.jpg`.

## Controlled trial

Run `scripts/github/probe-sub2api-standalone.sh` on a network-capable machine with authenticated `git` and `gh` and permission to create an organization repository. The script:

1. Checks the source is a fork, configures Git authentication through `gh auth setup-git --hostname github.com`, resolves the **live** main and PR HEAD, verifies both refs and their Git tree in a bare clone, and rechecks the exact source main and PR refs **before** creating anything.
2. Creates an **empty public standalone** repository (not a GitHub fork or template), or safely resumes a matching earlier partial trial only after verifying `fork: false`, public visibility, expected description, allowed refs and identical SHAs. Pushes exactly `main` and the PR branch **without force**, preserving Git history.
3. Checks `isFork=false`, both remote commit SHAs, and the feature branch Git tree before opening a PR; reruns reuse a matching still-open PR and never create a duplicate.
4. Does **not** transfer tags/other branches, secrets, settings, PR comments, issues, or Actions history; does **not** archive/delete/rename the original, change the original main, or merge the new PR.

If interrupted after repository creation, rerun the script against the **same exact source SHA**. It will resume only if the destination still contains solely the allowed matching refs. Any unexpected branch, tag, SHA, visibility, fork status, description or closed PR causes a safe refusal; inspect manually rather than deleting, resetting, force-pushing or overwriting an existing repository. If the source branch advanced, do **not** update a stale trial in place; inspect both repositories before choosing a new safe trial name.

The trial **only** tests whether actual GitHub Actions `CI`, `Security Scan` and `Account gateway native qualification` runs are created in the independent repository. A queued CodeQL dynamic run or a successful AI review does not count as E2E.

## Qualification gates before promotion

- Go **1.27.4** backend unit/integration tests, build, vet, lint on the new **final** SHA, plus macOS deployment-script checks.
- Node 24/26 frozen pnpm install, frontend typecheck/Vitest and production build.
- PostgreSQL 17, Redis 8, native transport/OAuth/custody/provider E2E, migration ordering by **full filename**, container/image/deployment smoke.
- Dependency and security scans, independent review approval, artifact and exact source checks. Count only actual successful jobs; never count `queued`, `skipped`, `cancelled` or AI-only as PASS.
- Only then merge through the new repository's standard PR policy and verify its main HEAD, postmerge workflows and downstream Account Gateway/Review Router compatibility.

## Safe cutover after success

- Deliberately migrate other required Git branches, tags, issues/PR references, organization permissions, branch protections/rulesets, repository secrets/variables, environments, webhooks, CI integration and consumer URLs. **Version tags are held back during the initial trial because pushing them may trigger a release/deployment.**
- Keep old PR #106 and review evidence accessible at its original URL. Git push does **not** transfer GitHub issues, PR comments, reviews, rulesets or Actions run history.
- For each developer clone after successful promotion, set `origin` to the new standalone repo, and **set or add** `upstream` to `https://github.com/Wei-Shaw/sub2api.git`. An existing `upstream` must use `git remote set-url upstream https://github.com/Wei-Shaw/sub2api.git`; if absent, use `git remote add upstream https://github.com/Wei-Shaw/sub2api.git`. Git remotes are local configuration and do **not** restore GitHub's `forked from` UI relation or auto-sync.
- Repoint dependencies and CI references, then mark the old fork's description/README **deprecated** while keeping it available for historical links. Do not detach/delete its fork network, which could discard GitHub metadata.

If new non-fork Actions also fail to start, **do not migrate or deprecate**: investigate repository/organization Actions policy. The old repository remains canonical until a fully qualified cutover.
