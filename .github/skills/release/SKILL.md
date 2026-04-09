---
name: release
description: Execute the repository release workflow safely: verify local git state, wait for CI, merge the release-please PR, and confirm a fresh release exists with the latest commit.
allowed-tools: github/get_commit, github/get_latest_release, github/issue_read, github/list_pull_requests, github/list_releases, github/list_tags, github/merge_pull_request, github/search_issues, github/search_pull_requests, github/update_pull_request 
---

# Purpose

Use this skill when asked to complete a release by merging the release-please pull request and verifying the release was created.

# Safety Rules

- Do not merge anything while any required check is failing.
- Do not merge any PR other than the release PR that updates only CHANGELOG.md.
- If a prerequisite fails, stop and report clearly to the user.

# Required Workflow

Follow these steps in order.

## Verify local repository readiness.
1. Ensure local working directory is clean (no staged/unstaged/untracked changes).
2. Ensure all local commits are pushed (local branch is not ahead of remote).
3. If the working tree is dirty or branch is ahead, stop and notify the user.

## Capture and memorize release commit.
1. Read the most recent commit SHA from the current branch HEAD.
2. Store it as: release commit.
3. Use this value later to validate release correctness.

## Wait for CI status.
1. Check all relevant running/pending CI actions for the current branch/PR.
2. Wait until they complete.
3. If no actions are currently running, tell the user that explicitly.

## Require successful CI before proceeding.
1. If any required action failed, stop.
2. Report failures to the user and do not continue.

## Find the release-please pull request.
1. Locate the open PR created by release-please.
2. Confirm it contains exactly one changed file: CHANGELOG.md.
3. If no such PR exists, or file set differs, stop and notify the user.

## Merge the release PR.
1. Merge the validated release-please PR using the repository's default merge policy.
2. Report the PR number and merge commit SHA to the user.

## Wait for post-merge CI.
1. After merge, wait for CI actions to start for the default branch.
2. Wait until all required actions finish successfully.
3. If any required action fails, stop and report failure details.

## Verify release creation and freshness.
1. Query the latest published release.
2. Verify it was created recently: within the last five minutes.
3. Verify it contains the latest commit in the repository.
4. Also verify the release includes the previously memorized release commit.
5. If any verification fails, report it as a release failure.

# Suggested Checks and Evidence

When reporting completion, include:

- release commit SHA
- release PR number
- merged commit SHA
- post-merge CI summary
- release tag/version
- release publish timestamp
- proof that latest repo commit and release commit are included in the release

# Completion Criteria

Only declare success when all of the following are true:

1. Local repo was clean and not ahead before release.
2. Pre-merge CI completed successfully.
3. Correct release-please PR (CHANGELOG.md only) was merged.
4. Post-merge CI completed successfully.
5. Latest release exists, is newer than five minutes threshold, and includes both the latest repo commit and the release commit.
