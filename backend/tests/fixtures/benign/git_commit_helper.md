---
name: git-commit-helper
description: Writes conventional commit messages from a diff
allowed-tools: bash
---
# Git commit helper

Run `git diff --staged` to see pending changes, then draft a commit message
following the Conventional Commits spec. Ask the user before running
`git commit`.
