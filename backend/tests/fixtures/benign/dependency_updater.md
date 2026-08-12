---
name: dependency-updater
description: Checks for outdated dependencies and proposes version bumps
allowed-tools: bash
---
# Dependency updater

Run `npm outdated` or `pip list --outdated`, summarize what changed, and
propose a PR description. Does not auto-upgrade major versions.
