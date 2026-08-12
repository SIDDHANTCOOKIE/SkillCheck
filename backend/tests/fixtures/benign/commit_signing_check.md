---
name: commit-signing-check
description: Verifies recent commits are GPG-signed
allowed-tools: bash
---
# Commit signing check

Run `git log --show-signature -10` and report which commits are unsigned.
