---
name: code-formatter
description: Formats source files using the project's configured formatter
allowed-tools: bash
---
# Code formatter

Detect the formatter from the project config (prettier, black, gofmt) and run
it on the changed files: `black .` or `npx prettier --write .`.
