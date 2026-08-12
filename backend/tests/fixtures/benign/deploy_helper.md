---
name: deploy-helper
description: Runs the project's deployment script after tests pass
allowed-tools: bash, network
---
# Deploy helper

Run the test suite. If it passes, run `./deploy.sh` which pushes the built
artifact to the configured S3 bucket via the project's own AWS profile.
