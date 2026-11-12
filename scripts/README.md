# scripts/

Helpers for pulling lab evidence from the VMs into this repo. Run everything from the **host**.

| Script | Runs on | Output folder |
|---|---|---|
| `collect-evidence.sh` | Host (Git Bash) | Orchestrates the three VM collectors below |
| `vm/gather-linux-server.sh` | Linux server .40 | `detections/ssh-bruteforce/evidence/` |
| `vm/gather-wazuh-suricata.sh` | Wazuh/Suricata .60 | `wazuh-suricata/evidence/` |
| `vm/gather-splunk.sh` | Splunk .10 | `splunk/exports/` |
| `windows/Collect-Sysmon.ps1` | Windows 11 .30 (admin PowerShell) | `sysmon/evidence/` (via shared folder) |
| `check-secrets.sh` | Host | Run before every push |

## One-time setup: SSH keys (avoids repeated password prompts)

```bash
ssh-keygen -t ed25519
for ip in 10 40 60; do
  cat ~/.ssh/id_ed25519.pub | ssh <user>@192.168.152.$ip "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys"
done
```
Edit the usernames at the top of `collect-evidence.sh`. The VM scripts use `sudo`, so you'll still be asked for the sudo password.

## Usage

```bash
chmod +x scripts/*.sh
./scripts/collect-evidence.sh server          # SSH evidence from .40
./scripts/collect-evidence.sh monitor         # Wazuh + Suricata from .60
./scripts/collect-evidence.sh siem            # Splunk exports from .10
./scripts/collect-evidence.sh all             # all three
./scripts/collect-evidence.sh server before   # saves into evidence/before/
./scripts/collect-evidence.sh server after    # saves into evidence/after/ (remediation check)
./scripts/check-secrets.sh
```

## Windows VM

1. Copy `Collect-Sysmon.ps1` into the VM (shared folder or drag and drop).
2. Open PowerShell **as Administrator**:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\Collect-Sysmon.ps1
   ```
3. Move `Desktop\evidence-windows` to the host via the shared folder and into `sysmon/evidence/`.

## Suggested workflow

1. Run the attack (Hydra / Nmap) and note the time.
2. Collect evidence right after, so logs are fresh.
3. Open the files and write real numbers into the READMEs.
4. Run `check-secrets.sh`, then commit and push.
5. After remediation, re-run the attack and collect with the `after` label.

## Notes

- `nmap-recon` evidence comes from the `.60` collection. Copy the relevant lines from `suricata-fast-log-sample.txt` and the Wazuh outputs into `detections/nmap-recon/`.
- Keep the Wireshark pcap on the monitoring VM and trim it there (`editcap -r in.pcap out.pcap 1-500`), then copy with `scp`.
- These are for your own isolated lab only. Check each output file by eye before committing.
