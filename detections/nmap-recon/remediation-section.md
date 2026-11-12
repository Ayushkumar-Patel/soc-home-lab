## Remediation / hardening notes

**1. Restrict who can reach .40 (host-based firewall)**
```bash
sudo ufw default deny incoming
sudo ufw allow from 192.168.152.0/24 to any port 22
sudo ufw allow from 192.168.152.0/24 to any port 80
sudo ufw enable
```
In this isolated lab this mainly documents the control; in a real network you'd scope the
`allow` rules to specific trusted hosts (e.g., a jump box), not the whole subnet.

**2. Rate-limit SSH to blunt scanning/brute-force together**
```bash
sudo ufw limit 22/tcp
```
`ufw limit` drops an IP that makes more than 6 connection attempts in 30 seconds — this slows
down both port scanning and the brute-force attack from the first detection, so it's worth
cross-referencing with `detections/ssh-bruteforce/README.md`.

**3. Reduce fingerprinting surface (what `-sV` actually exploited)**
The HTTP probe worked because Apache's default config advertises its exact version:
```bash
# /etc/apache2/conf-available/security.conf
ServerTokens Prod
ServerSignature Off
```
```bash
sudo a2enconf security
sudo systemctl reload apache2
```
After this change, re-running `nmap -sV` against port 80 should report a generic `Apache
httpd` instead of the exact version string — a good before/after comparison for the writeup.

**4. Close what isn't needed**
If a service isn't actually required for the lab (verify first with `ss -tulnp`), disable it
rather than firewalling it — fewer listening services means fewer things Nmap can fingerprint
at all. Document which ports stayed open and why each one is necessary.

**5. Tune Suricata to catch what the default ruleset missed**
If your findings noted the plain SYN scan went unflagged, add a custom rule rather than leaving
the gap undocumented:
```
alert tcp any any -> $HOME_NET any (msg:"LOCAL SYN scan - high SYN rate single source"; \
  flags:S,12; threshold:type threshold, track by_src, count 20, seconds 10; \
  classtype:attempted-recon; sid:9000001; rev:1;)
```
Place it in `/etc/suricata/rules/local.rules`, add that file to `rule-files` in
`suricata.yaml`, then `suricata-update` and restart.

**6. Add active response in Wazuh (optional, shows maturity)**
Wazuh can auto-block an IP after N scan alerts using `active-response` with
`firewall-drop.sh`. Worth a one-paragraph note even if you don't fully configure it — naming
the capability shows you know the detection-to-response pipeline doesn't have to stop at
alerting.

**7. Validate the fix**
Re-run the same `nmap -sV` and `--script vuln` commands from the Attack section and compare:
generic server banner instead of exact version, connection attempts now rate-limited by ufw,
and (if you added rule #5) a Suricata alert on the rescan that wasn't there before.
