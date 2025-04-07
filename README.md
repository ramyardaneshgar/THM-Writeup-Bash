# THM-Writeup-Bash
Writeup for TryHackMe Bash Lab - adversary emulation, threat detection, and system hardening using nmap, nikto, dig, whois, openssl, find, ps, awk, and md5sum.

By Ramyar Daneshgar 

### Task 2 – Recon Automation Framework

```bash
#!/bin/bash

target="$1"
output_dir="recon_${target}_$(date +%F_%H-%M)"
mkdir -p "$output_dir"

whois "$target" > "$output_dir/whois.txt"
dig "$target" ANY +noall +answer > "$output_dir/dns_records.txt"

while read sub; do
  host "$sub.$target" | grep "has address" >> "$output_dir/subdomains.txt"
done < /usr/share/wordlists/dns/subdomains.txt

curl -sI "$target" > "$output_dir/http_headers.txt"
echo | openssl s_client -connect "$target:443" 2>/dev/null | openssl x509 -noout -text > "$output_dir/cert_info.txt"
```

#### Explanation:
This script builds a complete reconnaissance package on a target domain. It:
- Extracts registrar and contact metadata via WHOIS.
- Dumps all DNS records (A, MX, TXT, etc.) which may expose misconfigured SPF/DKIM or internal IPs.
- Bruteforces subdomains using a wordlist, helping expose admin portals or shadow infrastructure.
- Captures HTTP headers, revealing technology stack, server banners, misconfigured CORS or security headers.
- Dumps full X.509 certificate details, which can include:
  - Expiration (useful for social engineering)
  - Misissued internal domains
  - Weak encryption (e.g., RSA-1024)

Red Teams use this to fingerprint external attack surfaces before choosing targets. Blue Teams use the same techniques to understand what information about their infrastructure is publicly exposed and exploitable.

---

### Task 3 – System User Enumeration and Threat Intelligence Correlation

```bash
#!/bin/bash

threat_users=("backup" "oracle" "test" "support")
alert_file="suspicious_users_$(date +%F).log"

while IFS=: read -r user _ uid gid home shell; do
  for threat in "${threat_users[@]}"; do
    if [[ "$user" == "$threat" ]]; then
      echo "[ALERT] User: $user (UID: $uid) - Shell: $shell - Home: $home" >> "$alert_file"
    fi
  done
done < /etc/passwd
```

#### Explanation:
This script parses `/etc/passwd` and matches usernames against a list of accounts that are commonly exploited or used for backdoor persistence in enterprise environments. It logs suspicious entries including their UID and shell.

The threat user list may come from:
- Threat intelligence feeds
- Past breach reports
- Internal red team findings

Used in compliance checks, hardened system baselining, and insider threat detection. In breach investigations, this can uncover accounts created or repurposed by attackers for lateral movement.

---

### Task 4 – Flexible Vulnerability Scanner Wrapper

```bash
#!/bin/bash

target="$1"
ports="$2"

[[ -z "$target" || -z "$ports" ]] && { echo "Usage: $0 <target> <ports>"; exit 1; }

mkdir -p scans

nmap -T4 -sC -sV -p "$ports" "$target" -oN "scans/${target}_nmap.txt"
nikto -h "$target" > "scans/${target}_nikto.txt"
```

#### Explanation:
This script takes dynamic input and launches two vulnerability scanners:
- `nmap` for open ports and service versioning with safe scripts
- `nikto` to check for web server misconfigurations and vulnerabilities

Input validation ensures the script only runs with valid arguments. Scan results are stored per-target, improving auditability and reproducibility.

Quickly assess a host’s exposure. Red Teams use it for initial reconnaissance. Blue Teams use it to validate patching across environments or to verify whether legacy ports like FTP, Telnet, or unprotected APIs are exposed.

---

### Task 5 – IOC-Based Batch File System Scanner

```bash
#!/bin/bash

declare -A iocs
iocs["rev_shell.sh"]="098f6bcd4621d373cade4e832627b4f6"
iocs["data_leak.py"]="d41d8cd98f00b204e9800998ecf8427e"

log_file="ioc_results_$(date +%F).log"

for filename in "${!iocs[@]}"; do
  while read -r found; do
    hash=$(md5sum "$found" | awk '{print $1}')
    if [[ "$hash" == "${iocs[$filename]}" ]]; then
      echo "[MATCH] $found (MD5: $hash)" | tee -a "$log_file"
    fi
  done < <(find / -type f -name "$filename" 2>/dev/null)
done
```

#### Explanation:
This script finds files by name and validates their contents using MD5 hash comparison. This prevents false positives in case a benign file shares a filename with a malicious one.

The `declare -A` syntax creates an associative array, mapping filenames to their known malicious hashes — a common format used by threat intelligence reports.

- Run on endpoints after a known malware incident
- Validate file contents against threat intelligence
- Can be modified to use SHA256 and scan specific directories like `/var/www`, `/opt`, or `/usr/local/bin`

---

### Task 6 – Critical File Integrity Monitor and Auto-Restore

```bash
#!/bin/bash

critical_file="/etc/ssh/sshd_config"
baseline_md5="e99a18c428cb38d5f260853678922e03"
current_md5=$(md5sum "$critical_file" | awk '{print $1}')
log="/var/log/sshd_integrity_check.log"

if [[ "$baseline_md5" != "$current_md5" ]]; then
  echo "[ALERT] sshd_config tampered with on $(date)" >> "$log"
  cp /opt/baselines/sshd_config.bak "$critical_file"
  echo "[ACTION] Restored from baseline" >> "$log"
else
  echo "[OK] sshd_config integrity verified $(date)" >> "$log"
fi
```

#### Explanation:
This script compares the current state of a high-risk configuration file (`sshd_config`) to its known-good baseline using an MD5 hash. If the file is altered, it logs the event and immediately replaces it with a backup copy.

In secure environments, configuration tampering can indicate post-exploitation activity or persistence attempts.

- Detects and remediates configuration backdoors (e.g., `PermitRootLogin yes`)
- Can be deployed via cron across hundreds of servers
- Useful for PCI-DSS, CIS, and NIST compliance monitoring

---

### Combined Threat Scanner and Local Host Defense Utility

```bash
#!/bin/bash

iocs=("malicious.sh" "crypto_miner" "reverse.py")
suspicious_users=("apache" "nobody" "backup" "support")
dirs_to_watch=("/tmp" "/var/tmp" "/opt")
log="threat_report_$(hostname)_$(date +%F_%H%M).log"

for ioc in "${iocs[@]}"; do
  for dir in "${dirs_to_watch[@]}"; do
    find "$dir" -type f -name "$ioc" 2>/dev/null | while read -r match; do
      echo "[IOC DETECTED] $match" | tee -a "$log"
    done
  done
done

while IFS=: read -r user _ uid _ home shell; do
  for entry in "${suspicious_users[@]}"; do
    if [[ "$user" == "$entry" && "$uid" -ge 1000 ]]; then
      echo "[SUSPICIOUS USER] $user (UID: $uid, Home: $home, Shell: $shell)" | tee -a "$log"
    fi
  done
done < /etc/passwd

for dir in "${dirs_to_watch[@]}"; do
  find "$dir" -type f -executable -name "*.sh" -exec echo "[EXE FILE] {}" \; >> "$log"
done

echo "[+] Scan completed on $(date)" >> "$log"
```

#### Explanation:
This script combines multiple behavioral and signature-based checks to function as a local threat-hunting tool:
- Detects known IOCs in temp or dropper locations.
- Flags executable shell scripts that may be persistence mechanisms.
- Reviews system user accounts for weak or abused identities.
- Logs findings with host- and time-specific markers for incident correlation.
- 
This is a modular threat detection and response tool used during:
- Initial host triage in incident response
- Scheduled system audits in a hardened infrastructure
- First-stage detection during memory forensics or when an EDR tool flags an alert
