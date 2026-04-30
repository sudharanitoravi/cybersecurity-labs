Cybersecurity Labs

Hands-on practical security labs documenting real tool usage,
analysis techniques, and findings. Each lab simulates tasks
performed daily by SOC analysts and security engineers.

---

## About This Repository
This repository contains practical cybersecurity exercises
covering network analysis, log analysis, SIEM/Splunk queries,
and security automation scripts. All labs are performed using
real tools on real data — not simulations or screenshots of
theory slides.

**Current Focus:** SOC Analyst skill development
**Tools Used:** Wireshark, Terminal, Splunk, Python
**Platform:** macOS + TryHackMe browser labs

---

## Repository Structure
cybersecurity-labs/
├── network-analysis/       → Wireshark packet analysis labs
├── log-analysis/           → Linux and Windows log analysis
├── splunk-labs/            → SPL queries and SIEM investigation
└── scripts/                → Python security automation tools

---

## Labs Completed

### Network Analysis
| Lab | Description | Tools | Status |
|-----|-------------|-------|--------|
| [Lab 01 — Wireshark HTTP Analysis](network-analysis/lab-01-wireshark-http-analysis/) | Full SOC-style analysis of HTTP capture — endpoint mapping, conversation analysis, file extraction, DNS investigation, TCP handshake analysis, User-Agent inspection | Wireshark | ✅ Complete |

### Log Analysis
| Lab | Description | Tools | Status |
|-----|-------------|-------|--------|
| [Lab 01 — Linux Auth Log Analysis](log-analysis/lab-01-linux-auth-logs/) | Analysing authentication logs for failed logins, brute force detection, and successful login correlation | Terminal, grep, awk | 🔄 In Progress |

### Splunk Labs
| Lab | Description | Tools | Status |
|-----|-------------|-------|--------|
| [Lab 01 — Basic SPL Searches](splunk-labs/lab-01-basic-spl/) | Core SPL commands — search, stats, table, sort, timechart | Splunk (TryHackMe) | 🔄 In Progress |

### Scripts
| Script | Description | Language | Status |
|--------|-------------|----------|--------|
| [log_analyzer.py](scripts/log_analyzer.py) | Parses auth.log files — flags brute force IPs, counts failures, identifies successful logins | Python | 🔄 In Progress |

---

## Lab 01 — Wireshark HTTP Analysis Highlights

**File analysed:** http.cap (43 packets)
**What I investigated:**

| Task | What I Did | SOC Relevance |
|------|-----------|---------------|
| Endpoint mapping | Identified all 4 unique IPs and their roles | First step in any network investigation |
| Conversation analysis | Mapped which IPs communicated and how much data | Detects unexpected communication |
| HTTP investigation | Extracted GET requests and reconstructed streams | Reveals what was accessed |
| File extraction | Exported all HTTP objects from the capture | Critical for malware analysis |
| DNS analysis | Examined query and response packets | C2 detection starts with DNS |
| TCP handshake | Analysed SYN/SYN-ACK sequence | Detects port scans and DoS |
| User-Agent analysis | Identified browser and OS from headers | Detects spoofing and automation |
| Packet size analysis | Checked size distribution for anomalies | Detects data exfiltration |
| Timeline reconstruction | Built full chronological event timeline | Foundation of incident response |
| Evidence export | Exported dissection as plain text | Standard SOC documentation practice |

---

## Skills Demonstrated

### Network Analysis
- Wireshark display filter syntax
- TCP stream reconstruction
- HTTP object extraction
- Protocol hierarchy analysis
- Endpoint and conversation statistics
- DNS query/response analysis
- TCP flag filtering (SYN, RST, ACK)
- User-Agent string analysis
- Packet size distribution analysis
- Traffic timeline reconstruction

### Log Analysis
- Linux auth.log parsing
- grep and awk command line tools
- Failed login detection
- Brute force IP identification
- Successful login correlation

### SIEM / Splunk
- SPL search syntax
- stats, table, sort, timechart commands
- SOC-relevant detection queries
- Brute force detection with SPL
- Threat hunting queries

### Scripting
- Python file parsing
- Counter and collections module
- Security automation concepts
- Log analysis automation

---

## MITRE ATT&CK Techniques Covered

| Technique | ID | Lab |
|-----------|-----|-----|
| Exfiltration Over C2 Channel | T1041 | Wireshark lab |
| DNS Tunneling | T1071.004 | Wireshark lab |
| Network Sniffing | T1040 | Wireshark lab |
| Adversary-in-the-Middle | T1557 | Wireshark lab |
| Brute Force | T1110 | Log analysis lab |
| Valid Accounts | T1078 | Log analysis lab |

---

## Tools & Setup

| Tool | Version | Purpose |
|------|---------|---------|
| Wireshark | 4.x | Network packet capture analysis |
| macOS Terminal | — | Log analysis and scripting |
| Python | 3.x | Security automation scripts |
| Splunk | TryHackMe hosted | SIEM query practice |

**No Kali Linux or VM required** — all labs run on macOS
Terminal or browser-based environments.

---

## Related Repositories

| Repository | Contents |
|------------|---------|
| [soc-analyst-learning](../soc-analyst-learning/) | TryHackMe notes, LetsDefend fundamentals |
| [incident-response-labs](../incident-response-labs/) | Full IR investigations, CyberDefenders cases |

---

## Currently Working On
- Log Analysis Lab 01 — Linux auth log investigation
- Splunk Lab 01 — Basic SPL queries
- Python log analyzer script
- Wireshark Lab 02 — Malware traffic analysis (coming soon)
