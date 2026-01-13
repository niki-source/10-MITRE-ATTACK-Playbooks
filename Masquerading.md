# Detection Playbook: Masquerading  
**MITRE ATT&CK Technique:** T1036 – Masquerading

---

## 1. Technique Overview

Masquerading is when an attacker **disguises malicious files, processes, or activity to look legitimate**.  
This is done to evade detection by users and security tools by abusing **trusted names, locations, or extensions**.

Common masquerading techniques:
- Renaming malware to look like legitimate binaries (e.g., svchost.exe)
- Using double file extensions (invoice.pdf.exe)
- Placing files in trusted directories
- Imitating legitimate software update processes
- Using look-alike domain or process names

---

## 2. Why This Matters

Masquerading enables attackers to:
- Bypass basic security controls
- Avoid user suspicion
- Maintain persistence longer
- Blend malicious activity into normal system behavior

Masquerading is a **stealth-enabler**—it doesn’t execute attacks by itself but hides them effectively.

---

## 3. Log Sources

Logs useful for detecting Masquerading:
- EDR process and file telemetry
- Windows Security Logs (4688)
- Sysmon (Event IDs 1, 11)
- File integrity monitoring logs
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- Executables with names similar to system binaries in non-standard paths
- System process names executed by non-system users
- Double file extensions
- Mismatch between file name and file metadata
- Unsigned binaries posing as signed software

### Example Pseudo-Logic
IF ProcessName resembles known system binary
AND FilePath NOT IN expected_system_paths
THEN Alert

yaml
Copy code

### Key Fields Used
- Process Name
- File Path
- Parent Process
- Digital Signature Status
- File Hash
- User Context
- Timestamp

---

## 5. Alert Example

**Alert Name:** Possible Masquerading Detected  
**Severity:** High  

**Description:**  
An executable with a system-like name was launched from an unexpected directory, suggesting masquerading behavior.

**Key Details:**
- Process: svchost.exe
- Path: C:\Users\Public\svchost.exe
- Signed: No
- User: standard.user
- Time: 11:47 PM

---

## 6. Investigation Steps

1. Verify the file path and name legitimacy
2. Check digital signature and hash reputation
3. Review parent process and execution chain
4. Identify when the file was created or modified
5. Look for persistence mechanisms
6. Check for network connections or C2 traffic
7. Search for similar files on other hosts

---

## 7. Correlation Opportunities

Higher confidence when correlated with:
- Ingress tool transfer
- Process injection
- C2 communication
- Persistence mechanisms
- Privilege escalation activity

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- Custom internal tools named similarly to system binaries
- Portable applications
- Legacy software behavior

Maintain allowlists for known internal tools.

---

## 9. Response Actions

- Quarantine the suspicious file
- Isolate the affected host if malicious
- Block associated hashes
- Perform a full system scan
- Remove persistence mechanisms
- Document findings and update detection logic

---

## 10. Mapping to MITRE ATT&CK

- **T1036 – Masquerading**
  - T1036.003 – Rename System Utilities
  - T1036.005 – Match Legitimate Name or Location
  - T1036.006 – Space after Filename
  - T1036.007 – Double File Extension
