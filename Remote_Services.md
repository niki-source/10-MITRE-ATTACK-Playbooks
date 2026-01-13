# Detection Playbook: Remote Services  
**MITRE ATT&CK Technique:** T1021 – Remote Services

---

## 1. Technique Overview

Remote Services refers to an attacker using legitimate remote access mechanisms to connect to systems within a network.  
Rather than deploying malware, attackers often rely on **built-in administrative protocols** to move laterally and blend in.

Commonly abused remote services include:
- Remote Desktop Protocol (RDP)
- Server Message Block (SMB)
- Windows Remote Management (WinRM)
- Secure Shell (SSH)

This activity usually occurs **after credentials are compromised**.

---

## 2. Why This Matters

Suspicious use of remote services is a strong indicator of **lateral movement** or **post-compromise activity**.

Attacker goals:
- Pivoting to additional systems
- Accessing sensitive servers (file servers, domain controllers)
- Establishing persistence using valid credentials
- Avoiding detection by using legitimate tools

Remote access from unusual sources, at odd times, or by unexpected users is often malicious.

---

## 3. Log Sources

Relevant logs for detecting Remote Services activity include:
- Windows Security Event Logs (4624, 4672, 4648)
- RDP logs (TerminalServices)
- EDR authentication and network telemetry
- Firewall and network flow logs
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- Successful logins from unexpected source IPs
- Remote logons outside normal working hours
- Lateral movement using the same account across multiple hosts
- Administrative logons without prior justification
- RDP or SMB access from non-admin workstations

### Example Pseudo-Logic
IF LogonType = Remote
AND Authentication = Success
AND Source_IP NOT IN trusted_ranges
AND User NOT IN approved_admins
THEN Alert

yaml
Copy code

### Key Fields Used
- User / Account Name
- Source IP Address
- Destination Host
- Logon Type
- Timestamp
- Authentication Result

---

## 5. Alert Example

**Alert Name:** Suspicious Remote Service Logon  
**Severity:** High  

**Description:**  
A successful remote logon was detected from an unusual source using valid credentials. This activity may indicate lateral movement.

**Key Details:**
- User: jsmith
- Source IP: 10.10.5.23
- Destination Host: FILE-SRV-01
- Logon Type: RDP
- Time: 02:13 AM

---

## 6. Investigation Steps

1. Confirm whether the user normally performs remote access
2. Validate the source IP and device ownership
3. Check for additional logins from the same account
4. Review prior authentication failures
5. Look for follow-on activity (file access, command execution)
6. Determine whether the access aligns with a change request or ticket

---

## 7. Correlation Opportunities

Stronger confidence when correlated with:
- Credential dumping alerts
- Multiple remote logins across hosts
- Privilege escalation events
- Suspicious process execution after login
- C2 or beaconing alerts from the destination host

---

## 8. False Positives

Legitimate scenarios that may trigger alerts:
- IT administrators performing maintenance
- Help desk remote support sessions
- After-hours emergency access
- Automated management tools

Always validate against approved admin lists and schedules.

---

## 9. Response Actions

- Verify legitimacy with the user or IT team
- Reset credentials if compromise is suspected
- Isolate affected hosts if lateral movement is confirmed
- Review access logs across the environment
- Document findings and update detection logic if needed

---

## 10. Mapping to MITRE ATT&CK

- **T1021 – Remote Services**
  - T1021.001 – Remote Desktop Protocol
  - T1021.002 – SMB / Windows Admin Shares
  - T1021.003 – Distributed Component Object Model (DCOM)
  - T1021.004 – SSH
  - T1021.006 – WinRM
