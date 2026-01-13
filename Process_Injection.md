# Detection Playbook: Process Injection  
**MITRE ATT&CK Technique:** T1055 – Process Injection

---

## 1. Technique Overview

Process Injection occurs when an attacker **injects malicious code into the memory of a legitimate process**.  
This allows the attacker to:
- Execute code stealthily
- Evade antivirus and EDR detection
- Run under the context of trusted processes

Common injection techniques include:
- DLL injection
- Process hollowing
- Thread injection
- Reflective DLL loading
- APC injection

This technique is commonly used by **advanced malware and post-exploitation frameworks**.

---

## 2. Why This Matters

Process Injection is a **high-confidence indicator of compromise**.

Attacker goals:
- Hide malicious activity
- Escalate privileges
- Maintain persistence
- Execute payloads without dropping files
- Evade endpoint defenses

Legitimate software rarely injects into unrelated processes.

---

## 3. Log Sources

Logs useful for detecting Process Injection:
- EDR memory and behavioral telemetry
- Windows Security Logs (4688, 4673)
- Sysmon (Event IDs 8, 10, 11)
- Windows API monitoring (where available)
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- One process writing to another process’s memory
- Creation of remote threads
- Suspicious parent-child process relationships
- Unsigned processes injecting into signed system binaries
- Injection into common targets (explorer.exe, lsass.exe)

### Example Pseudo-Logic
IF Process_A writes memory to Process_B
AND Process_A NOT IN trusted_list
AND Process_B IN high_value_processes
THEN Alert

yaml
Copy code

### Key Fields Used
- Source Process Name
- Target Process Name
- Process ID (PID)
- User Context
- Memory Operation Type
- Code Signature Status
- Timestamp

---

## 5. Alert Example

**Alert Name:** Suspicious Process Injection Activity  
**Severity:** Critical  

**Description:**  
A non-standard process attempted to inject code into a trusted system process, indicating potential malware activity.

**Key Details:**
- Source Process: malware.exe
- Target Process: explorer.exe
- Injection Method: Remote Thread
- User: NT AUTHORITY\SYSTEM
- Time: 04:02 AM

---

## 6. Investigation Steps

1. Identify the source and target processes
2. Check digital signatures of both processes
3. Review process execution history
4. Analyze memory artifacts if available
5. Look for related persistence mechanisms
6. Check for outbound network connections
7. Assess scope across other endpoints

---

## 7. Correlation Opportunities

Higher confidence when correlated with:
- Ingress tool transfer
- C2 communication
- Credential dumping
- Suspicious process execution
- Privilege escalation alerts

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- Security tools (AV/EDR)
- Accessibility software
- Debugging tools
- Legitimate application hooks

Maintain allowlists for known injectors.

---

## 9. Response Actions

- Immediately isolate the affected host
- Terminate malicious processes
- Capture memory for forensic analysis
- Block associated hashes and IOCs
- Reset credentials if privilege theft is suspected
- Perform full endpoint remediation

---

## 10. Mapping to MITRE ATT&CK

- **T1055 – Process Injection**
  - T1055.001 – Dynamic-link Library Injection
  - T1055.002 – Portable Executable Injection
  - T1055.003 – Thread Execution Hijacking
  - T1055.004 – Asynchronous Procedure Call
  - T1055.012 – Process Hollowing
