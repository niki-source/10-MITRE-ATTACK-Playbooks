# Detection Playbook: Network Service Discovery  
**MITRE ATT&CK Technique:** T1046 – Network Service Discovery

---

## 1. Technique Overview

Network Service Discovery occurs when an attacker **scans a network to identify active services and open ports** on hosts.  
This helps the attacker understand **what systems exist, what services are running, and which targets are vulnerable**.

Common methods include:
- Port scanning (e.g., TCP/UDP)
- Service enumeration
- Banner grabbing
- Automated scanning tools (Nmap, Masscan)

This activity typically happens during **reconnaissance or early lateral movement planning**.

---

## 2. Why This Matters

Network Service Discovery is often a **precursor to exploitation**.

Attacker goals:
- Identify vulnerable services (RDP, SMB, SSH, databases)
- Map the internal network
- Select targets for lateral movement
- Avoid noisy attacks by choosing high-value systems

Discovery activity itself may not cause damage, but it enables everything that comes after.

---

## 3. Log Sources

Logs useful for detecting Network Service Discovery:
- Firewall logs
- Network IDS/IPS alerts
- NetFlow / network traffic logs
- EDR network telemetry
- Windows Security Logs (5156, 5158)
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- One host connecting to many ports on a single destination
- One host scanning the same port across many hosts
- Rapid connection attempts in a short time window
- Connections to uncommon or unused ports
- Scanning activity originating from a workstation

### Example Pseudo-Logic
IF Source_IP connects to > X unique ports
OR Source_IP connects to > Y unique hosts
WITHIN Z minutes
THEN Alert

yaml
Copy code

### Key Fields Used
- Source IP
- Destination IP
- Destination Port
- Protocol (TCP/UDP)
- Connection Count
- Timestamp

---

## 5. Alert Example

**Alert Name:** Network Service Discovery Detected  
**Severity:** Medium–High  

**Description:**  
A host was observed making multiple connection attempts across numerous ports and systems, consistent with network scanning behavior.

**Key Details:**
- Source IP: 10.10.10.45
- Destination Hosts: 27
- Ports Scanned: 22, 80, 135, 139, 445, 3389
- Time Window: 3 minutes

---

## 6. Investigation Steps

1. Identify the source host and owner
2. Determine if scanning activity is authorized
3. Check for known scanning tools or processes
4. Review authentication and login activity from the source host
5. Look for follow-on exploitation attempts
6. Validate whether the host shows signs of compromise

---

## 7. Correlation Opportunities

Higher confidence when correlated with:
- Credential access alerts
- Lateral movement detections
- Exploitation attempts
- Suspicious process execution
- External C2 communication

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- Vulnerability scanners
- Network monitoring tools
- IT asset discovery
- Penetration testing or red team activity

Maintain allowlists for approved scanners and tools.

---

## 9. Response Actions

- Confirm legitimacy of scanning activity
- Isolate the host if unauthorized
- Block suspicious IPs if needed
- Capture network traffic for deeper analysis
- Reset credentials if compromise is suspected
- Update detection thresholds if necessary

---

## 10. Mapping to MITRE ATT&CK

- **T1046 – Network Service Discovery**
  - Related tactics: Discovery, Lateral Movement
  - Often paired with:
    - T1018 – Remote System Discovery
    - T1021 – Remote Services
    - T1087 – Account Discovery

