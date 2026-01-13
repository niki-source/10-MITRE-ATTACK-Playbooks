# Detection Playbook: Application Layer Protocol (C2)  
**MITRE ATT&CK Technique:** T1071 – Application Layer Protocol

---

## 1. Technique Overview

Application Layer Protocol is used by attackers to **establish Command and Control (C2) channels** over common application protocols.  
By using normal-looking traffic (such as web or DNS), attackers can **blend malicious communications into legitimate network activity**.

Common protocols abused:
- HTTP / HTTPS
- DNS
- SMTP
- FTP

These channels allow attackers to:
- Send commands to compromised systems
- Receive stolen data
- Maintain persistent access

---

## 2. Why This Matters

C2 communication means the attacker:
- Has an active foothold
- Can control infected systems remotely
- Can deploy additional tools
- Can exfiltrate data

Detecting C2 traffic often confirms **active compromise**, not just reconnaissance.

---

## 3. Log Sources

Logs useful for detecting Application Layer C2:
- Proxy / web gateway logs
- DNS query logs
- Network Detection & Response (NDR)
- Firewall egress logs
- EDR network telemetry
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- Regular beaconing intervals
- Repeated connections to rare or newly registered domains
- Small, periodic outbound data transfers
- Encrypted traffic on non-standard ports
- DNS queries with long or random-looking subdomains

### Example Pseudo-Logic
IF Outbound connections show periodic beaconing
AND Destination domain reputation = Low
AND No business justification
THEN Alert

yaml
Copy code

### Key Fields Used
- Source host
- Destination IP / domain
- Protocol
- Port
- Request frequency
- Data size
- Timestamp

---

## 5. Alert Example

**Alert Name:** Suspicious C2 Communication Detected  
**Severity:** Critical  

**Description:**  
A host is making repeated outbound connections consistent with command-and-control behavior over an application layer protocol.

**Key Details:**
- Host: WKSTN-17
- Protocol: HTTPS
- Destination Domain: update-checker[.]xyz
- Interval: Every 60 seconds
- Data Size: ~300 bytes per request

---

## 6. Investigation Steps

1. Identify the destination domain and IP
2. Check domain age and reputation
3. Review traffic patterns and frequency
4. Validate whether the protocol usage is legitimate
5. Inspect endpoint activity around beacon times
6. Look for downloaded payloads or executed commands
7. Check for similar traffic from other hosts

---

## 7. Correlation Opportunities

Higher confidence when correlated with:
- Ingress tool transfer
- Process injection
- Suspicious process execution
- Persistence mechanisms
- Credential access activity

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- Software update services
- Telemetry or monitoring tools
- Cloud service APIs
- CDNs and content delivery services

Allowlist known benign domains and update servers.

---

## 9. Response Actions

- Isolate affected hosts
- Block malicious domains/IPs
- Capture network traffic for analysis
- Perform full endpoint scans
- Reset credentials if needed
- Monitor for reinfection

---

## 10. Mapping to MITRE ATT&CK

- **T1071 – Application Layer Protocol**
  - T1071.001 – Web Protocols
  - T1071.002 – File Transfer Protocols
  - T1071.003 – Mail Protocols
  - T1071.004 – DNS
