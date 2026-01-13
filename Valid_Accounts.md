# Detection Playbook: Valid Accounts  
**MITRE ATT&CK Technique:** T1078 – Valid Accounts

---

## 1. Technique Overview

Valid Accounts refers to attackers **using legitimate credentials** to access systems, rather than exploiting software vulnerabilities.  
These credentials may be obtained through phishing, credential dumping, password reuse, or purchasing stolen credentials.

Because the attacker logs in “normally,” this technique is **harder to detect** than malware-based attacks.

Common account types abused:
- Domain user accounts
- Local administrator accounts
- Service accounts
- Cloud accounts (IAM users, SSO identities)

---

## 2. Why This Matters

Valid Accounts usage allows attackers to:
- Bypass many security controls
- Blend in with normal user activity
- Move laterally without malware
- Maintain persistence for long periods
- Access sensitive systems and data

Many major breaches succeed **without exploits**—only stolen credentials.

---

## 3. Log Sources

Key logs for detecting Valid Account abuse:
- Windows Security Logs (4624, 4625, 4648, 4672)
- Authentication logs (AD, Azure AD, Okta)
- VPN and remote access logs
- EDR identity telemetry
- Cloud audit logs (AWS CloudTrail, Azure, GCP)
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- Logins from unusual geolocations or IPs
- Access outside normal working hours
- Login attempts across multiple systems in short time
- Privileged logins without prior elevation activity
- Successful logins following multiple failures
- Service accounts used interactively

### Example Pseudo-Logic
IF Authentication = Success
AND User uses new device OR new location
AND No MFA challenge observed
THEN Alert

yaml
Copy code

### Key Fields Used
- Username / Account ID
- Source IP / Geolocation
- Authentication method
- Logon type
- Timestamp
- Privilege level
- MFA status

---

## 5. Alert Example

**Alert Name:** Suspicious Use of Valid Account  
**Severity:** High  

**Description:**  
A successful login using valid credentials was detected from an unusual source and does not match the user’s normal behavior.

**Key Details:**
- User: finance-admin
- Source IP: 203.0.113.88
- Location: Outside expected region
- Logon Type: Remote
- MFA: Not observed
- Time: 03:41 AM

---

## 6. Investigation Steps

1. Confirm whether the login was legitimate
2. Validate the source IP and device
3. Review prior authentication failures
4. Check for additional activity after login
5. Determine whether the account is privileged
6. Identify potential credential theft sources
7. Review recent phishing or malware alerts

---

## 7. Correlation Opportunities

Higher confidence when correlated with:
- Phishing detections
- Credential dumping alerts
- Lateral movement activity
- Privilege escalation events
- New persistence mechanisms
- Access to sensitive resources

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- User traveling or using a VPN
- After-hours work
- New device enrollment
- Password resets followed by login
- Automated service account behavior

Baselines and identity context reduce noise.

---

## 9. Response Actions

- Verify activity with the user
- Force password reset
- Revoke active sessions
- Enable or enforce MFA
- Isolate affected systems if needed
- Review permissions and access scope
- Document findings and lessons learned

---

## 10. Mapping to MITRE ATT&CK

- **T1078 – Valid Accounts**
  - T1078.001 – Default Accounts
  - T1078.002 – Domain Accounts
  - T1078.003 – Local Accounts
  - T1078.004 – Cloud Accounts
