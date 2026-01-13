# Detection Playbook: Phishing  
**MITRE ATT&CK Technique:** T1566 – Phishing

---

## 1. Technique Overview

Phishing is a technique where attackers **deceive users into revealing credentials, executing malware, or visiting malicious sites** by pretending to be a trusted entity.  
It is one of the most common **initial access** vectors and often leads to credential theft, malware execution, or account compromise.

Common phishing methods include:
- Malicious email attachments
- Credential-harvesting links
- HTML smuggling
- QR-code phishing (quishing)
- Business Email Compromise (BEC)

---

## 2. Why This Matters

Phishing is responsible for a **large percentage of real-world breaches**.

Attacker goals:
- Steal credentials
- Deliver malware or payloads
- Gain initial foothold
- Bypass perimeter defenses by exploiting human trust

One successful phishing email can compromise an entire environment.

---

## 3. Log Sources

Logs useful for detecting Phishing activity:
- Email security gateway logs (Proofpoint, M365, Google Workspace)
- User-reported phishing alerts
- EDR process and file telemetry
- Proxy / DNS logs
- Authentication logs
- SIEM platforms (Splunk, Elastic)

---

## 4. Detection Logic

### Behavioral Indicators
- Emails with suspicious sender domains
- Unexpected attachments or links
- Users clicking links shortly after email delivery
- Attachment execution from email clients
- Login attempts following email interaction

### Example Pseudo-Logic
IF Email contains suspicious link OR attachment
AND User clicks link OR opens attachment
THEN Alert

yaml
Copy code

### Key Fields Used
- Sender email address
- Sender domain reputation
- Recipient
- Attachment name and type
- URL clicked
- Timestamp
- User interaction status

---

## 5. Alert Example

**Alert Name:** Phishing Email Interaction Detected  
**Severity:** High  

**Description:**  
A user interacted with a suspected phishing email, potentially exposing credentials or executing malicious content.

**Key Details:**
- User: n.kalkeri@company.com
- Sender: billing@secure-payments[.]co
- Subject: “Urgent Invoice Review”
- Action: Link Clicked
- Time: 10:22 AM

---

## 6. Investigation Steps

1. Review the email content and headers
2. Check sender and domain reputation
3. Confirm user interaction (click, open, download)
4. Determine if credentials were entered
5. Check endpoint for malware execution
6. Review authentication activity post-click
7. Identify other recipients of the same email

---

## 7. Correlation Opportunities

Higher confidence when correlated with:
- Valid account abuse
- Ingress tool transfer
- Malware execution
- MFA bypass attempts
- Unusual authentication behavior

---

## 8. False Positives

Legitimate activity that may trigger alerts:
- Internal test phishing campaigns
- Marketing emails with tracking links
- User-reported suspicious but benign emails

Label training campaigns clearly to reduce noise.

---

## 9. Response Actions

- Remove the email from all inboxes
- Reset affected user credentials
- Enforce or re-verify MFA
- Scan affected endpoints
- Block malicious domains and senders
- Educate the user on phishing indicators

---

## 10. Mapping to MITRE ATT&CK

- **T1566 – Phishing**
  - T1566.001 – Spearphishing Attachment
  - T1566.002 – Spearphishing Link
  - T1566.003 – Spearphishing via Service
