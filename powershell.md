# Detection Playbook: PowerShell Execution
MITRE ATT&CK Technique: T1059.001 – PowerShell

## 1. Technique Overview
Adversaries abuse **PowerShell** to execute commands and scripts on compromised systems 
in order to perform malicious actions while blending in with legitimate administrative activity. 
PowerShell provides deep access to the Windows operating system, allowing attackers to download payloads, 
execute code in memory, gather system information, and establish persistence.

Because PowerShell is a native Windows tool commonly used by administrators and IT automation, 
its malicious use can be difficult to distinguish from normal activity. Attackers often leverage PowerShell for **fileless attacks**, 
using encoded or obfuscated commands to evade traditional security controls and reduce forensic artifacts on disk.

## 2. Why This Matters
PowerShell abuse is a high-impact technique because it allows attackers to execute powerful commands using 
a **trusted, built-in Windows tool**. Since PowerShell is commonly used for system administration and automation, 
malicious activity can easily blend in with legitimate behavior, making detection challenging.

### Impact
- Enables **fileless malware execution**, leaving minimal artifacts on disk
- Allows attackers to **download and execute payloads directly in memory**
- Provides access to detailed system and domain information
- Supports automation of malicious actions at scale

### Attacker Goals
- Evade traditional antivirus and signature-based detection
- Maintain stealth by abusing legitimate administrative tools (LOLBins)
- Rapidly progress from initial access to persistence, credential theft, or lateral movement
- Execute commands remotely with minimal user interaction

### Why Defenders Care
PowerShell activity often represents an early execution stage of an attack. Failure to detect malicious PowerShell usage 
can allow adversaries to quickly escalate privileges, spread across the environment, or establish command-and-control without deploying obvious malware.

## 3. Log Sources
Detection of **PowerShell abuse** relies on visibility into process execution, script activity, and endpoint telemetry. The following log sources are critical:

- **Windows Security Logs**
  - Event ID **4688** – Process Creation  
  - Captures PowerShell execution, command-line arguments, parent process, and user context

- **EDR Telemetry**
  - PowerShell process creation and process tree relationships
  - Command-line parameters and encoded command detection
  - File, memory, and network activity associated with PowerShell

- **PowerShell Operational Logs**
  - Script Block Logging
  - Module and command execution details
  - PowerShell engine start and stop events

- **SIEM (Splunk / Elastic)**
  - Centralized aggregation and normalization of PowerShell events
  - Correlation with network, authentication, and endpoint alerts
  - Historical baselining and alerting

**Why These Matter**  
PowerShell Operational logs provide deep visibility into script content, while Security and EDR logs 
capture execution context. When correlated in a SIEM, these sources enable high-confidence detection of malicious PowerShell activity.

## 4. Detection Logic
Detection focuses on identifying **abnormal PowerShell behavior** that deviates from normal administrative or automation usage.

### Behavioral Indicators
- PowerShell executed with **encoded or obfuscated commands**
  - Use of `-enc`, `-EncodedCommand`, or long Base64 strings
- PowerShell launched by **unusual parent processes**
  - Microsoft Office applications (Word, Excel)
  - Browsers or email clients
- PowerShell running under **unexpected user contexts**
  - Non-admin users
  - Service accounts
- Execution followed by **network activity**
  - Downloads from external URLs
  - DNS queries to unknown or newly registered domains
- PowerShell spawning additional processes rapidly

---

### Example Detection Logic (Pseudo-Logic) 
IF process_name = powershell.exe
AND (
command_line CONTAINS "-enc"
OR command_line CONTAINS "EncodedCommand"
OR parent_process IN (winword.exe, excel.exe, outlook.exe)
)
THEN alert = Suspicious PowerShell Execution


## 5. Alert Example
### Alert Name
Suspicious PowerShell Encoded Command Execution

### Alert Description
PowerShell was executed with encoded command-line arguments, a common technique used for fileless malware execution and post-exploitation activity.

### MITRE ATT&CK Mapping
- Technique: T1059 – Command & Scripting Interpreter
- Sub-technique: T1059.001 – PowerShell

### Alert Severity
High

### Sample Alert Details
- **Host:** WIN-ACCT-07
- **User:** jdoe
- **Process Name:** powershell.exe
- **Command Line:**
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA


- **Parent Process:** winword.exe
- **Process ID:** 4820
- **Timestamp:** 2026-01-07 15:41:22 UTC

### Why This Alert Triggered
- Use of Base64-encoded PowerShell commands
- PowerShell spawned by an Office application
- Execution occurred under a standard user context

### Analyst Notes
Encoded PowerShell launched from Microsoft Word is a common post-phishing execution pattern and is frequently associated with malware delivery and command execution.

### Recommended Immediate Actions
- Decode and review the PowerShell command
- Investigate the originating document or email
- Check for related network connections or file creation
- Escalate and isolate the host if malicious activity is confirmed

## 6. Investigation Steps
Use the following checklist to investigate alerts related to **suspicious PowerShell activity**.

### Step 1: Validate the Alert
- Confirm the process is `powershell.exe`
- Review the full command-line arguments
- Identify the parent process that launched PowerShell
- Verify the host, user, and timestamp

### Step 2: Assess User Context
- Determine whether the user normally runs PowerShell scripts
- Check user privilege level (standard user vs administrator)
- Identify service or automation accounts
- Look for signs of compromised credentials

### Step 3: Analyze the Command
- Identify encoded or obfuscated content (`-enc`, `-EncodedCommand`)
- Decode Base64 commands if present
- Determine command intent (download, execution, reconnaissance)
- Check for known malicious PowerShell functions or patterns

### Step 4: Review Process Tree
- Examine parent-child process relationships
- Identify suspicious chains (e.g., Office → PowerShell)
- Check for PowerShell spawning additional tools or scripts
- Look for rapid or repeated PowerShell execution

### Step 5: Check for Follow-On Activity
- Review outbound network connections after execution
- Check DNS queries and contacted domains
- Identify file creation, registry changes, or scheduled tasks
- Look for credential access or lateral movement indicators

### Step 6: Correlate Related Alerts
- Search for similar PowerShell executions on other hosts
- Correlate with phishing, email, or web gateway alerts
- Check for repeated activity within a short time window

### Step 7: Determine Severity and Scope
- Assess whether activity is isolated or widespread
- Determine if behavior is malicious or a false positive
- Assign appropriate alert severity

### Step 8: Respond and Document
- Escalate and isolate the host if malicious behavior is confirmed
- Preserve logs and artifacts for further analysis
- Reset credentials if compromise is suspected
- Document findings and map to MITRE ATT&CK

## 7. Correlation Opportunities
Correlation increases confidence by linking **PowerShell execution** with other suspicious activity across endpoint, network, and user telemetry. The following correlations help confirm malicious PowerShell usage.

### PowerShell + Network Activity
- PowerShell execution followed by outbound network connections
- DNS queries to newly registered or low-reputation domains
- HTTP/HTTPS requests initiated by PowerShell scripts
- Connections to known command-and-control infrastructure

### PowerShell + Initial Access Indicators
- PowerShell execution shortly after:
  - Phishing email delivery
  - Attachment opening or macro execution
  - Malicious URL click events

### PowerShell + Process Behavior
- Office applications spawning PowerShell
- Browsers or scripting engines launching PowerShell
- PowerShell spawning additional tools or scripts

### PowerShell + Credential or Discovery Activity
- PowerShell commands querying Active Directory or system credentials
- Execution of discovery-related commands (users, groups, network info)
- Access to LSASS or credential-related files or APIs

### PowerShell + Persistence Indicators
- Script execution followed by:
  - Scheduled task creation
  - Registry run key modifications
  - Startup folder changes
  - WMI event subscriptions

### Cross-Host Correlation
- Similar PowerShell commands executed on multiple hosts
- Repeated execution patterns within short time windows
- Shared encoded commands or script content across systems

**Why This Matters**  
Single PowerShell executions may be benign. Correlating them with network, user, and
persistence activity significantly increases confidence and reduces false positives.

## 8. False Positives
Not all PowerShell activity is malicious. The following legitimate behaviors may trigger alerts and should be evaluated during investigation.

### Administrative and IT Operations
- System administrators running PowerShell for configuration or maintenance
- Patch management or system update scripts
- Endpoint management tools executing PowerShell commands

### Developer and Automation Activity
- Developers running PowerShell for testing or automation
- CI/CD pipelines executing PowerShell scripts
- Scheduled automation tasks and startup scripts

### Enterprise Tools and Security Software
- EDR, AV, or monitoring tools using PowerShell internally
- Configuration management platforms (e.g., SCCM, Intune)
- Backup or monitoring agents invoking PowerShell

### Contextual Indicators of Benign Activity
- Known and trusted parent processes
- Execution from standard system directories
- Commands consistent with job role and historical behavior
- Script paths located in approved repositories

**Analyst Guidance**  
PowerShell abuse detection requires careful context evaluation.
Focus on command content, parent process, user role, and follow-on behavior before escalating.

## 9. Response Actions
Response actions should be based on the **severity and confidence** of the alert. If malicious PowerShell activity is confirmed, take the following steps.

### Containment
- Isolate the affected endpoint from the network
- Terminate malicious PowerShell processes
- Block associated IP addresses, domains, or URLs
- Disable or lock compromised user accounts

### Eradication
- Remove malicious PowerShell scripts and downloaded payloads
- Delete persistence mechanisms (scheduled tasks, registry run keys, WMI subscriptions)
- Clean up malicious files from user or temp directories
- Reimage the system if compromise is extensive

### Recovery
- Restore systems from known-good backups if needed
- Re-enable network access after validation
- Reset credentials and enforce password changes
- Monitor for recurring PowerShell activity

### Post-Incident Actions
- Document actions taken and investigation findings
- Update PowerShell detection rules and alert thresholds
- Improve logging (enable Script Block Logging if not already enabled)
- Conduct a lessons-learned review

**Goal**  
Stop malicious PowerShell execution quickly, remove all attacker footholds, and restore systems to a secure operational state.

## 10. Mapping to MITRE
This playbook maps to **PowerShell abuse** within the :contentReference[oaicite:0]{index=0} Enterprise framework.

### Primary Technique
- **T1059 – Command & Scripting Interpreter**
  - Adversaries execute commands and scripts using native interpreters to control systems and perform malicious actions.

### Primary Sub-Technique
- **T1059.001 – PowerShell**
  - Adversaries abuse PowerShell to execute commands, download payloads, perform discovery, establish persistence, and conduct fileless attacks.

### Commonly Associated Techniques
PowerShell activity is often observed alongside:
- **T1027 – Obfuscated Files or Information** (encoded or obfuscated commands)
- **T1105 – Ingress Tool Transfer** (downloading payloads via PowerShell)
- **T1055 – Process Injection** (PowerShell spawning injected processes)
- **T1082 – System Information Discovery**
- **T1053 – Scheduled Task/Job** (persistence via PowerShell)

### Defensive Value
Mapping PowerShell alerts to MITRE ATT&CK:
- Provides standardized attacker behavior classification
- Enables consistent detection coverage tracking
- Supports reporting, metrics, and threat hunting alignment
