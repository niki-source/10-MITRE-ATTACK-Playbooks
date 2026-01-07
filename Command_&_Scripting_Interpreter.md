# Detection Playbook: Command & Scripting Interpreter
MITRE ATT&CK Technique: T1059 – Command & Scripting Interpreter

## 1. Technique Overview
Adversaries abuse command and scripting interpreters to execute commands on a compromised system. 
These interpreters allow attackers to run system commands, download payloads, perform reconnaissance, move laterally,
and maintain persistence. Because these tools are native to operating systems, their use often blends in with legitimate administrative activity.

## 2. Why This Matters
Abuse of command and scripting interpreters gives attackers a powerful and flexible way to control 
a compromised system while blending in with legitimate activity. Because tools like PowerShell, 
cmd.exe, and bash are built into operating systems, their malicious use can be difficult to distinguish from normal administrative behavior.

** Impact **

* Enables remote command execution and full system control
* Supports fileless attacks, reducing forensic artifacts on disk
* Allows rapid automation of malicious actions across hosts
* Facilitates follow-on activity such as credential theft, lateral movement, and data exfiltration

** Attacker Goals **

* Execute payloads without deploying obvious malware
* Maintain stealth by abusing trusted system utilities (LOLBins)
* Establish persistence or prepare the environment for later attack stages
* Move quickly from initial access to broader compromise

** Why Defenders Care **
Failure to detect malicious interpreter usage often means the attacker has already progressed beyond initial access. 
Early detection at this stage can prevent escalation into privilege abuse, widespread lateral movement, or command-and-control activity.

## 3. Log Sources
### Endpoint / Host-Based Logs
- **Windows Security Logs**
  - Event ID **4688** – Process Creation  
  - Captures interpreter execution, command-line arguments, parent process, and user context
- **PowerShell Operational Logs**
  - Script block logging  
  - Module and command execution details
- **Linux / macOS Process Logs**
  - Bash or shell command execution  
  - Auditd / syslog process events

### EDR / Endpoint Telemetry
- Process creation and process tree data
- Command-line arguments and parent-child relationships
- User context and privilege level
- File and memory activity related to script execution

### Network Logs (Supporting Evidence)
- DNS logs (script-driven callbacks or downloads)
- Proxy / web gateway logs (payload retrieval)
- Firewall logs (outbound connections following execution)

### SIEM Data
- Normalized process execution events
- Correlated alerts across endpoint and network telemetry
- Historical execution patterns for baseline comparison

## 4. Detection Logic
Detection focuses on identifying **abnormal or high-risk usage** of command and 
scripting interpreters by analyzing process behavior, command-line arguments, user context, and follow-on activity.

### High-Level Detection Conditions
Trigger alerts when one or more of the following are observed:

- Command interpreters execute with **encoded, obfuscated, or suspicious arguments**
- Interpreters are launched by **unusual parent processes** (e.g., Office applications, browsers)
- Command interpreters run under **unexpected user contexts** (non-admin users, service accounts)
- Interpreters execute from **non-standard or user-writable directories**
- Interpreter execution is followed by **network connections, file writes, or credential access**

### Behavioral Indicators
- Use of Base64-encoded commands (e.g., `-enc`, `-EncodedCommand`)
- Rapid execution of multiple commands or scripts
- Script execution shortly after phishing attachment or macro execution
- Parent-child process chains that do not align with normal system behavior

### Correlation Opportunities
- Interpreter execution + outbound network connection
- Interpreter execution + credential-related events
- Repeated interpreter execution across multiple hosts within a short time window

**Goal**  
Identify malicious command execution early while minimizing false positives from legitimate administrative or development activity.

## 5. Alert Example
### Alert Name
Suspicious PowerShell Command Execution

### Alert Description
PowerShell was executed with encoded command-line arguments, which may indicate malicious command execution or fileless attack activity.

### MITRE ATT&CK Mapping
- Technique: T1059 – Command & Scripting Interpreter  
- Sub-technique: PowerShell (T1059.001)

### Alert Severity
High

### Sample Alert Data
- **Host:** WIN-USER-23
- **User:** NT AUTHORITY\SYSTEM
- **Process Name:** powershell.exe
- **Command Line:**  powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...
- **Parent Process:** winword.exe
- **Timestamp:** 2026-01-07 14:32:10 UTC

### Why This Alert Triggered
- PowerShell executed with Base64-encoded commands
- Unusual parent process (Microsoft Word)
- Execution occurred under a high-privilege context

### Analyst Notes
Encoded PowerShell launched by an Office application is a common post-phishing execution pattern and is strongly associated with malicious activity.

### Recommended Next Steps
- Decode and review the PowerShell command
- Check for related network connections or file creation
- Investigate the originating document or email
- Isolate the host if malicious activity is confirmed

## 6. Investigation Steps
Use the following checklist to triage alerts related to **Command & Scripting Interpreter** activity.

### Step 1: Validate the Alert
- Confirm the command interpreter involved (PowerShell, cmd.exe, bash, etc.)
- Review the full command-line arguments
- Identify the parent process that launched the interpreter
- Check the execution timestamp and host

### Step 2: Assess User Context
- Identify the user or service account that executed the command
- Determine if the user normally runs scripts or admin tools
- Verify privilege level (standard user vs administrator)
- Look for signs of impersonation or token misuse

### Step 3: Analyze Command Behavior
- Check for encoded, obfuscated, or suspicious parameters
- Decode Base64 or obfuscated commands if present
- Identify actions performed (download, execution, reconnaissance)
- Determine whether the command aligns with normal activity

### Step 4: Review Process Tree
- Examine parent and child processes
- Identify unusual process chains (e.g., Office → PowerShell)
- Look for rapid or repeated interpreter execution
- Check for spawned tools commonly used by attackers

### Step 5: Check for Follow-On Activity
- Review network connections after execution
- Look for DNS queries or outbound connections to unknown domains
- Identify file creation, registry changes, or scheduled tasks
- Check for credential access or lateral movement indicators

### Step 6: Search for Related Activity
- Look for similar interpreter executions on other hosts
- Check for repeated activity within a short time window
- Correlate with phishing, email, or web gateway alerts

### Step 7: Determine Severity and Scope
- Assess whether activity is isolated or widespread
- Determine if the behavior is malicious or a false positive
- Assign appropriate alert severity

### Step 8: Respond and Document
- Isolate the host if malicious activity is confirmed
- Preserve relevant logs and artifacts
- Reset credentials if compromise is suspected
- Document findings and map to MITRE ATT&CK

## 7. Correlation Opportunities
Correlation strengthens confidence by linking **command and scripting interpreter execution** with other suspicious activity across hosts, users, and time windows. The following correlations help distinguish malicious behavior from legitimate administration.

### Process + Network Activity
- Interpreter execution followed by outbound network connections
- DNS queries to newly registered or low-reputation domains
- Script-driven downloads via HTTP/HTTPS or PowerShell web requests

### Process + User Behavior
- Command execution by users who do not normally run scripts
- Interpreter activity from service accounts or non-interactive users
- Execution outside normal business hours

### Process + Parent/Child Relationships
- Office applications spawning PowerShell, cmd.exe, or scripting engines
- Browsers launching command interpreters
- Interpreters spawning credential access or discovery tools

### Process + Persistence Indicators
- Script execution followed by:
  - Scheduled task creation
  - Registry run key modifications
  - Startup folder changes

### Cross-Host Correlation
- Similar interpreter commands executed on multiple hosts
- Repeated execution patterns within a short time window
- Shared command-line arguments or scripts across systems

### Email / Initial Access Correlation
- Interpreter execution shortly after:
  - Phishing email delivery
  - Attachment or macro execution
  - Malicious URL click events

**Why This Matters**  
Single interpreter executions can be benign. Correlating them with network, user, and persistence activity helps confirm attacker intent and reduces false positives.

## 8. False Positives
Not all command and scripting interpreter activity is malicious. The following legitimate behaviors may trigger alerts and should be evaluated during triage.

### Administrative Activity
- IT administrators running PowerShell or command-line scripts
- System maintenance or configuration scripts
- Software installation, patching, or update processes

### Developer and Power User Activity
- Developers executing Python, PowerShell, or shell scripts
- Use of scripting tools for testing, automation, or debugging
- Execution from development environments or known script repositories

### Automated System Processes
- Scheduled tasks or startup scripts
- Endpoint management tools (e.g., software deployment agents)
- Backup or monitoring agents executing scripts

### Enterprise Security and IT Tools
- EDR or AV tools running command-line utilities
- Configuration management platforms (e.g., SCCM, Ansible)
- Log collection or monitoring scripts

### Contextual Clues That Suggest Benign Activity
- Known and trusted parent processes
- Execution from standard system directories
- Commands align with normal job responsibilities
- Activity matches historical baselines for the user or host

**Analyst Guidance**  
False positives are common for this technique. Focus on command-line content, user context, parent process, and follow-on behavior before escalating.

## 9. Response Actions
Response actions should be based on the **severity and confidence** of the alert. If malicious command or scripting activity is confirmed, take the following steps.

### Containment
- Isolate the affected host from the network
- Terminate malicious processes or scripts
- Block associated IP addresses, domains, or URLs
- Disable compromised user or service accounts

### Eradication
- Remove malicious scripts, files, or scheduled tasks
- Delete persistence mechanisms (registry keys, startup items)
- Clean or reimage the system if required
- Apply security patches or configuration fixes

### Recovery
- Restore systems from known-good backups if needed
- Re-enable network connectivity after validation
- Reset credentials and enforce password changes
- Monitor the host for recurring activity

### Post-Incident Actions
- Document findings and actions taken
- Update detection logic or SIEM rules to prevent recurrence
- Map confirmed behavior to MITRE ATT&CK techniques
- Conduct a lessons-learned review

**Goal**  
Stop attacker activity quickly, remove all malicious artifacts, and restore systems to a secure operational state.

## 10. Mapping to MITRE
### Primary Technique
- **T1059 – Command & Scripting Interpreter**
  - Adversaries execute commands or scripts using native interpreters to control systems and perform malicious actions.

### Related Sub-Techniques
- **T1059.001 – PowerShell**
  - Abuse of PowerShell for command execution, automation, and fileless attacks
- **T1059.003 – Windows Command Shell**
  - Use of `cmd.exe` to run system commands or scripts
- **T1059.004 – Unix Shell**
  - Execution of shell commands on Linux or macOS systems
- **T1059.006 – Python**
  - Use of Python interpreters to run malicious scripts
- **T1059.007 – JavaScript**
  - Execution of JavaScript via scripting engines or system utilities

### Defensive Value
Mapping alerts and investigations to MITRE ATT&CK:
- Provides a **common language** for analysts and teams
- Helps track **attacker behavior across incidents**
- Enables consistent reporting and detection coverage analysis
