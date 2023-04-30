File Deletion: To detect file deletion, you can use the following RegEx to search for events where a file has been deleted:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4660
| regex Object_Name=".*\\.(doc|xls|pdf)$"

Remote Access: To detect remote access attempts, you can use the following RegEx to search for events where a user has logged in from a remote location:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| regex Workstation_Name="^-\[0-9\]$"

Data Exfiltration: To detect data exfiltration attempts, you can use the following RegEx to search for events where a user has uploaded files to an external location:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=5145
| regex Share_Name="^\\\\[A-Za-z0-9_-]+(\\\\[A-Za-z0-9_-]+)+$"

Command Execution: To detect command execution attempts, you can use the following RegEx to search for events where a command has been executed:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex New_Process_Name="cmd.exe" CommandLine=".*"

Persistence: To detect persistence techniques used by adversaries, you can use the following RegEx to search for events where a new service has been created:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4697
| regex Service_Name=".*"

Lateral Movement: To detect lateral movement attempts, you can use the following RegEx to search for events where a user has connected to a remote system:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
| regex Logon_Process=".*\\sscm$"

Privilege Escalation: To detect privilege escalation attempts, you can use the following RegEx to search for events where a user has obtained admin privileges:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4672
| regex Privilege_List=".*SeDebugPrivilege.*"

Reconnaissance: To detect reconnaissance attempts, you can use the following RegEx to search for events where a user has queried for system information:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688 CommandLine=".*systeminfo.*"

Credential Dumping: To detect credential dumping attempts, you can use the following RegEx to search for events where a process has accessed the LSASS process:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663 Accesses=".*ReadData.*" Object_Name="*\\lsass.exe"
| regex Process_Name=".*"

Defense Evasion: To detect attempts to evade security defenses, you can use the following RegEx to search for events where a process has spawned a new process using the CreateProcess API:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688 Parent_Process_Name!="svchost.exe"
| regex Process_Name=".*CreateProcess.*"

Execution through API: To detect attempts to execute malicious code through legitimate APIs, you can use the following RegEx to search for events where a process has called a Windows API:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex Process_Command_Line=".*[A-Z]:\\\\(Windows|Program Files)\\\\.*"

Data Encrypted: To detect attempts to encrypt data, you can use the following RegEx to search for events where a process has accessed an encrypted file:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4656 Accesses=".*ReadData.*" Object_Name="*\\*.encrypted"
| regex Process_Name=".*"

Network Sniffing: To detect attempts to perform network sniffing, you can use the following RegEx to search for events where a process has created a network socket:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4689
| regex Process_Name=".*socket.*"

Process Injection: To detect attempts to inject malicious code into a process, you can use the following RegEx to search for events where a process has opened a remote process:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4658 Access_Mask=".*0x100.*" Object_Type="Process"
| regex Subject_Logon_Id=".*" Target_User_Name=".*"

DNS Tunneling: To detect attempts to use DNS tunneling to bypass security controls, you can use the following RegEx to search for DNS queries containing base64-encoded data:
index=SecnNet sourcetype="stream:DNS"
| regex query=".*[a-zA-Z0-9+/]{4,}.*"

DLL Side-loading: To detect attempts to side-load a DLL file, you can use the following RegEx to search for events where a process has loaded a DLL from a non-standard location:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex Image=".*\\\\(Windows|Program Files)\\\\.*" Target_Image=".*\\\\(Windows|Program Files)\\\\.*"

DNS Spoofing: To detect attempts to spoof DNS responses, you can use the following RegEx to search for events where a DNS query has been redirected to a different IP address:
index=SecnNet sourcetype="stream:DNS"
| regex answer="^.*$|^(?:(?!<your_ip_address>).)*$"

Command and Control: To detect attempts to establish command and control channels, you can use the following RegEx to search for network traffic to known command and control servers:
index=SecnNet sourcetype="stream:tcp"
| regex dest_ip="^((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}))$"

Malicious Email Attachments: To detect malicious email attachments, you can use the following RegEx to search for email attachments with known malicious file extensions:
index=SecnNet sourcetype="mail" Attachment_Name="*.zip|*.rar|*.7z|*.exe|*.bat|*.js|*.jar|*.docm|*.xlsm|*.pptm"

Credential Phishing: To detect attempts to steal credentials through phishing, you can use the following RegEx to search for email messages containing known phishing keywords:
index=SecnNet sourcetype="mail" Subject=".*password.*|.*account.*|.*verify.*|.*reset.*" Message=".*login.*|.*phishing.*|.*scam.*|.*fraud.*"

PowerShell Execution: To detect attempts to execute PowerShell scripts, you can use the following RegEx to search for events where a PowerShell command has been executed:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| regex Message=".*CommandLine:.*"

DNS Tunneling: To detect attempts to use DNS tunneling to exfiltrate data, you can use the following RegEx to search for DNS queries containing non-standard characters:
index=SecnNet sourcetype="stream:DNS"
| regex query=".*[^a-zA-Z0-9.]+.*"

User Account Manipulation: To detect attempts to manipulate user accounts, you can use the following RegEx to search for events where a user account has been modified:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4728
| regex Target_User_Name=".*"

Malware Execution: To detect attempts to execute malware, you can use the following RegEx to search for events where a process has spawned a new process with a known malicious file path:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex New_Process_Name=".*C:\\Users\\Public\\malware.exe.*"

DNS Cache Poisoning: To detect attempts to poison DNS cache, you can use the following RegEx to search for DNS responses with an unexpected source IP address:
index=SecnNet sourcetype="stream:DNS"
| regex answer="^.*$|^(?:(?!<your_ip_address>).)*$"

Spearphishing Link: To detect attempts to conduct spearphishing attacks with malicious links, you can use the following RegEx to search for emails containing suspicious links:
index=SecnNet sourcetype="mail" Subject=".*click.*|.*download.*" Message=".*http[s]?://(?!www\\.example\\.com).*"

Remote Desktop Protocol (RDP) Brute Force: To detect attempts to brute force RDP credentials, you can use the following RegEx to search for failed logon events with multiple logon attempts:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=10
| stats count by src_ip, user
| where count > 10

SQL Injection: To detect attempts to exploit SQL injection vulnerabilities, you can use the following RegEx to search for web server logs containing SQL injection payloads:
index=SecnNet sourcetype="access_combined_wcookie"
| regex uri=".*(\\%27)|(\\')|(\\%3B)|(;).*(\\%3D)|[=].*"

Phishing with Attachment: To detect attempts to conduct phishing attacks with malicious attachments, you can use the following RegEx to search for emails containing suspicious attachments:
index=SecnNet sourcetype="mail" Subject=".*invoice.*|.*payment.*" Attachment_Name=".*.docm|.*.xlsm|.*.pptm|.*.exe|.*.js|.*.vbs|.*.bat"

Remote Access Trojan (RAT): To detect attempts to use remote access trojans to gain unauthorized access, you can use the following RegEx to search for network traffic to known RAT command and control servers:
index=SecnNet sourcetype="stream:tcp" dest_ip="*:*" dest_port="80|443|8080"
| regex dest_ip="^((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}))$"

Cross-Site Scripting (XSS): To detect attempts to exploit cross-site scripting vulnerabilities, you can use the following RegEx to search for web server logs containing XSS payloads:
index=SecnNet sourcetype="access_combined_wcookie"
| regex uri=".*(\\%3C)|(\\<)|(<).*(\\%3E)|(\\>)|(>).*(\\%3C)|(<).*(\\%3E)|(\\>)|(>).*"

Password Spraying: To detect attempts to use password spraying to gain unauthorized access, you can use the following RegEx to search for failed logon events with multiple users and a common password:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by src_ip, user
| where count > 10
| lookup common_passwords user
| where common_passwords != ""

Distributed Denial-of-Service (DDoS): To detect attempts to conduct distributed denial-of-service attacks, you can use the following RegEx to search for network traffic to known botnet command and control servers:
index=SecnNet sourcetype="stream:tcp" dest_port="6667|6697"
| regex dest_ip="^((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}))$"

DLL Search Order Hijacking: To detect attempts to hijack the DLL search order, you can use the following RegEx to search for events where a process has loaded a DLL from a non-standard location:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex Image=".*\\\\(Windows|Program Files)\\\\.*" Target_Image=".*\\\\(Windows|Program Files)\\\\.*"

Remote File Copy: To detect attempts to remotely copy files, you can use the following RegEx to search for events where a file has been copied to a remote location:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| regex Object_Name=".*" Accesses=".*WRITE_DAC.*"
| stats count by Subject_User_Name, Object_Name
| where count > 10

Ransomware: To detect attempts to execute ransomware, you can use the following RegEx to search for events where a process has created multiple files with a non-standard file extension:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| regex Object_Name=".*\\\\.*\\..{3,4}" Accesses=".*WriteData.*"
| stats count by Process_Name, Object_Name
| where count > 10

Command and Control (C2) Communication: To detect attempts to communicate with a known command and control server, you can use the following RegEx to search for network traffic to known C2 IP addresses:
index=SecnNet sourcetype="stream:tcp" dest_ip="1.1.1.1|2.2.2.2|3.3.3.3" dest_port="80|443|8080"

Data Exfiltration: To detect attempts to exfiltrate data, you can use the following RegEx to search for network traffic to known data exfiltration destinations:
index=SecnNet sourcetype="stream:tcp" dest_ip="4.4.4.4|5.5.5.5|6.6.6.6" dest_port="80|443|8080"

Network Sniffing: To detect attempts to sniff network traffic, you can use the following RegEx to search for network traffic to known network sniffing destinations:
index=SecnNet sourcetype="stream:tcp" dest_ip="7.7.7.7|8.8.8.8|9.9.9.9" dest_port="80|443|8080"

Exploit Kit: To detect attempts to exploit vulnerabilities using an exploit kit, you can use the following RegEx to search for web server logs containing suspicious URI paths:
index=SecnNet sourcetype="access_combined_wcookie" uri=".*\\.(php|jsp|aspx)\\?.*=http://.*"

Fileless Malware: To detect attempts to execute fileless malware, you can use the following RegEx to search for events where a process has created and executed code in memory:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex Image=".*\\\\(Windows|Program Files)\\\\.*" CommandLine=".*powershell.exe.*-EncodedCommand.*"

Credential Dumping: To detect attempts to dump credentials, you can use the following RegEx to search for events where a process has dumped LSASS memory:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=10
| regex EventData=".*\\b(?:lsass.exe|lsass)\b.*"

PowerShell Obfuscation: To detect attempts to use PowerShell obfuscation techniques, you can use the following RegEx to search for PowerShell commands containing base64-encoded strings:
index=SecnNet sourcetype="WinEventLog:Windows PowerShell" SourceName="PowerShell"
| regex Message=".*[A-Za-z0-9+/]{100,}.*"

Domain Generation Algorithms (DGA): To detect attempts to use domain generation algorithms for command and control, you can use the following RegEx to search for network traffic to randomly generated domain names:
index=SecnNet sourcetype="stream:tcp" dest_port="80|443|8080"
| regex dest_ip="^[A-Za-z0-9]{32}\\.(com|net|org)$"

Suspicious User Activity: To detect suspicious user activity, you can use the following RegEx to search for events where a user has logged in from multiple locations in a short period of time:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Subject_User_Name, Logon_Type, src_ip
| where count > 10

PowerShell Scripting: To detect attempts to use PowerShell for malicious purposes, you can use the following RegEx to search for PowerShell commands containing suspicious keywords:
index=SecnNet sourcetype="WinEventLog:Windows PowerShell" SourceName="PowerShell"
| regex Message=".*(Invoke-Expression|DownloadString|IEX|Invoke-WebRequest|DownloadFile|Out-File|Set-Content|Invoke-Shellcode|Add-Type|New-Object|Net.WebClient|Get-Content|Get-ChildItem|Get-Process|Get-Item|Remove-Item|Copy-Item|Move-Item|Start-Process|Stop-Process).*"

Malware Persistence: To detect attempts to establish persistence on a compromised system, you can use the following RegEx to search for events where a process has created a scheduled task:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" TaskCategory="Task Creation"
| regex Message=".*Task Scheduler successfully registered task.*"

Spear Phishing: To detect attempts to conduct spear phishing attacks, you can use the following RegEx to search for emails containing suspicious subject lines and targeted recipients:
index=SecnNet sourcetype="mail" Subject=".*invoic.*|.*payment.*|.*resume.*|.*salary.*|.*W-2.*" To="user1@domain.com|user2@domain.com|user3@domain.com"

SQL Injection: To detect attempts to perform SQL injection attacks, you can use the following RegEx to search for web server logs containing suspicious SQL statements:
index=SecnNet sourcetype="access_combined_wcookie" uri=".*\\.(php|jsp|aspx)\\?.*SELECT.*FROM.*"

System Information Discovery: To detect attempts to gather system information for reconnaissance purposes, you can use the following RegEx to search for events where a process has executed systeminfo.exe:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| regex Image=".*\\\\system32\\\\systeminfo.exe.*"

Brute Force: To detect attempts to perform brute force attacks, you can use the following RegEx to search for events where a user has failed to log in multiple times:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Subject_User_Name, src_ip
| where count > 10

DNS Tunneling: To detect attempts to use DNS tunneling for data exfiltration, you can use the following RegEx to search for network traffic to known DNS tunneling destinations:
index=SecnNet sourcetype="stream:tcp" dest_port="53"
| regex dest_ip="10.0.0.1|11.0.0.1|12.0.0.1"

DLL Search Order Hijacking: To detect attempts to perform DLL search order hijacking, you can use the following RegEx to search for events where a process has loaded a DLL from a non-standard directory:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" ImageLoaded="*\\*\\*.dll"
| regex TargetFilename=".*\\\\(temp|downloads)\\\\.*"

Exploitation of Remote Services: To detect attempts to exploit remote services, you can use the following RegEx to search for network traffic to known vulnerable ports:
index=SecnNet sourcetype="stream:tcp" dest_port="21|22|23|25|53|80|110|135|137|139|143|445|3306|3389|5900|8080|8443"

User Execution: To detect attempts to execute malicious code through user interaction, you can use the following RegEx to search for events where a user has opened a file containing a known exploit:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11
| regex TargetFilename=".*\\\\(doc|xls|ppt|pdf|jar)\\b" CommandLine=".*-noLogo.*"

Process Injection: To detect attempts to inject code into a legitimate process, you can use the following RegEx to search for events where a process has created a new thread within another process:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=8
| regex Image=".*\\\\.*" TargetImage=".*\\\\.*"

Exfiltration Over Command and Control Channel: To detect attempts to exfiltrate data over a command and control channel, you can use the following RegEx to search for network traffic containing base64-encoded data:
index=SecnNet sourcetype="stream:tcp" dest_port="80|443|8080"
| regex dest_ip="^[A-Za-z0-9]{32}\\.(com|net|org)$"
| regex payload=".*[A-Za-z0-9+/]{100,}.*"

PowerShell Empire: To detect attempts to use the PowerShell Empire framework for post-exploitation activities, you can use the following RegEx to search for PowerShell commands containing Empire-specific keywords:
index=SecnNet sourcetype="WinEventLog:Windows PowerShell" SourceName="PowerShell"
| regex Message=".*(Invoke-Empire|Get-Empire|Import-Empire|Start-Empire).*"

Remote File Copy: To detect attempts to copy files remotely, you can use the following RegEx to search for events where a process has created a remote file share:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=5145
| regex Message=".*Object Type:\s+File\s+New Handle ID:.*\s+Accesses:\s+0x100000.*Share Name:.*"

Ransomware: To detect attempts to install or execute ransomware, you can use the following RegEx to search for events where a process has created and encrypted files with a specific extension:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11
| regex TargetFilename=".*\\\\(doc|xls|ppt|pdf|txt)\\b" CommandLine=".*-noLogo.*"
| regex TargetFilename=".*\\\\(docx|xlsx|pptx|pdf|txt)\\b" CommandLine=".*-Encrypt.*"

Kerberoasting: To detect attempts to perform Kerberoasting attacks, you can use the following RegEx to search for events where a user has requested a service ticket for a service that does not require delegation:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4769
| regex TargetUserName=".*" ServiceName="(?!HOST|.*\/).*"
| stats count by TargetUserName, ServiceName

Command-Line Interface: To detect attempts to use the command-line interface for malicious purposes, you can use the following RegEx to search for command-line arguments containing suspicious keywords:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\(cmd|powershell)\\.exe" CommandLine=".*-EncodedCommand|.*DownloadString|.*Invoke-Expression|.*iex|.*-Command.*"

Steganography: To detect attempts to use steganography for data exfiltration, you can use the following RegEx to search for network traffic containing base64-encoded data:
index=SecnNet sourcetype="stream:tcp" dest_port="80|443"
| regex payload=".*[A-Za-z0-9+/]{100,}.*"

Network Sniffing: To detect attempts to perform network sniffing for reconnaissance purposes, you can use the following RegEx to search for events where a network adapter has been set to promiscuous mode:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=22
| regex Image=".*\\\\system32\\\\netsh.exe" CommandLine=".*interface.*promiscuous.*"

Pass-The-Hash: To detect attempts to perform Pass-The-Hash attacks, you can use the following RegEx to search for events where a user has logged in using a hashed password:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| regex Logon_Process=".*Advapi.*" Logon_Type=".*2.*" Authentication_Package=".*NTLM.*"
| stats count by Logon_Account, Source_Network_Address

Web Shell: To detect attempts to use web shells for post-exploitation activities, you can use the following RegEx to search for web server logs containing suspicious HTTP requests:
index=SecnNet sourcetype="access_combined_wcookie" uri=".*\\.(php|jsp|aspx)\\?.*cmd=.*"

Remote Access Tools: To detect attempts to use remote access tools for post-exploitation activities, you can use the following RegEx to search for network traffic to known RAT command and control servers:
index=SecnNet sourcetype="stream:tcp" dest_port="443"
| regex dest_ip="^([A-Za-z0-9]{8}\\-){4}[A-Za-z0-9]{12}\\.(com|net|org)$"

DNS Spoofing: To detect attempts to perform DNS spoofing attacks, you can use the following RegEx to search for DNS traffic containing suspicious domain names:
index=SecnNet sourcetype="stream:dns"
| regex qname=".*bankofamerica|.*paypal|.*wellsfargo|.*google|.*facebook|.*apple"

Lateral Movement: To detect attempts to perform lateral movement, you can use the following RegEx to search for events where a user has logged in from multiple machines in a short period of time:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Logon_Account, Source_Network_Address
| where count > 1

Exploitation for Defense Evasion: To detect attempts to use exploits for defense evasion, you can use the following RegEx to search for events where a process has modified system security settings:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
| regex Image=".*\\\\.*" CommandLine=".*SeSecurityPrivilege.*"

File Deletion: To detect attempts to delete files, you can use the following RegEx to search for events where a process has deleted a file with a specific extension:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| regex Object_Name=".*\\\\(doc|xls|ppt|pdf|txt)\\b" Access_Mask=".*DELETE.*"

Memory Scraping: To detect attempts to steal data from memory, you can use the following RegEx to search for events where a process has accessed a memory location outside of its own virtual address space:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=10
| regex Image=".*\\\\.*" SourceImage=".*\\\\.*"
| stats count by Image, SourceImage

PowerShell-based Malware: To detect attempts to use PowerShell-based malware, you can use the following RegEx to search for events where a process has executed a PowerShell command with an encoded command-line argument:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\powershell.exe" CommandLine=".*-EncodedCommand.*"

DNS Tunneling: To detect attempts to use DNS tunneling for data exfiltration, you can use the following RegEx to search for DNS traffic containing suspicious domain names and base64-encoded data:
index=SecnNet sourcetype="stream:dns"
| regex qname=".*[A-Za-z0-9+/]{50,}.*"
| regex qname=".*\\.dns\\.tunneling\\..*"
| regex qname=".*\\.dns\\.data\\.exfiltration\\..*"

Network Reconnaissance: To detect attempts to perform network reconnaissance for post-exploitation activities, you can use the following RegEx to search for network traffic to known command and control servers:
index=SecnNet sourcetype="stream:tcp" dest_port="80|443"
| regex dest_ip="^([A-Za-z0-9]{8}\\-){4}[A-Za-z0-9]{12}\\.(com|net|org)$"

Data Obfuscation: To detect attempts to obfuscate data for defense evasion, you can use the following RegEx to search for events where a process has used an obfuscation technique to hide command-line arguments:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\.*" CommandLine=".*-noP.*|.*-w.*"

Domain Fronting: To detect attempts to use domain fronting for network communications, you can use the following RegEx to search for network traffic containing two different domain names:
index=SecnNet sourcetype="stream:http"
| regex host!="^.*\\.(google\\.com|appspot\\.com)$"
| stats count by clientip, host

Windows Registry: To detect attempts to modify the Windows Registry for persistence, you can use the following RegEx to search for events where a process has modified the Registry with a specific key name:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
| regex Image=".*\\\\.*" TargetObject=".*\\\\.*\\b"
| where TargetObject like "*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*"

Remote File Copy: To detect attempts to copy files remotely for data exfiltration, you can use the following RegEx to search for network traffic containing file paths:
index=SecnNet sourcetype="stream:tcp" dest_port="445"
| regex payload=".*[A-Za-z]:\\\\.*"

Pass-The-Ticket: To detect attempts to perform Pass-The-Ticket attacks, you can use the following RegEx to search for events where a user has logged in using a ticket that was not obtained from the Kerberos ticket-granting service:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| regex Logon_Process=".*Advapi.*" Logon_Type=".*10.*"
| stats count by Logon_Account, Source_Network_Address

DLL Search Order Hijacking: To detect attempts to use DLL search order hijacking for privilege escalation, you can use the following RegEx to search for events where a process has loaded a DLL from a non-standard location:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=7
| regex Image=".*\\\\.*" TargetFilename!=".*\\\\System32\\\\.*|.*\\\\Windows\\\\.*"

Obfuscated Files or Information: To detect attempts to use obfuscated files or information for defense evasion, you can use the following RegEx to search for events where a process has used an obfuscation technique to hide file contents:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\.*" CommandLine=".*-e.*"

Data Destruction: To detect attempts to destroy data for sabotage, you can use the following RegEx to search for events where a process has deleted files with specific extensions:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| regex Object_Name=".*\\\\(doc|xls|ppt|pdf|txt)\\b" Access_Mask=".*DELETE.*"
| stats count by Object_Name

PowerShell Empire: To detect attempts to use the PowerShell Empire framework for post-exploitation activities, you can use the following RegEx to search for PowerShell commands containing Empire-specific keywords:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\powershell.exe" CommandLine=".*empire.*"
| stats count by CommandLine

Ransomware: To detect attempts to install or execute ransomware, you can use the following RegEx to search for events where a process has created or modified files with specific extensions:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4656
| regex Object_Name=".*\\\\(doc|xls|ppt|pdf|txt)\\b" Access_Mask=".*WRITE_DAC.*|.*WRITE_OWNER.*"

Brute Force: To detect attempts to brute force user credentials, you can use the following RegEx to search for failed login attempts with multiple user accounts:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Logon_Account
| where count > 5

Remote Access: To detect attempts to establish remote access to a system, you can use the following RegEx to search for network traffic containing suspicious command-line arguments:
index=SecnNet sourcetype="stream:tcp" dest_port="3389"
| regex payload=".*\buser:.*"
| regex payload=".*\bpassword:.*"

Spear Phishing: To detect attempts to use spear phishing for social engineering attacks, you can use the following RegEx to search for suspicious email activity:
index=SecnNet sourcetype="mail" subject!=".*Re:.*"
| stats count by from, subject

Keylogging: To detect attempts to capture keystrokes for exfiltration, you can use the following RegEx to search for events where a process has created or modified files with specific names:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| regex Object_Name=".*\\\\(keylog|keystroke)\\b" Access_Mask=".*WRITE_DAC.*|.*WRITE_OWNER.*"

PowerShell Empire Stagers: To detect attempts to use PowerShell Empire stagers for post-exploitation activities, you can use the following RegEx to search for PowerShell commands containing Empire-specific stager names:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\powershell.exe" CommandLine=".*-ep.*"
| regex CommandLine=".*-enc.*"
| regex CommandLine=".*empire.*"
| stats count by CommandLine

DLL Side-Loading: To detect attempts to use DLL side-loading for privilege escalation, you can use the following RegEx to search for events where a process has loaded a DLL from a non-standard location:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=7
| regex Image=".*\\\\.*" TargetFilename!=".*\\\\System32\\\\.*|.*\\\\Windows\\\\.*"

SQL Injection: To detect attempts to exploit SQL injection vulnerabilities for data exfiltration, you can use the following RegEx to search for SQL statements containing suspicious keywords:
index=SecnNet sourcetype="stream:tcp" dest_port="1433"
| regex payload=".*\\bselect\\b.*\\bfrom\\b.*\\bwhere\\b.*\\b(union|or)\\b.*"

Lateral Movement: To detect attempts to move laterally within a network, you can use the following RegEx to search for network traffic containing specific protocols:
index=SecnNet sourcetype="stream:tcp" dest_port="135" OR dest_port="445" OR dest_port="3389"
| stats count by src_ip, dest_ip, dest_port

Exfiltration Over Web Service: To detect attempts to exfiltrate data over a web service, you can use the following RegEx to search for network traffic containing specific user agents:
index=SecnNet sourcetype="stream:http"
| regex user_agent=".*(curl|wget).*"
| stats count by clientip, uri

Windows Management Instrumentation (WMI): To detect attempts to use WMI for post-exploitation activities, you can use the following RegEx to search for events where a process has executed a WMI query:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\.*" CommandLine=".*-Namespace.*"
| stats count by Image, CommandLine

RDP Bruteforce: To detect attempts to bruteforce RDP credentials, you can use the following RegEx to search for multiple failed login attempts from a single IP address:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Logon_Account, Source_Network_Address
| where count > 10

Cross-Site Scripting (XSS): To detect attempts to exploit XSS vulnerabilities for web-based attacks, you can use the following RegEx to search for HTTP responses containing suspicious keywords:
index=SecnNet sourcetype="stream:http" status="200"
| regex payload=".*<script>.*"
| regex payload=".*<img.*onerror=.*"
| regex payload=".*<iframe>.*"

Persistence: To detect attempts to establish persistence on a system, you can use the following RegEx to search for events where a process has created a new service:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=10
| regex Image=".*\\\\.*" ServiceName!=".*\\\\system32\\\\.*|.*\\\\Windows\\\\.*"
| stats count by Image, ServiceName

Spear Phishing Attachment: To detect attempts to use spear phishing with a malicious attachment for social engineering attacks, you can use the following RegEx to search for email attachments with specific extensions:
index=SecnNet sourcetype="mail"
| regex attachment=".*\\\\.(doc|xls|ppt|pdf|txt)\\b"

System Information Discovery: To detect attempts to gather system information for reconnaissance purposes, you can use the following RegEx to search for events where a process has executed systeminfo.exe:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\systeminfo.exe"
| stats count by Image, CommandLine

Spear Phishing Link: To detect attempts to use spear phishing with a malicious link for social engineering attacks, you can use the following RegEx to search for email messages with links to suspicious domains:
index=SecnNet sourcetype="mail"
| regex payload=".*(http|https)://.*\\b(bank|paypal|ebay|amazon|office365|login|security|support|signin)\\b.*"
| stats count by from, subject

Command-Line Interface (CLI) Execution: To detect attempts to execute commands through the command-line interface for post-exploitation activities, you can use the following RegEx to search for events where a process has executed a command with specific keywords:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\cmd.exe" CommandLine=".*net user.*"
| regex CommandLine=".*wmic.*"
| stats count by Image, CommandLine

Distributed Denial of Service (DDoS): To detect attempts to launch a DDoS attack, you can use the following RegEx to search for network traffic containing specific patterns:
index=SecnNet sourcetype="stream:tcp" dest_port="80"
| regex payload=".*\\bX-Forwarded-For\\b.*"
| regex payload=".*\\bUser-Agent:.*"

Lateral Tool Transfer: To detect attempts to transfer tools or scripts laterally within a network, you can use the following RegEx to search for network traffic containing specific patterns:
index=SecnNet sourcetype="stream:tcp" dest_port="445" OR dest_port="139"
| regex payload=".*\b(PSExec|wmic|smb|net use|schtasks|bitsadmin)\b.*"

Password Spraying: To detect attempts to password spray against user accounts, you can use the following RegEx to search for multiple failed login attempts against different user accounts from a single IP address:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Logon_Account, Source_Network_Address
| where count > 10

Windows Management Instrumentation (WMI) Event Subscription: To detect attempts to establish persistence using WMI event subscriptions, you can use the following RegEx to search for events where a new WMI subscription has been created:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" EventCode=5858
| regex User=".*\\\\SYSTEM" TargetNamespace!=".*\\\\root\\\\cimv2\\\\.*"
| stats count by User, TargetNamespace

DNS Tunneling: To detect attempts to use DNS tunneling for data exfiltration, you can use the following RegEx to search for DNS queries with specific patterns:
index=SecnNet sourcetype="stream:dns"
| regex query=".*\\b(hacker|malware|botnet|backdoor|data|exfiltration|command|control)\\b.*"
| stats count by query, query_type

Windows Management Instrumentation (WMI) Remote Execution: To detect attempts to remotely execute commands using WMI, you can use the following RegEx to search for events where a WMI command has been executed against a remote system:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\wmic.exe" CommandLine=".*\\/node:.*"
| stats count by Image, CommandLine

Windows Management Instrumentation (WMI) Persistence: To detect attempts to establish persistence using WMI, you can use the following RegEx to search for events where a new WMI filter or consumer has been created:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" (EventCode=5860 OR EventCode=5861)
| regex User=".*\\\\SYSTEM" TargetNamespace!=".*\\\\root\\\\cimv2\\\\.*"
| stats count by User, TargetNamespace, EventCode

Domain Generation Algorithms (DGA): To detect attempts to use DGA for command and control, you can use the following RegEx to search for DNS queries with randomly generated subdomains:
index=SecnNet sourcetype="stream:dns"
| regex query=".*\\b[a-z0-9]{32}\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\..*\\b.*"
| stats count by query

Data Obfuscation: To detect attempts to obfuscate data in transit, you can use the following RegEx to search for network traffic containing suspicious patterns:
index=SecnNet sourcetype="stream:tcp"
| regex payload=".*base64.*"
| regex payload=".*xor.*"

Remote Access Trojan (RAT): To detect attempts to use a RAT for post-exploitation activities, you can use the following RegEx to search for events where a process has established a connection to a known RAT command and control server:
index=SecnNet sourcetype="stream:tcp" dest_port="443"
| regex dest_ip=".*\\b([a-f0-9]{32}|[a-f0-9]{64})\\b.*"
| stats count by dest_ip, dest_port

DNS Cache Poisoning: To detect attempts to poison DNS caches for command and control, you can use the following RegEx to search for DNS queries with suspicious patterns:
index=SecnNet sourcetype="stream:dns"
| regex query=".*\\b(command|control|exfiltration|malware|botnet|hacker|backdoor)\\b.*"
| stats count by query

Credential Dumping: To detect attempts to dump credentials from memory, you can use the following RegEx to search for events where a process has read or accessed LSASS.exe:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=10
| regex Image=".*\\\\lsass.exe"
| stats count by Image, User

Windows Management Instrumentation (WMI) Persistence: To detect attempts to establish persistence using WMI, you can use the following RegEx to search for events where a new WMI filter or consumer has been created:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" (EventCode=5860 OR EventCode=5861)
| regex User=".*\\\\SYSTEM" TargetNamespace!=".*\\\\root\\\\cimv2\\\\.*"
| stats count by User, TargetNamespace, EventCode

Exfiltration Over Command and Control Channel: To detect attempts to exfiltrate data over a command and control channel, you can use the following RegEx to search for DNS queries with specific patterns:
index=SecnNet sourcetype="stream:dns"
| regex query=".*\\b(base64|encryption|file|data|transfer|exfiltration|malware|botnet|hacker)\\b.*"
| stats count by query

Ransomware: To detect ransomware activity, you can use the following RegEx to search for events where a process has encrypted files:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11
| regex Image=".*\\\\(taskdl.exe|taskse.exe|dfsvc.exe)" TargetFilename=".*\\.(doc|docx|xlsx|xls|ppt|pptx|pdf)"
| stats count by Image, User

Remote File Copy: To detect attempts to copy files remotely, you can use the following RegEx to search for events where a process has copied files over the network:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
| regex Image=".*\\\\(net.exe|smb.exe)" TargetFilename=".*"
| stats count by Image, User

Process Injection: To detect attempts to inject code into a running process, you can use the following RegEx to search for events where a process has injected code into another process:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=8
| regex Image=".*\\\\(explorer.exe|svchost.exe)" TargetImage=".*"
| stats count by Image, TargetImage

Command and Scripting Interpreter: To detect attempts to execute malicious scripts or commands, you can use the following RegEx to search for events where a command or script has been executed:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| regex Image=".*\\\\(powershell.exe|cmd.exe|cscript.exe|wscript.exe)"
| stats count by Image, User

