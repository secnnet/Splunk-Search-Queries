File Deletion: To detect file deletion, you can use the following RegEx to search for events where a file has been deleted:
index=main sourcetype="WinEventLog:Security" EventCode=4660 | regex Object_Name=".*\\.(doc|xls|pdf)$"

Remote Access: To detect remote access attempts, you can use the following RegEx to search for events where a user has logged in from a remote location:
index=main sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10 | regex Workstation_Name="^-\[0-9\]$"

Data Exfiltration: To detect data exfiltration attempts, you can use the following RegEx to search for events where a user has uploaded files to an external location:
index=main sourcetype="WinEventLog:Security" EventCode=5145 | regex Share_Name="^\\\\[A-Za-z0-9_-]+(\\\\[A-Za-z0-9_-]+)+$"

Command Execution: To detect command execution attempts, you can use the following RegEx to search for events where a command has been executed:
index=main sourcetype="WinEventLog:Security" EventCode=4688 | regex New_Process_Name="cmd.exe" CommandLine=".*"

Persistence: To detect persistence techniques used by adversaries, you can use the following RegEx to search for events where a new service has been created:
index=main sourcetype="WinEventLog:Security" EventCode=4697 | regex Service_Name=".*"

Lateral Movement: To detect lateral movement attempts, you can use the following RegEx to search for events where a user has connected to a remote system:
index=main sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3 | regex Logon_Process=".*\\sscm$"

Privilege Escalation: To detect privilege escalation attempts, you can use the following RegEx to search for events where a user has obtained admin privileges:
index=main sourcetype="WinEventLog:Security" EventCode=4672 | regex Privilege_List=".*SeDebugPrivilege.*"

Reconnaissance: To detect reconnaissance attempts, you can use the following RegEx to search for events where a user has queried for system information:
index=main sourcetype="WinEventLog:Security" EventCode=4688 CommandLine=".*systeminfo.*"

Credential Dumping: To detect credential dumping attempts, you can use the following RegEx to search for events where a process has accessed the LSASS process:
index=main sourcetype="WinEventLog:Security" EventCode=4663 Accesses=".*ReadData.*" Object_Name="*\\lsass.exe" | regex Process_Name=".*"

Defense Evasion: To detect attempts to evade security defenses, you can use the following RegEx to search for events where a process has spawned a new process using the CreateProcess API:
index=main sourcetype="WinEventLog:Security" EventCode=4688 Parent_Process_Name!="svchost.exe" | regex Process_Name=".*CreateProcess.*"

Execution through API: To detect attempts to execute malicious code through legitimate APIs, you can use the following RegEx to search for events where a process has called a Windows API:
index=main sourcetype="WinEventLog:Security" EventCode=4688 | regex Process_Command_Line=".*[A-Z]:\\\\(Windows|Program Files)\\\\.*"

Data Encrypted: To detect attempts to encrypt data, you can use the following RegEx to search for events where a process has accessed an encrypted file:
index=main sourcetype="WinEventLog:Security" EventCode=4656 Accesses=".*ReadData.*" Object_Name="*\\*.encrypted" | regex Process_Name=".*"

Network Sniffing: To detect attempts to perform network sniffing, you can use the following RegEx to search for events where a process has created a network socket:
index=main sourcetype="WinEventLog:Security" EventCode=4689 | regex Process_Name=".*socket.*"

Process Injection: To detect attempts to inject malicious code into a process, you can use the following RegEx to search for events where a process has opened a remote process:
index=main sourcetype="WinEventLog:Security" EventCode=4658 Access_Mask=".*0x100.*" Object_Type="Process" | regex Subject_Logon_Id=".*" Target_User_Name=".*"

DNS Tunneling: To detect attempts to use DNS tunneling to bypass security controls, you can use the following RegEx to search for DNS queries containing base64-encoded data:
index=main sourcetype="stream:DNS" | regex query=".*[a-zA-Z0-9+/]{4,}.*"

DLL Side-loading: To detect attempts to side-load a DLL file, you can use the following RegEx to search for events where a process has loaded a DLL from a non-standard location:
index=main sourcetype="WinEventLog:Security" EventCode=4688 | regex Image=".*\\\\(Windows|Program Files)\\\\.*" Target_Image=".*\\\\(Windows|Program Files)\\\\.*"

DNS Spoofing: To detect attempts to spoof DNS responses, you can use the following RegEx to search for events where a DNS query has been redirected to a different IP address:
index=main sourcetype="stream:DNS" | regex answer="^.*$|^(?:(?!<your_ip_address>).)*$"

Command and Control: To detect attempts to establish command and control channels, you can use the following RegEx to search for network traffic to known command and control servers:
index=main sourcetype="stream:tcp" | regex dest_ip="^((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}))$"

Malicious Email Attachments: To detect malicious email attachments, you can use the following RegEx to search for email attachments with known malicious file extensions:
index=main sourcetype="mail" Attachment_Name="*.zip|*.rar|*.7z|*.exe|*.bat|*.js|*.jar|*.docm|*.xlsm|*.pptm"

Credential Phishing: To detect attempts to steal credentials through phishing, you can use the following RegEx to search for email messages containing known phishing keywords:
index=main sourcetype="mail" Subject=".*password.*|.*account.*|.*verify.*|.*reset.*" Message=".*login.*|.*phishing.*|.*scam.*|.*fraud.*"




















