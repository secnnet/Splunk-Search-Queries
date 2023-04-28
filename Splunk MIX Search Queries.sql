Search for failed login attempts:
index=security sourcetype=WinEventLog:Security EventCode=4625
| stats count by host

Search for suspicious network activity:
index=network src_port=80 OR src_port=443
| stats count by src_ip, dest_ip

Search for malware activity:
index=security sourcetype="wineventlog:security" EventCode=4688 Image_Path=\AppData\Roaming\.exe
| stats count by host

Search for failed VPN logins:
index=vpn_log VPN_Status=failure
| stats count by VPN_Username

Search for suspicious DNS activity:
index=dns query_type=A NOT query_name=*.local
| stats count by query

Detecting Brute Force Attacks:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by src_user
| where count>5

Detecting Malicious File Uploads:
index=web sourcetype="access_combined" cs_method=POST
| rex "(?i)/([^/\s]+.((jpe?g)|(png)|(gif)|(bmp)))$"
| stats count by src
| where count > 50

Detecting Data Exfiltration:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| rex field=object_path "\\([^\\]+)\[^\\]+$"
| stats count by dest_user, extracted_field
| where count > 100

Detecting Suspicious Network Traffic:
index=SecnNet sourcetype="netflow"
| eval bytes_sent=bytes/1024/1024
| stats sum(bytes_sent) as total_sent by src_ip, dest_ip
| where total_sent > 100

Detecting Suspicious Login Activity:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4672)
| stats count by src_user, dest
| where count>100

Detecting DDoS Attacks:
index=web sourcetype="access_combined"
| stats count by clientip, useragent
| where count > 10000
| eval count=count/3600
| where count > 100

Detecting Malware Infections:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| search Image_Path IN (".exe",".dll","*.ocx")
| stats count by Account_Name, Image_Path
| where count > 100

Detecting Suspicious DNS Activity:
index=dns sourcetype="stream:dns"
| stats count by query, qclass, qtype, src_ip
| where count > 100
| eval ratio=count/reply_count
| where ratio>100

Detecting Malicious PowerShell Activity:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| search "ScriptBlockText="
| rex "ScriptBlockText=\s*(?<script_block>.*)"
| eval script_block_length=length(script_block)
| stats count by User, script_block_length
| where script_block_length > 200

Detecting Phishing Attempts:
index=SecnNet sourcetype="mail" (subject="password" OR subject="account")
| stats count by src_user, subject
| where count > 50

Detecting Web Application Attacks:
index=SecnNet sourcetype="apache_access"
| rex "(?i)"(?<request>([^"]|\")*)""
| eval request=replace(request, "\"", """)
| eval request_length=length(request)
| stats count by clientip, method, uri, status, request_length
| where count > 100

Detecting Network Scans:
index=SecnNet sourcetype="bro_conn"
| stats count by id.orig_h
| where count > 1000

Detecting Ransomware Attacks:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| search object_path=":\Users*\Documents*" OR object_path=":\Users*\Desktop*"
| stats count by object_path, dest_user
| where count > 500

Detecting Unauthorized Access to Sensitive Data:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| search object_path=":\HR Data*" OR object_path=":\Financial Data*"
| stats count by object_path, dest_user
| where count > 50

Detecting Account Takeover:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| stats count by account_name, src_ip
| where count > 50

Detecting Insider Threats:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4663 OR EventCode=4656)
| stats count by object_path, dest_user
| where count > 1000

Detecting Advanced Persistent Threats:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| search (Image_Path="*powershell.exe" OR Image_Path="*rundll32.exe") AND (ParentImage_Path!="*powershell.exe" AND ParentImage_Path!="*rundll32.exe")
| stats count by Image_Path, ParentImage_Path
| where count > 50
This search query will detect if suspicious processes like PowerShell or Rundll32 are executed, but not by another process like another instance of PowerShell or Rundll32. This can indicate potential advanced persistent threats or malware.

Detecting Remote Access Trojans:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="\AppData\Roaming\.exe"
| stats count by Image, ParentImage
| where count > 50
This search query will detect if suspicious executables are executed from a user's AppData\Roaming directory, indicating potential remote access trojans (RATs) or malware.

Detecting Credential Dumping:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\lsass.exe"
| stats count by SourceImage, ProcessCommandLine
| where count > 10
This search query will detect if a process is dumping or extracting user credentials from the Local Security Authority Subsystem Service (LSASS) process, indicating potential credential dumping or harvesting.

Detecting Malicious PowerShell Scripts:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
| search "ScriptBlockText="
| regex "(?i)(Invoke-Expression)|((New-Object).(Net.WebClient).(DownloadFile))|((System.Net.WebClient).*(DownloadString))"
| stats count by User, ScriptBlockText
| where count > 10

Detecting File Deletion and Modification:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4663 OR EventCode=4656)
| search (Accesses="DELETE" OR Accesses="WRITE_OWNER") AND (object_path=":\Users*\Documents*" OR object_path=":\Users*\Desktop*")
| stats count by dest_user, object_path
| where count > 50

Detecting DNS Tunneling:
index=SecnNet sourcetype="stream:dns"
| stats count by query, qclass, qtype, src_ip
| where count > 100
| eval ratio=count/reply_count
| where ratio>100 AND (query="" OR query=".") AND (qclass="" OR qclass="IN") AND (qtype="" OR qtype="A")

Detecting Brute-Force Attacks:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Failure_Reason
| where count > 10 AND Failure_Reason="%%2313"

Detecting Suspicious Network Traffic:
index=SecnNet sourcetype="bro_conn"
| stats count by id.orig_h, id.resp_h, id.resp_p, service
| where count > 1000

Detecting Malicious Domain Names:
index=SecnNet sourcetype="stream:dns"
| search query="*"
| eval domain=mvindex(split(lower(query), "."), -2) + "." + mvindex(split(lower(query), "."), -1)
| stats count by domain
| where count > 1000

Detecting HTTP-Based C2 Traffic:
index=SecnNet sourcetype="bro_http"
| search (method="POST" OR method="GET") AND (user_agent="PowerShell" OR user_agent="Python")
| stats count by dest_ip, method, uri, user_agent
| where count > 50

Detecting Brute-Force SSH Attacks:
index=SecnNet sourcetype="linux_secure" (message="Failed password" OR message="Invalid user")
| stats count by src_ip, user
| where count > 100

Detecting Malicious JavaScript:
index=SecnNet sourcetype="bro_http" method="GET"
| rex field=uri "..js"
| search uri="http"
| stats count by dest_ip, uri
| where count > 50

Detecting Malware Persistence:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4688 OR EventCode=5140)
| search (Image_Path="*regsvr32.exe" OR Image_Path="*rundll32.exe") AND (ParentImage_Path!="*regsvr32.exe" AND ParentImage_Path!="*rundll32.exe")
| stats count by Image_Path, ParentImage_Path
| where count > 10

Detecting Web Application Attacks:
index=SecnNet sourcetype="access"
| search status="5??"
| stats count by clientip, uri
| where count > 1000

Detecting Data Exfiltration via Email:
index=SecnNet sourcetype="msx" OR sourcetype="maillog"
| search messageid=""
| rex field=messageid ".@(.*).com"
| stats count by domain, recipient_address
| where count > 50

Detecting SQL Injection Attacks:
index=SecnNet sourcetype="access"
| search method="GET" AND uri="select"
| stats count by clientip, uri
| where count > 1000

Detecting Credential Stuffing:
index=SecnNet sourcetype="access"
| rex field=request ".?(.)"
| rex field=_raw "username=(?<user>\w+)"
| stats count by user, clientip
| where count > 100
This search query will detect if a high number of failed login attempts are being made for a specific user account from a variety of IP addresses, indicating potential credential stuffing attacks.

Detecting Ransomware Activity:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4656 OR EventCode=4663)
| search Accesses="WRITE_DATA" AND (Object_Name=":\Users*\Documents*.exe" OR Object_Name=":\Users*\Desktop*.exe")
| stats count by dest_user, Object_Name
| where count > 50

Detecting Privilege Escalation:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| search Account_Name="*" AND Logon_Type=3
| stats count by Account_Name, Elevated_Token
| where count > 10 AND Elevated_Token="True"

Detecting Suspicious SMB Traffic:
index=SecnNet sourcetype="bro_conn" service=""
| search (id.orig_h="" AND id.resp_h="")
| stats count by id.orig_h, id.resp_h, service
| where count > 1000 AND service="" AND id.resp_p=445

Detecting Suspicious PowerShell Activity:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search "New-Item" OR "Set-ItemProperty" OR "Remove-Item"
| stats count by ComputerName, ScriptName
| where count > 50

Detecting Malware Persistence via Startup Items:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4688 OR EventCode=5140)
| search (Image_Path="ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" OR Image_Path="AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
| stats count by Image_Path, ParentImage_Path
| where count > 10

Detecting Malicious SSH Traffic:
index=SecnNet sourcetype="linux_secure" (message="Failed password" OR message="Accepted publickey")
| stats count by src_ip, user
| where count > 100 AND user!="root"

Detecting Malware Infection via Registry Changes:
index=SecnNet sourcetype="WinEventLog:Security" (EventCode=4657 OR EventCode=4663)
| search Accesses="WRITE_OWNER" AND Object_Name="*:\Windows\System32*"
| stats count by Object_Name, dest_user
| where count > 50

Detecting Credential Theft via Mimikatz:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4688
| search Image_Path="mimikatz"
| stats count by ComputerName, Account_Name
| where count > 5

Detecting Malware Infection via Scheduled Tasks:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=107
| search Task_Name="*"
| stats count by ComputerName, Task_Name
| where count > 10

Detecting Cryptocurrency Mining Malware:
index=SecnNet sourcetype="access"
| search method="GET" AND uri="cryptonight"
| stats count by clientip
| where count > 1000

Detecting Unauthorized Access Attempts:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| search Failure_Reason!="An Error occurred during Logon" AND Logon_Type!="3"
| stats count by src_ip, Account_Name
| where count > 10

Detecting Malware Infection via Network Connections:
index=SecnNet sourcetype="bro_conn" id.resp_p=443
| stats count by id.orig_h, id.resp_h
| where count > 1000 AND id.orig_h!="" AND id.resp_h!=""

Detecting Data Exfiltration via DNS:
index=SecnNet sourcetype="dns"
| search query="" AND (answer!="" OR rcode!="NOERROR")
| stats count by clientip, query
| where count > 1000

Detecting Malware Infection via PowerShell Script Block Logging:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search Script_Block_Text="IEXEncodedCommand*"
| stats count by ComputerName, Script_Name
| where count > 10

Detecting Phishing Attempts:
index=SecnNet sourcetype="mail" (subject="password" OR subject="login")
| stats count by sender, recipient
| where count > 50

Detecting Malware Infection via Process Hollowing:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="*explorer.exe" EventCode=1
| search Image="*cmd.exe" AND ParentImage="*explorer.exe"
| stats count by ComputerName, ParentImage, Image
| where count > 10

Detecting Brute Force Attacks:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| search Failure_Reason="%%2313"
| stats count by src_ip, Account_Name
| where count > 50

Detecting Malware Infection via Scheduled Tasks (Part 2):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=106
| search Task_Name="*"
| stats count by ComputerName, Task_Name
| where count > 10

Detecting DNS Tunneling:
index=SecnNet sourcetype="dns"
| search query="" AND answer=""
| stats count by clientip, query
| where count > 1000

Detecting Malware Infection via WMI:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational"
| search Operation="__InstanceCreationEvent" AND TargetInstance!="*"
| stats count by ComputerName, Operation
| where count > 10

Detecting Malware Infection via Lateral Movement:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| search Logon_Type="3"
| stats count by src_ip, Account_Name, dest_ip
| where count > 10

Detecting DDoS Attacks:
index=SecnNet sourcetype="bro_conn" id.resp_p=80 OR id.resp_p=443
| search method="POST" AND (uri="/xmlrpc.php" OR uri="/wp-login.php")
| stats count by id.orig_h
| where count > 1000

Detecting Malware Infection via Suspicious Registry Key Changes:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4657
| search Object_Name="\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" OR Object_Name="\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
| stats count by ComputerName, Object_Name
| where count > 10

Detecting Malware Infection via Scheduled Tasks (Part 3):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=140
| search Task_Name="*"
| stats count by ComputerName, Task_Name
| where count > 10

Detecting Malware Infection via PowerShell Script Block Logging (Part 2):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| search Script_Block_Text="(Get-WmiObject -Class win32_process -Filter)*"
| stats count by ComputerName, Script_Name
| where count > 10

Detecting Privilege Escalation Attempts:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4672
| search Privilege_List="SeDebugPrivilege"
| stats count by src_ip, Account_Name
| where count > 10

Detecting Malware Infection via Unusual Network Traffic:
index=SecnNet sourcetype="bro_conn"
| search service!="dns" AND service!="http" AND service!="ssl" AND service!="smtp"
| stats count by id.orig_h, id.resp_h, service
| where count > 100

Detecting Malware Infection via Use of WMI Persistence:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational"
| search Operation="__InstanceModificationEvent" AND TargetInstance!="*"
| stats count by ComputerName, Operation
| where count > 10

Detecting Suspicious User Account Activity:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4720 OR EventCode=4722 OR EventCode=4723 OR EventCode=4724 OR EventCode=4725 OR EventCode=4726 OR EventCode=4727 OR EventCode=4728 OR EventCode=4729 OR EventCode=4730 OR EventCode=4731 OR EventCode=4732 OR EventCode=4733 OR EventCode=4734 OR EventCode=4735 OR EventCode=4737 OR EventCode=4738 OR EventCode=4740 OR EventCode=4741 OR EventCode=4742 OR EventCode=4743 OR EventCode=4744 OR EventCode=4745 OR EventCode=4746 OR EventCode=4747 OR EventCode=4748 OR EventCode=4749 OR EventCode=4750 OR EventCode=4751 OR EventCode=4752 OR EventCode=4753 OR EventCode=4754 OR EventCode=4755 OR EventCode=4756 OR EventCode=4757 OR EventCode=4758 OR EventCode=4760 OR EventCode=4761 OR EventCode=4762 OR EventCode=4763 OR EventCode=4764 OR EventCode=4765 OR EventCode=4766 OR EventCode=4767 OR EventCode=4768 OR EventCode=4769 OR EventCode=4770 OR EventCode=4771 OR EventCode=4772 OR EventCode=4773 OR EventCode=4774 OR EventCode=4775 OR EventCode=4776 OR EventCode=4777 OR EventCode=4778 OR EventCode=4779 OR EventCode=4780 OR EventCode=4781 OR EventCode=4782 OR EventCode=4783 OR EventCode=4784 OR EventCode=4785 OR EventCode=4786 OR EventCode=4787 OR EventCode=4788 OR EventCode=4789 OR EventCode=4790 OR EventCode=4791 OR EventCode=4792 OR EventCode=4793 OR EventCode=4794 OR EventCode=4795 OR EventCode=4796 OR EventCode=4797 OR EventCode=4798 OR EventCode=4799 OR EventCode=4800 OR EventCode=4801 OR EventCode=4802 OR EventCode=4803 OR EventCode=5376 OR EventCode=5377 OR EventCode=5378 OR EventCode=5447 OR EventCode=5448
| stats count by src_ip, Account_Name, EventCode
| where count > 10

Detecting Malware Infection via Scheduled Tasks (Part 4):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=141
| search Task_Name="*"
| stats count by ComputerName, Task_Name

Detecting Malware Infection via DNS Tunneling:
index=SecnNet sourcetype="bro_dns" query=""
| rex field=q "\S+ (\S+)$"
| search qtype="" NOT qtype="PTR" NOT qtype="SOA" NOT qtype="NS" NOT qtype="MX" NOT qtype="A" NOT qtype="AAAA" NOT qtype="CNAME" NOT qtype="SRV" NOT qtype="HINFO"
| stats count by q, qtype
| where count > 1000

Detecting Brute Force Password Attacks:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| stats count by src_ip, Account_Name
| where count > 10

Detecting Malware Infection via Suspicious Email Activity:
index=SecnNet sourcetype="*ms:o365:management:activity" Operation="SendMail"
| rex field=To "\w+@(\w+.\w+)"
| search NOT recipient_domain="company.com"
| stats count by recipient_domain
| where count > 100

Detecting Malware Infection via Suspicious File Modifications:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4656
| search Object_Name="\AppData\Roaming\.exe" OR Object_Name="\AppData\Local\Temp\.exe"
| stats count by ComputerName, Object_Name
| where count > 10

Detecting Malware Infection via Use of Windows Management Instrumentation (WMI):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| search QueryLanguage="WQL" AND Query="SELECT * FROM Win32_Process"
| stats count by ComputerName, Query
| where count > 10

Detecting Suspicious Privileged Account Activity:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4672
| search Privilege_List="SeTcbPrivilege" OR Privilege_List="SeImpersonatePrivilege" OR Privilege_List="SeAssignPrimaryTokenPrivilege"
| stats count by src_ip, Account_Name, Privilege_List
| where count > 10

Detecting Malware Infection via Registry Modification:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4657
| search Object_Name="*\Software\Microsoft\Windows\CurrentVersion\Run"
| stats count by ComputerName, Object_Name
| where count > 10

Detecting Potential Insider Threat Activity:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4624
| eval Success_Logon_Type=if(Logon_Type="2" OR Logon_Type="7", "Interactive", if(Logon_Type="3", "Network", if(Logon_Type="8", "NetworkCleartext", if(Logon_Type="10", "RemoteInteractive", "Unknown"))))
| search NOT Account_Name="" NOT Account_Name="ANONYMOUS LOGON" NOT Account_Name="$" Success_Logon_Type="Network"
| stats count by Account_Name, src_ip
| where count > 10

Detecting Malware Infection via Use of PowerShell:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
| search ScriptBlockText!="Search-ADAccount"
| stats count by ComputerName, ScriptBlockText
| where count > 10

Detecting Malware Infection via Suspicious Network Traffic:
index=SecnNet sourcetype="bro_conn"
| search id.orig_h="" id.resp_h="" id.resp_p="*"
| stats count by id.orig_h, id.resp_h, id.resp_p
| where count > 1000

Detecting Suspicious Process Execution via Windows Event Logs:
index=SecnNet sourcetype="WinEventLog:System" EventCode=4688
| search Process_Command_Line!="\System32\svchost.exe" AND Process_Command_Line!="\System32\services.exe"
| stats count by src_ip, Account_Name, Process_Name, Process_Command_Line
| where count > 10

Detecting Suspicious DNS Query Activity:
index=SecnNet sourcetype="dns" query!=""
| eval domain=lower(split(query,"\.",-1))
| lookup blacklisted_domains domain OUTPUT domain as domain_blacklisted
| search NOT domain_blacklisted=""
| stats count by query, clientip
| where count > 1000

Detecting Suspicious User Account Modifications:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4728 OR EventCode=4729 OR EventCode=4730 OR EventCode=4731 OR EventCode=4732 OR EventCode=4733
| stats count by Account_Name, EventCode
| where count > 10

Detecting Malware Infection via Suspicious Network Behavior:
index=SecnNet sourcetype="bro_conn"
| search NOT service="*"
| stats count by service, id.orig_h, id.resp_h, id.resp_p
| where count > 1000

Detecting Suspicious SSH Login Attempts:
index=SecnNet sourcetype="secure" action=login
| search method="publickey" OR method="password"
| stats count by user, src_ip
| where count > 10

Detecting Malware Infection via Suspicious Host Behavior:
index=SecnNet sourcetype="bro_conn"
| search id.resp_h="*"
| stats count by id.resp_h
| where count > 10000

Detecting Suspicious LDAP Queries:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4662
| search Object_Type="groupPolicyContainer" AND Object_DN="*CN=Policies,CN=System"
| stats count by ComputerName, Account_Name, Object_DN
| where count > 10

Detecting Suspicious File Deletion:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4663
| search Access_Mask="0x2" AND FileAttributes="Directory"
| stats count by src_ip, Account_Name, Object_Name
| where count > 10

Detecting Malware Infection via Use of Scheduled Tasks:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" EventCode=106
| search Task_To_Run!="\system32\.*"
| stats count by ComputerName, Task_To_Run
| where count > 10

Detecting Suspicious User Account Authentication:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4625
| search NOT Account_Name="" NOT Account_Name="ANONYMOUS LOGON" NOT Account_Name="$" NOT src_ip="127.0.0.1" Logon_Type="3"
| stats count by Account_Name, src_ip
| where count > 10

Detecting Malware Infection via Use of Windows Scripting Host (WSH):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WinRM/Operational" EventCode=300
| search Message!="Created WSH shell object"
| stats count by ComputerName, Message
| where count > 10

Detecting Suspicious Network Traffic via SSL:
index=SecnNet sourcetype="bro_ssl"
| search NOT server_name="*"
| stats count by server_name, id.orig_h, id.resp_h, id.resp_p
| where count > 1000

Detecting Suspicious DNS Traffic via DNS Tunneling:
index=SecnNet sourcetype="dns"
| eval domain=lower(split(query,"\.",-1))
| lookup blacklisted_domains domain OUTPUT domain as domain_blacklisted
| search NOT domain_blacklisted="*"
| stats count by query, clientip
| where count > 100 AND count < 200

Detecting Malware Infection via Suspicious HTTP Traffic:
index=SecnNet sourcetype="access_combined"
| search method="POST" status=200
| stats count by clientip, uri, method
| where count > 10

Detecting Suspicious Login Behavior via Microsoft Exchange Server Logs:
index=SecnNet sourcetype="WinEventLog:MSExchange Management" EventCode=1
| search EventMessage="WarningLogon failure on database*"
| stats count by src_ip, Account_Name, Database, Client_Info
| where count > 10

Detecting Malware Infection via Suspicious Registry Modifications:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4657
| search Object_Name!="\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
| stats count by src_ip, Account_Name, Object_Name
| where count > 10

Detecting Suspicious Network Traffic via SMB:
index=SecnNet sourcetype="smb"
| search NOT service="*"
| stats count by service, id.orig_h, id.resp_h
| where count > 1000

Detecting Suspicious Network Traffic via SSH:
index=SecnNet sourcetype="ssh"
| search NOT command="*"
| stats count by command, src_ip
| where count > 10

Detecting Malware Infection via Suspicious PowerShell Activity:
index=SecnNet sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" TaskCategory="ScriptBlockInvocation"
| search NOT ScriptName="*"
| stats count by ComputerName, ScriptBlockText
| where count > 10

Detecting Suspicious DNS Traffic via DNS DGA:
index=SecnNet sourcetype="dns"
| eval domain=lower(split(query,"\.",-1))
| lookup blacklisted_domains domain OUTPUT domain as domain_blacklisted
| search NOT domain_blacklisted="*"
| stats count by query, clientip
| where count > 200

Detecting Malware Infection via Suspicious WMI Activity:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4656 OR EventCode=4658
| search Object_Name="root\cimv2"
| stats count by Account_Name, Object_Name
| where count > 10

Detecting Suspicious Network Traffic via ICMP:
index=SecnNet sourcetype="icmp"
| search NOT type="*"
| stats count by type, id.orig_h, id.resp_h
| where count > 1000

Detecting Suspicious Network Traffic via DNS:
index=SecnNet sourcetype="dns"
| search query_type!="*"
| stats count by query_type, query, clientip
| where count > 1000

Detecting Malware Infection via Use of Windows Management Instrumentation (WMI):
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" EventCode=5858
| search Query!="SELECT * FROM Win32_Processor"
| stats count by ComputerName, Query
| where count > 10

Detecting Suspicious Network Traffic via RDP:
index=SecnNet sourcetype="rdp"
| search NOT client_name="*"
| stats count by client_name, src_ip, dest_ip
| where count > 1000

Detecting Malware Infection via Suspicious HTTP User-Agent:
index=SecnNet sourcetype="access_combined"
| search User_Agent!="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299"
| stats count by clientip, User_Agent
| where count > 10

Detecting Suspicious Network Traffic via FTP:
index=SecnNet sourcetype="ftp"
| search NOT command="*"
| stats count by command, src_ip
| where count > 10

Detecting Suspicious Network Traffic via SSL/TLS:
index=SecnNet sourcetype="ssl"
| search NOT subject="*"
| stats count by subject, id.orig_h, id.resp_h
| where count > 1000

Detecting Malware Infection via Suspicious Office Documents:
index=SecnNet sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search Image="\winword.exe" OR Image="\excel.exe"
| rex field=TargetObject ".*\(?<filename>[^\]+)"
| stats count by Computer, filename
| where count > 10

Detecting Suspicious Network Traffic via NTP:
index=SecnNet sourcetype="ntp"
| search NOT leap_indicator="*"
| stats count by leap_indicator, id.orig_h, id.resp_h
| where count > 1000

Detecting Malware Infection via Suspicious DLL Loading:
index=SecnNet sourcetype="WinEventLog:Security" EventCode=4657
| search Object_Name="\Windows\System32\"
| stats count by Account_Name, Object_Name
| where count > 10

Detecting Suspicious Network Traffic via SNMP:
index=SecnNet sourcetype="snmp"
| search NOT sysDescr="*"
| stats count by sysDescr, src_ip
| where count > 1000

Detecting Suspicious Network Traffic via SMB:
index=SecnNet sourcetype="smb"
| search NOT command="*"
| stats count by command, src_ip
| where count > 10

Detecting Malware Infection via Suspicious Registry Changes:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search Image="\reg.exe"
| rex field=TargetObject ".\(?<key>[^\]+)"
| stats count by Computer, key
| where count > 10

Detecting Suspicious Network Traffic via IRC:
index=SecnNet sourcetype="irc"
| search NOT nick="*"
| stats count by nick, src_ip
| where count > 1000

Detecting Malware Infection via Suspicious JavaScript Activity:
index=SecnNet sourcetype="access_combined"
| search cs_User_Agent="Firefox" AND cs_method="GET" AND cs_uri_stem="/js/"
| stats count by clientip, cs_User_Agent, cs_uri_stem
| where count > 10

Detecting Suspicious Network Traffic via Telnet:
index=SecnNet sourcetype="telnet"
| search NOT command="*"
| stats count by command, src_ip
| where count > 10

Detecting Suspicious Network Traffic via SSH:
index=SecnNet sourcetype="ssh"
| search NOT command="*"
| stats count by command, src_ip
| where count > 10

Detecting Malware Infection via Suspicious PowerShell Activity:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="\powershell.exe" AND CommandLine!="Get-EventLog"
| rex field=CommandLine ".-EncodedCommand (?<encoded_cmd>[^ ]+).*"
| stats count by Computer, encoded_cmd
| where count > 10

Detecting Suspicious Network Traffic via ICMP:
index=SecnNet sourcetype="icmp"
| search NOT icmp_type="*"
| stats count by icmp_type, src_ip, dest_ip
| where count > 1000

Detecting Malware Infection via Suspicious Scheduled Tasks:
index=SecnNet sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="\schtasks.exe"
| rex field=CommandLine ". (?<task_name>[^\]+)$"
| stats count by Computer, task_name
| where count > 10

Detecting Suspicious Network Traffic via NetBIOS:
index=SecnNet sourcetype="netbios"
| search NOT name_service="*"
| stats count by name_service, src_ip, dest_ip
| where count > 1000



