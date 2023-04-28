Search for all failed login attempts in the last 24 hours:
index=main sourcetype=access_* action=failure

Identify all privileged user actions taken during a specified timeframe:
index=main sourcetype=access_* user_type=privileged earliest=-7d

Search for all traffic to a specific IP address in the last 24 hours:
index=main sourcetype=network_traffic dest_ip=192.168.0.1 earliest=-24h

Identify all user authentication failures followed by successful authentication within a specified timeframe:
index=main sourcetype=access_* action=failure OR action=success earliest=-7d
| eval failure=if(action="failure",1,0)
| eval success=if(action="success",1,0)
| eventstats sum(failure) as failures sum(success) as successes by user
| where failures > 0 AND successes > 0

Search for any indications of command and control activity:
index=main sourcetype=network_traffic dest_port=443
| where dest_ip IN ("192.168.0.1","192.168.0.2","192.168.0.3")
| stats count by src_ip,dest_ip
| where count > 10

Identify all user activity from a specific department during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user_department=HR OR user_department=IT
Search for any indications of malware infections on a specific endpoint:

index=main sourcetype=endpoint_logs host="endpoint-01"
| where EventID=4678 AND ImagePath="C:\Windows\System32\svchost.exe"

Identify all user activity from a specific IP address during a specified timeframe:
index=main sourcetype=access_* src_ip="192.168.0.1" earliest=-7d

Search for all activity related to a specific file or process during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h FileName="malware.exe" OR ImagePath="C:\Windows\System32\svchost.exe"

Identify all activity related to a specific user during a specified timeframe:
index=main sourcetype=access_* earliest=-7d user="SecnNet"

Search for all DNS queries made by a specific endpoint during a specified timeframe:
index=main sourcetype=dns_logs dest_host="malicious.com" earliest=-24h

Identify all login activity outside of normal business hours:
index=main sourcetype=access_* earliest=-7d
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Search for all traffic to a specific domain in the last 24 hours:
index=main sourcetype=network_traffic dest_domain="malicious.com" earliest=-24h

Identify all attempts to escalate privileges during a specified timeframe:
index=main sourcetype=access_* earliest=-7d
| search "Privilege escalation" OR "User added to administrator group"

Search for all failed login attempts from a specific IP address in the last 24 hours:
index=main sourcetype=access_* action=failure src_ip="192.168.0.1" earliest=-24h

Identify all user activity that occurred during a specified timeframe, sorted by the number of events generated by each user:
index=main sourcetype=access_* earliest=-24h
| stats count by user
| sort -count

Search for all network traffic to a specific port in the last 24 hours:
index=main sourcetype=network_traffic dest_port=443 earliest=-24h

Identify all activity related to a specific process or service during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\services.exe" OR ImagePath="C:\Windows\System32\svchost.exe"

Search for all failed login attempts from a specific user in the last 24 hours:
index=main sourcetype=access_* action=failure user="SecnNet" earliest=-24h

Identify all changes to critical system files or registry keys during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h EventID=4656
| where Object_Name LIKE "%System32%" OR Object_Name LIKE "%registry%"
These queries can help security teams quickly identify and investigate

Identify all login activity from a specific geographic location during a specified timeframe:
index=main sourcetype=access_* earliest=-24h City="New York" OR City="Los Angeles"

Search for all traffic to a specific URL in the last 24 hours:
index=main sourcetype=network_traffic dest_url="http://malicious.com" earliest=-24h

Identify all activity related to a specific process that spawned child processes during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ParentImage="C:\Windows\System32\svchost.exe"

Search for all traffic to a specific IP address and port in the last 24 hours:
index=main sourcetype=network_traffic dest_ip="192.168.0.1" dest_port=80 earliest=-24h

Identify all activity related to a specific domain during a specified timeframe:
index=main sourcetype=access_* earliest=-24h dest_domain="malicious.com"

Search for all network traffic to a specific subnet in the last 24 hours:
index=main sourcetype=network_traffic dest_ip="192.168.0.*" earliest=-24h

Identify all activity related to a specific process that made network connections during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=3 OR EventCode=10

Search for all traffic to a specific hostname in the last 24 hours:
index=main sourcetype=network_traffic dest_hostname="malicious.com" earliest=-24h

Identify all changes to critical system files during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h EventID=4656
| where Object_Name LIKE "%System32%"

Search for all activity related to a specific user and process during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" ImagePath="C:\Windows\System32\svchost.exe"

Identify all activity related to a specific service during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\services.exe"

Search for all traffic to a specific protocol in the last 24 hours:
index=main sourcetype=network_traffic protocol=TCP earliest=-24h

Identify all activity related to a specific process that modified system files during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4657

Search for all activity related to a specific user and IP address during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific user and process that accessed sensitive data during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" ImagePath="C:\Windows\System32\svchost.exe"
| search Object_Name="C:\Windows\System32\config"

Search for all traffic to a specific IP address that occurred during non-business hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1"
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Identify all activity related to a specific process that accessed sensitive registry keys during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search Object_Name LIKE "%registry%"

Search for all activity related to a specific domain and user during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" dest_domain="malicious.com"

Identify all activity related to a specific process that modified critical system files during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4657 AND Object_Name LIKE "%System32%"

Search for all activity related to a specific process and port during a specified timeframe:
index=main sourcetype=network_traffic earliest=-24h ImagePath="C:\Windows\System32\svchost.exe" dest_port=80

Identify all activity related to a specific user and process that created or deleted files during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData%"

Search for all traffic to a specific protocol and port in the last 24 hours:
index=main sourcetype=network_traffic protocol=UDP dest_port=53 earliest=-24h

index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=10
Search for all activity related to a specific user and domain during a specified timeframe:


index=main sourcetype=access_* earliest=-24h user="SecnNet" dest_domain="example.com"
Identify all activity related to a specific process that created or deleted registry keys during a specified timeframe:


index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4657 AND Object_Name LIKE "%registry%"

index=main sourcetype=network_traffic earliest=-24h Country="China"
Identify all activity related to a specific process that accessed sensitive files during a specified timeframe:

index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search Object_Name LIKE "%\AppData%"

Search for all activity related to a specific user and IP address that occurred during non-business hours:
index=main sourcetype=access_* earliest=-24h user="SecnNet" src_ip="192.168.0.1"
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Identify all activity related to a specific process that created or deleted files in sensitive directories during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%System32%"

Search for all activity related to a specific user and URL during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" dest_url="http://malicious.com"

index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4657 AND Object_Name LIKE "%registry%"

Search for all traffic to a specific IP address that was denied by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1" action="deny"

Identify all activity related to a specific process that accessed sensitive directories during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search Object_Name LIKE "%System32%"

Search for all activity related to a specific user and keyword in access logs during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" | search "password" OR "login"

Identify all activity related to a specific process that created or deleted files on removable media during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%Removable%"

Search for all traffic to a specific port that was denied by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_port=22 action="deny"

Identify all activity related to a specific process that created or deleted registry keys in sensitive areas during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4657 AND Object_Name LIKE "%HKLM%"

Search for all activity related to a specific user and file hash during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" md5="d41d8cd98f00b204e9800998ecf8427e"

Identify all activity related to a specific process that accessed a specific DLL during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search Object_Name="C:\Windows\System32\ntdll.dll"

Search for all activity related to a specific user and IP address that occurred during business hours:
index=main sourcetype=access_* earliest=-24h user="SecnNet" src_ip="192.168.0.1"
| eval hour=strftime(_time, "%H")
| where hour >= "08" AND hour <= "18"

Search for all activity related to a specific user and file path during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" Object_Name="C:\Users\SecnNet\Desktop\test.exe"

Identify all activity related to a specific process that created or deleted files on network shares during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%"

Search for all activity related to a specific user and file type during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" Object_Name LIKE "%\.docx%"

Identify all activity related to a specific process that accessed sensitive folders on local disk during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%"

Search for all traffic to a specific domain that occurred during business hours:
index=main sourcetype=network_traffic earliest=-24h dest_domain="malicious.com"
| eval hour=strftime(_time, "%H")
| where hour >= "08" AND hour <= "18"

Identify all activity related to a specific process that created or deleted files in a specific folder during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\Downloads%"

Search for all activity related to a specific user and email address during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" dest_email="john@example.com"

Identify all activity related to a specific process that spawned child processes that created or deleted files during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=10 AND Object_Name LIKE "%\AppData%"

Search for all traffic to a specific IP address that occurred during non-business hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1"
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%"

Search for all activity related to a specific user and source IP address during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that created or deleted files in a specific folder during a specified timeframe and was signed by a trusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\Downloads%" AND Signature_Status="Signed Trusted"

Search for all traffic to a specific domain that was denied by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_domain="malicious.com" action="deny"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%"

Search for all activity related to a specific user and HTTP status code during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" status=404

Identify all activity related to a specific process that created or deleted files with a specific file extension during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\.docx%"

Search for all activity related to a specific user and keyword in firewall logs during a specified timeframe:
index=main sourcetype=firewall_logs earliest=-24h user="SecnNet" | search "blocked" OR "denied"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and was signed by a trusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Signed Trusted"

Search for all traffic to a specific port that occurred during non-business hours:
index=main sourcetype=network_traffic earliest=-24h dest_port=22
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Identify all activity related to a specific process that created or deleted files with a specific file name during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%test.docx%"

Search for all activity related to a specific user and file creation during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" EventCode=4656 Action=CREATE

Identify all activity related to a specific process that accessed sensitive folders on network shares during a specified timeframe and was signed by a trusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Signed Trusted"

Search for all activity related to a specific user and HTTP method during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" method=POST

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and was signed by a trusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Signature_Status="Signed Trusted"

Search for all traffic to a specific IP address that was denied by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1" action="deny"

Identify all activity related to a specific process that accessed sensitive folders on local disk during a specified timeframe and created or deleted files:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND (Action=CREATE OR Action=DELETE)

Search for all activity related to a specific user and IP address during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that created or deleted files in sensitive folders on local disk during a specified timeframe and was signed by a trusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND (Action=CREATE OR Action=DELETE) AND Signature_Status="Signed Trusted"

Search for all traffic to a specific port that was allowed by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_port=80 action="allow"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and created or deleted files:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND (Action=CREATE OR Action=DELETE)

Search for all activity related to a specific user and command line during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h user="SecnNet" CommandLine="*powershell*"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and was signed by an untrusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Signed Untrusted"

Search for all traffic to a specific domain that was allowed by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_domain="example.com" action="allow"

Identify all activity related to a specific process that created or deleted files with a specific extension in a specific folder on local disk during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local\Downloads%" AND Object_Name LIKE "%.exe%"

Search for all activity related to a specific user and IP address during a specified timeframe in IIS logs:
index=main sourcetype=iis earliest=-24h cs_username="SecnNet" c_ip="192.168.0.1"

Identify all activity related to a specific process that created or deleted files with a specific file name in a specific folder on local disk during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local\Downloads\test.exe%"

Search for all activity related to a specific user and HTTP response code during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" status=401

Identify all activity related to a specific process that accessed sensitive folders on local disk during a specified timeframe and created or deleted files with a specific file name:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND (Action=CREATE OR Action=DELETE) AND Object_Name LIKE "%.docx%"

Search for all traffic to a specific IP address that occurred during non-business hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1"
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and was not signed by any publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Unsigned"

Search for all activity related to a specific user and HTTP URI during a specified timeframe:
index=main sourcetype=access_* earliest=-24h user="SecnNet" uri="/login"

Identify all activity related to a specific process that accessed sensitive folders on network shares during a specified timeframe and was not signed by any publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Unsigned"

Search for all traffic to a specific domain that occurred during non-business hours:
index=main sourcetype=network_traffic earliest=-24h dest_domain="example.com"
| eval hour=strftime(_time, "%H")
| where hour < "08" OR hour > "18"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and was not signed by any publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Signature_Status="Unsigned"

Search for all activity related to a specific user and HTTP response code during a specified timeframe in IIS logs:
index=main sourcetype=iis earliest=-24h cs_username="SecnNet" sc_status=500

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and was signed by an untrusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Signed Untrusted"

Search for all traffic to a specific IP address that was blocked by a firewall in the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1" action="block"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and was signed by an untrusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Signature_Status="Signed Untrusted"

Search for all activity related to a specific user and HTTP response code during a specified timeframe in Apache logs:
index=main sourcetype=apache earliest=-24h username="SecnNet" status=404

Identify all activity related to a specific process that accessed sensitive folders on network shares during a specified timeframe and created or deleted files with a specific file name:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND (Action=CREATE OR Action=DELETE) AND Object_Name LIKE "%.txt%"

Search for all activity related to a specific user and port during a specified timeframe in firewall logs:
index=main sourcetype=firewall earliest=-24h user="SecnNet" dst_port=3389

Identify all activity related to a specific process that accessed sensitive folders on local disk during a specified timeframe and created or deleted files with a specific extension:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND (Action=CREATE OR Action=DELETE) AND Object_Name LIKE "%.xls%"

Search for all activity related to a specific user and IP address during a specified timeframe in firewall logs:
index=main sourcetype=firewall earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that created or deleted files in a specific folder on local disk during a specified timeframe:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local\Temp%" AND (Action=CREATE OR Action=DELETE)

Search for all activity related to a specific user and HTTP method during a specified timeframe in Apache logs:
index=main sourcetype=apache earliest=-24h username="SecnNet" method=GET

Identify all activity related to a specific process that accessed sensitive folders on network shares during a specified timeframe and was signed by a revoked publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Signed Revoked"

Search for all activity related to a specific user and IP address during a specified timeframe in VPN logs:
index=main sourcetype=vpn earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and was signed by a revoked publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Signature_Status="Signed Revoked"

Search for all activity related to a specific user and HTTP response code during a specified timeframe in NGINX logs:
index=main sourcetype=nginx earliest=-24h user="SecnNet" status=500

Identify all activity related to a specific process that accessed sensitive folders on network shares during a specified timeframe and was signed by a trusted publisher:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Signature_Status="Signed Trusted"

Search for all traffic to a specific IP address that exceeded a specified threshold during the last 24 hours:
index=main sourcetype=network_traffic earliest=-24h dest_ip="192.168.0.1"
| stats count by src_ip
| where count > 1000

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and triggered a specific event:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND EventID=12345

Search for all activity related to a specific user and HTTP method during a specified timeframe in IIS logs:
index=main sourcetype=iis earliest=-24h cs_username="SecnNet" cs_method=POST

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific event:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND EventID=12345

Search for all activity related to a specific user and IP address during a specified timeframe in web server logs:
index=main sourcetype=web_server earliest=-24h username="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and triggered a specific alert:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Alert_Name="Suspicious Activity Detected"

Search for all activity related to a specific user and HTTP response code during a specified timeframe in Tomcat logs:
index=main sourcetype=tomcat earliest=-24h user="SecnNet" status=403

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific alert:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Alert_Name="Suspicious Activity Detected"

Search for all activity related to a specific user and IP address during a specified timeframe in SSH logs:
index=main sourcetype=ssh earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and triggered a specific event type:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND EventType="Access Denied"

index=main sourcetype=tomcat earliest=-24h user="SecnNet" status=500
Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific alert type:

index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Alert_Type="Malware Detected"

Search for all activity related to a specific user and HTTP method during a specified timeframe in NGINX access logs:
index=main sourcetype=nginx earliest=-24h username="SecnNet" method=GET

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and triggered a specific alert category:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Alert_Category="Unauthorized Access"

Search for all activity related to a specific user and IP address during a specified timeframe in RDP logs:
index=main sourcetype=rdp earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific event category:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Event_Category="File Access"

Search for all activity related to a specific user and HTTP response code during a specified timeframe in Apache access logs:
index=main sourcetype=apache earliest=-24h user="SecnNet" status=404

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and triggered a specific alert severity:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Alert_Severity="High"

Search for all activity related to a specific user and IP address during a specified timeframe in FTP logs:
index=main sourcetype=ftp earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific alert name:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Alert_Name="Malware Detected"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific event severity:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Event_Severity="High"

Search for all activity related to a specific user and HTTP status code during a specified timeframe in IIS logs:
index=main sourcetype=iis earliest=-24h cs_username="SecnNet" sc_status=200

Identify all activity related to a specific process that accessed sensitive files on network shares during a specified timeframe and triggered a specific alert description:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\\server\share%" AND Alert_Description="Unauthorized Access Detected"

Search for all activity related to a specific user and IP address during a specified timeframe in DNS logs:
index=main sourcetype=dns earliest=-24h user="SecnNet" src_ip="192.168.0.1"

Identify all activity related to a specific process that accessed sensitive files on local disk during a specified timeframe and triggered a specific event description:
index=main sourcetype=endpoint_logs earliest=-24h ImagePath="C:\Windows\System32\svchost.exe"
| search EventCode=4663 AND Object_Name LIKE "%\AppData\Local%" AND Event_Description="File Access Attempt Detected"

