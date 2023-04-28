List all high severity alerts in the last 24 hours.
index=SecnNet severity=high earliest=-24h
| table source, sourcetype, _time, severity, description

Identify potential account lockouts in the last hour.
index=SecnNet action=failure earliest=-1h
| stats count by user
| where count > 5

Get a list of new user accounts created in the last week.
index=SecnNet action=create earliest=-7d user!="*default"
| table user, source, sourcetype, _time

Detect any login attempts from blacklisted IP addresses.
index=SecnNet source="firewall" action=login earliest=-1d
| lookup blacklist.csv IP OUTPUT IP as blacklist_IP
| search NOT IP=blacklist_IP
| table user, IP, _time

Search for attempts to delete critical files.
index=SecnNet source="file" action=delete
| search file="*/important/*"
| table user, file, _time

Identify users who have accessed files they should not have in the last 24 hours.
index=SecnNet action=* earliest=-24h
| search file="/sensitive/*" user!="admin"
| table user, file, _time

Get a list of all failed SSH login attempts in the last hour.
index=SecnNet source="ssh" action=failure earliest=-1h
| table user, IP, _time

Detect attempts to execute commands with sudo.
index=SecnNet source="sudo" action=*
| search command!="su"
| table user, command, _time

Find users who have been added to the sudoers file in the last 24 hours.
index=SecnNet source="sudoers" action=* earliest=-24h
| table user, group, _time

Identify users who have been logging in from unusual locations.
index=SecnNet action=* earliest=-24h
| iplocation src_ip
| stats count by user, Country
| where Country!="United States" AND count > 5
| table user, Country, _time

Get a list of all processes with high CPU utilization.
index=performance earliest=-24h
| stats avg(percent_cpu) as CPU by process_name
| sort -CPU
| head 10

Identify machines with low disk space.
index=performance earliest=-24h
| stats avg(percent_disk_space) as disk_space by host
| where disk_space < 10
| table host, disk_space, _time

Find users who have been accessing sensitive files outside of normal business hours.
index=SecnNet action=*
| search file="/sensitive/*"
| where (strftime("%H", _time) < "07" OR strftime("%H", _time) > "18")
| table user, file, _time

Get a list of all web requests with status code 404.
index=web source="access.log" status=404 earliest=-24h
| table clientip, method, uri_path, _time

Identify machines with outdated antivirus signatures.
index=antivirus action=update earliest=-24h
| stats count by host
| where count < 5
| table host, _time

Detect attempts to exploit vulnerabilities in web applications.
index=web source="access.log" action=exploit earliest

Search for any attempts to elevate privileges through group membership changes.
index=SecnNet action=group earliest=-24h
| search member_type="user" AND member_type="group" AND action="add"
| table user, group, _time

Identify machines with failed login attempts from multiple users.
index=SecnNet action=failure earliest=-24h
| stats count by host, user
| where count > 5
| table host, user, count, _time

Find users who have been attempting to access web pages with sensitive information.
index=web source="access.log" earliest=-24h
| search uri_path="/sensitive/*"
| table clientip, uri_path, _time

Get a list of all DNS requests for known malicious domains.
index=dns source="dns.log" earliest=-24h
| lookup malicious_domains.csv domain OUTPUT domain as malicious_domain
| search domain=malicious_domain
| table clientip, domain, _time

Detect potential malware infections by looking for unusual command line arguments.
index=SecnNet action=* earliest=-24h
| search process="*malware*" AND command_line="*abnormal argument*"
| table user, process, command_line, _time

Identify machines with suspicious network traffic patterns.
index=network source="network.log" earliest=-24h
| stats count by host, dest_ip
| where count > 100
| table host, dest_ip, count, _time

Get a list of all failed login attempts for a specific user.
index=SecnNet action=failure user="specific_user" earliest=-24h
| table source, sourcetype, _time, description

Search for attempts to exfiltrate sensitive data through email.
index=SecnNet action=* earliest=-24h
| search email_to="*sensitive_email_address*" AND attachment="*sensitive_data*"
| table user, email_from, email_to, attachment, _time

Identify machines with unusually high network bandwidth usage.
index=network source="network.log" earliest=-24h
| stats avg(bytes) as avg_bytes by host
| where avg_bytes > 100000000
| table host, avg_bytes, _time

Get a list of all successful file transfers from a specific machine.
index=SecnNet action=transfer source="specific_machine" earliest=-24h
| table source, dest, _time

Detect attempts to exploit vulnerabilities in the OS.
index=SecnNet source="system" action=*
| search description="*vulnerability*"
| table user, description, _time

Identify machines with outdated software versions.
index=SecnNet source="system" action=update earliest=-24h
| stats count by host
| where count < 5
| table host, _time

Search for attempts to bypass SecnNet measures.
index=SecnNet action=* earliest=-24h
| search description="*bypass*"
| table user, description, _time

Get a list of all successful logins with multi-factor authentication.
index=SecnNet action=login multifactor_auth="true" earliest=-24h
| table user, 

Identify machines with unapproved software installations.
index=SecnNet source="system" action=install earliest=-24h
| search software!="*approved_software*"
| table host, software, _time

Search for attempts to access files with unauthorized encryption.
index=SecnNet source="file" action=*
| search file="*/sensitive/*" AND encryption="*unauthorized*"
| table user, file, encryption, _time

Detect attempts to create unauthorized network connections.
index=network source="network.log" action=*
| search dest_port!="*allowed_port*" AND action="connect"
| table host, dest_ip, dest_port, _time

Get a list of all successful login attempts with unusual locations.
index=SecnNet action=login earliest=-24h
| iplocation src_ip
| stats count by user, Country
| where Country!="United States" AND count > 5
| table user, Country, _time

Identify machines with unusually high CPU usage.
index=performance earliest=-24h
| stats avg(percent_cpu) as CPU by host
| where CPU > 80
| table host, CPU, _time

Search for attempts to change critical system files.
index=SecnNet source="system" action=modify
| search file="*/critical/*"
| table user, file, _time

Get a list of all web requests with unusual user agents.
index=web source="access.log" earliest=-24h
| search user_agent="*unusual_user_agent*"
| table clientip, user_agent, uri_path, _time

Detect attempts to exploit vulnerabilities in email clients.
index=SecnNet source="email" action=*
| search description="*vulnerability*"
| table user, description, _time

Identify machines with large numbers of failed login attempts.
index=SecnNet action=failure earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to use unauthorized remote access tools.
index=SecnNet source="remote_access" action=*
| search tool!="*approved_tool*"
| table user, tool, _time

Identify machines with unapproved software installations.
index=SecnNet source="system" action=install earliest=-24h
| search software!="*approved_software*"
| table host, software, _time

Search for attempts to access files with unauthorized encryption.
index=SecnNet source="file" action=*
| search file="*/sensitive/*" AND encryption="*unauthorized*"
| table user, file, encryption, _time

Detect attempts to create unauthorized network connections.
index=network source="network.log" action=*
| search dest_port!="*allowed_port*" AND action="connect"
| table host, dest_ip, dest_port, _time

Get a list of all successful login attempts with unusual locations.
index=SecnNet action=login earliest=-24h
| iplocation src_ip
| stats count by user, Country
| where Country!="United States" AND count > 5
| table user, Country, _time

Identify machines with unusually high CPU usage.
index=performance earliest=-24h
| stats avg(percent_cpu) as CPU by host
| where CPU > 80
| table host, CPU, _time

Search for attempts to change critical system files.
index=SecnNet source="system" action=modify
| search file="*/critical/*"
| table user, file, _time

Get a list of all web requests with unusual user agents.
index=web source="access.log" earliest=-24h
| search user_agent="*unusual_user_agent*"
| table clientip, user_agent, uri_path, _time

Detect attempts to exploit vulnerabilities in email clients.
index=SecnNet source="email" action=*
| search description="*vulnerability*"
| table user, description, _time

Identify machines with large numbers of failed login attempts.
index=SecnNet action=failure earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to use unauthorized remote access tools.
index=SecnNet source="remote_access" action=*
| search tool!="*approved_tool*"
| table user, tool, _time

Identify machines with suspicious process activity.
index=SecnNet action=* earliest=-24h
| search process="*suspicious_process*"
| table user, process, _time

Search for attempts to delete system logs.
index=SecnNet source="system" action=delete
| search file="*/log/*"
| table user, file, _time

Get a list of all successful logins with unusual durations.
index=SecnNet action=login earliest=-24h
| eval duration = _time - _indextime
| search duration > 3600
| table user, IP, duration, _time

Detect attempts to use unauthorized USB devices.
index=SecnNet source="usb" action=*
| search device!="*approved_device*"
| table user, device, _time

Identify machines with unusually high memory usage.
index=performance earliest=-24h
| stats avg(percent_memory) as memory by host
| where memory > 80
| table host, memory, _time

Search for attempts to modify or delete critical registry keys.
index=SecnNet source="registry" action=*
| search key="*/critical/*"
| table user, key, _time

Get a list of all failed login attempts with unusual usernames.
index=SecnNet action=failure earliest=-24h
| search user="*unusual_username*"
| table user, IP, _time

Detect attempts to use unauthorized network protocols.
index=network source="network.log" action=*
| search protocol!="*approved_protocol*"
| table host, protocol, _time

Identify machines with large amounts of network traffic from unusual sources.
index=network source="network.log" earliest=-24h
| stats sum(bytes) as bytes by host, src_ip
| where bytes > 100000000
| table host, src_ip, bytes, _time

Search for attempts to bypass email SecnNet measures.
index=SecnNet source="email" action=*
| search description="*bypass*"
| table user, description, _time

Identify machines with high numbers of failed email delivery attempts.
index=SecnNet source="email" action=delivery_failure earliest=-24h
| stats count by host, recipient
| where count > 10
| table host, recipient, count, _time

Search for attempts to escalate privileges through service account abuse.
index=SecnNet action=* earliest=-24h
| search user="*service_account*" AND description="*escalation*"
| table user, description, _time

Detect attempts to use unauthorized VPNs.
index=SecnNet source="vpn" action=*
| search vpn!="*approved_vpn*"
| table user, vpn, _time

Identify machines with unusually high numbers of outbound email messages.
index=SecnNet source="email" action=send earliest=-24h
| stats count by host, sender
| where count > 100
| table host, sender, count, _time

Search for attempts to access sensitive files during non-business hours.
index=SecnNet source="file" action=* earliest=-24h
| search file="*/sensitive/*" AND NOT strftime(_time, "%H") >= 9 AND NOT strftime(_time, "%H") <= 17
| table user, file, _time

Get a list of all email messages with attachments over a certain size.
index=SecnNet source="email" action=send earliest=-24h
| search attachment_size > 1000000
| table user, attachment_name, attachment_size, _time

Detect attempts to use unauthorized cloud storage services.
index=SecnNet source="cloud" action=*
| search service!="*approved_service*"
| table user, service, _time

Identify machines with unusually high numbers of DNS requests.
index=dns source="dns.log" earliest=-24h
| stats count by host
| where count > 1000
| table host, count, _time

Search for attempts to download files from unauthorized websites.
index=SecnNet source="web" action=*
| search url!="*approved_url*" AND action="download"
| table user, url, _time

Get a list of all successful SSH logins from unusual IP addresses.
index=SecnNet action=login earliest=-24h
| search protocol="ssh" AND NOT src_ip="*allowed_IP*"
| table user, src_ip, _time

Identify machines with unusually high numbers of SSH failed login attempts.
index=SecnNet action=failure earliest=-24h
| search protocol="ssh"
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to create unauthorized network shares.
index=SecnNet source="network" action=*
| search share!="*approved_share*"
| table user, share, _time

Get a list of all successful FTP logins with unusual upload activity.
index=SecnNet action=login earliest=-24h
| search protocol="ftp" AND action="upload"
| table user, IP, _time

Detect attempts to use unauthorized web proxies.
index=SecnNet source="web" action=*
| search proxy!="*approved_proxy*"
| table user, proxy, _time

Identify machines with unusually high numbers of Windows login failures.
index=SecnNet action=failure source="system" earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to disable or modify antivirus software.
index=SecnNet source="system" action=*
| search antivirus="*modify*" OR antivirus="*disable*"
| table user, antivirus, _time

Get a list of all successful VPN logins from unusual IP addresses.
index=SecnNet source="vpn" action=login earliest=-24h
| search NOT src_ip="*allowed_IP*"
| table user, src_ip, _time

Detect attempts to use unauthorized chat applications.
index=SecnNet source="chat" action=*
| search app!="*approved_chat*"
| table user, app, _time

Identify machines with unusually high numbers of file modifications.
index=SecnNet source="file" action=modify earliest=-24h
| stats count by host
| where count > 1000
| table host, count, _time

Search for attempts to escalate privileges through DLL hijacking.
index=SecnNet source="system" action=*
| search description="*DLL hijacking*"
| table user, description, _time

Identify machines with unusually high numbers of process starts.
index=SecnNet source="system" action=start earliest=-24h
| stats count by host
| where count > 5000
| table host, count, _time

Search for attempts to use unauthorized virtualization software.
index=SecnNet source="virtualization" action=*
| search software!="*approved_software*"
| table user, software, _time

Get a list of all successful logins with unusual locations.
index=SecnNet action=login earliest=-24h
| iplocation src_ip
| stats count by user, Country
| where Country!="United States" AND count > 5
| table user, Country, _time

Detect attempts to use unauthorized email clients.
index=SecnNet source="email" action=*
| search client!="*approved_client*"
| table user, client, _time

Identify machines with unusually high numbers of network traffic to suspicious countries.
index=network source="network.log" earliest=-24h
| stats sum(bytes) as bytes by host, dest_country
| where dest_country IN ("North Korea", "Iran", "Russia") AND bytes > 100000000
| table host, dest_country, bytes, _time

Search for attempts to use unauthorized file compression software.
index=SecnNet source="file" action=*
| search compression!="*approved_compression*"
| table user, compression, _time

Get a list of all successful logins with unusual durations.
index=SecnNet action=login earliest=-24h
| eval duration = _time - _indextime
| search duration > 3600
| table user, IP, duration, _time

Detect attempts to use unauthorized remote desktop software.
index=SecnNet source="remote_desktop" action=*
| search software!="*approved_software*"
| table user, software, _time

Identify machines with unusually high numbers of file deletions.
index=SecnNet source="file" action=delete earliest=-24h
| stats count by host
| where count > 500
| table host, count, _time

Search for attempts to escalate privileges through DLL search order hijacking.
index=SecnNet source="system" action=*
| search description="*DLL search order hijacking*"
| table user, description, _time

Identify machines with unusually high numbers of failed logins to cloud services.
index=SecnNet source="cloud" action=failure earliest=-24h
| stats count by host
| where count > 1000
| table host, count, _time

Search for attempts to use unauthorized remote access tools.
index=SecnNet source="remote_access" action=*
| search tool!="*approved_tool*"
| table user, tool, _time

Get a list of all successful logins with unusual device types.
index=SecnNet action=login earliest=-24h
| search NOT device_type="*laptop*" AND NOT device_type="*desktop*"
| table user, device_type, _time

Detect attempts to use unauthorized software installation tools.
index=SecnNet source="system" action=*
| search software_installation!="*approved_tool*"
| table user, software_installation, _time

Identify machines with unusually high numbers of successful DNS queries to suspicious domains.
index=dns source="dns.log" earliest=-24h
| stats count by host, query
| where query IN ("malware-domain.com", "phishing-domain.com", "botnet-domain.com") AND count > 100
| table host, query, count, _time

Search for attempts to access unauthorized databases.
index=SecnNet source="database" action=*
| search database!="*approved_database*"
| table user, database, _time

Get a list of all successful logins with unusual login types.
index=SecnNet action=login earliest=-24h
| search NOT login_type="*password*" AND NOT login_type="*token*"
| table user, login_type, _time

Detect attempts to use unauthorized encryption software.
index=SecnNet source="file" action=*
| search encryption!="*approved_encryption*"
| table user, encryption, _time

Identify machines with unusually high numbers of file access failures.
index=SecnNet source="file" action=access_failure earliest=-24h
| stats count by host
| where count > 1000
| table host, count, _time

Search for attempts to escalate privileges through process injection.
index=SecnNet source="system" action=*
| search description="*process injection*"
| table user, description, _time

Identify machines with unusually high numbers of successful logins to cloud services.
index=SecnNet source="cloud" action=success earliest=-24h
| stats count by host
| where count > 1000
| table host, count, _time

Search for attempts to use unauthorized USB devices.
index=SecnNet source="usb" action=*
| search device!="*approved_device*"
| table user, device, _time

Get a list of all successful logins with unusual protocols.
index=SecnNet action=login earliest=-24h
| search NOT protocol="*http*" AND NOT protocol="*ssh*" AND NOT protocol="*ftp*"
| table user, protocol, _time

Detect attempts to use unauthorized screen capture software.
index=SecnNet source="system" action=*
| search screen_capture!="*approved_software*"
| table user, screen_capture, _time

Identify machines with unusually high numbers of outgoing network connections.
index=network source="network.log" earliest=-24h
| stats count by host
| where count > 10000
| table host, count, _time

Search for attempts to access unauthorized cloud storage buckets.
index=SecnNet source="cloud" action=*
| search bucket!="*approved_bucket*"
| table user, bucket, _time

Get a list of all successful logins with unusual geographic locations.
index=SecnNet action=login earliest=-24h
| iplocation src_ip
| stats count by user, City
| where City!="New York" AND City!="San Francisco" AND count > 5
| table user, City, _time

Detect attempts to use unauthorized password cracking software.
index=SecnNet source="system" action=*
| search password_cracker!="*approved_software*"
| table user, password_cracker, _time

Identify machines with unusually high numbers of file copies to external devices.
index=SecnNet source="file" action=copy earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to escalate privileges through registry hijacking.
index=SecnNet source="system" action=*
| search description="*registry hijacking*"
| table user, description, _time

Identify machines with unusually high numbers of failed logins to cloud services from a single IP address.
index=SecnNet source="cloud" action=failure earliest=-24h | stats count by host, src_ip | where count > 50 | table host, src_ip, count, _time

Search for attempts to use unauthorized Bluetooth devices.
index=SecnNet source="bluetooth" action=* | search device!="*approved_device*" | table user, device, _time

Get a list of all successful logins with unusual IP geolocations.
index=SecnNet action=login earliest=-24h | iplocation src_ip | stats count by user, City | where City!="Los Angeles" AND City!="Seattle" AND count > 5 | table user, City, _time

Detect attempts to use unauthorized keylogging software.
index=SecnNet source="system" action=* | search keylogger!="*approved_software*" | table user, keylogger, _time

Identify machines with unusually high numbers of DNS requests to malicious domains.
index=dns source="dns.log" earliest=-24h | stats count by host, query | where query IN ("malware-domain.com", "phishing-domain.com", "botnet-domain.com") AND count > 1000 | table host, query, count, _time

Search for attempts to access unauthorized network shares.
index=SecnNet source="network" action=* | search share!="*approved_share*" | table user, share, _time

Get a list of all successful logins with unusual web browser types.
index=SecnNet action=login earliest=-24h | search NOT browser_type="*Chrome*" AND NOT browser_type="*Firefox*" AND NOT browser_type="*Safari*" | table user, browser_type, _time

Detect attempts to use unauthorized data encryption tools.
index=SecnNet source="file" action=* | search data_encryption!="*approved_tool*" | table user, data_encryption, _time

Identify machines with unusually high numbers of successful logins from a single IP address.
index=SecnNet action=success earliest=-24h | stats count by host, src_ip | where count > 50 | table host, src_ip, count, _time

Search for attempts to escalate privileges through DLL side-loading.
index=SecnNet source="system" action=* | search description="*DLL side-loading*" | table user, description, _time

Identify machines with unusually high numbers of failed logins to cloud services from a single user account.
index=SecnNet source="cloud" action=failure earliest=-24h | stats count by host, user | where count > 50 | table host, user, count, _time

Search for attempts to use unauthorized VPN software.
index=SecnNet source="network" action=* | search vpn!="*approved_vpn*" | table user, vpn, _time

Get a list of all successful logins with unusual device names.
index=SecnNet action=login earliest=-24h | search NOT device_name="*PC*" AND NOT device_name="*Mac*" | table user, device_name, _time

Detect attempts to use unauthorized remote control software.
index=SecnNet source="remote_access" action=* | search remote_control!="*approved_software*" | table user, remote_control, _time

Identify machines with unusually high numbers of inbound network connections.
index=network source="network.log" earliest=-24h | stats count by dest_ip | where count > 5000 | table dest_ip, count, _time

Search for attempts to access unauthorized cloud services.
index=SecnNet source="cloud" action=* | search service!="*approved_service*" | table user, service, _time

Get a list of all successful logins with unusual operating system versions.
index=SecnNet action=login earliest=-24h | search NOT os_version="*Windows 10*" AND NOT os_version="*macOS Big Sur*" | table user, os_version, _time

Detect attempts to use unauthorized software update tools.
index=SecnNet source="system" action=* | search software_update!="*approved_tool*" | table user, software_update, _time

Identify machines with unusually high numbers of file deletions.
index=SecnNet source="file" action=delete earliest=-24h | stats count by host | where count > 100 | table host, count, _time

Search for attempts to escalate privileges through DLL hijacking.
index=SecnNet source="system" action=* | search description="*DLL hijacking*" | table user, description, _time

Identify machines with unusually high numbers of successful logins from a single user account.
index=SecnNet action=success earliest=-24h | stats count by host, user | where count > 50 | table host, user, count, _time

Search for attempts to use unauthorized network sniffing tools.
index=SecnNet source="network" action=* | search sniffer!="*approved_tool*" | table user, sniffer, _time

Get a list of all successful logins with unusual email clients.
index=SecnNet action=login earliest=-24h | search NOT email_client="*Outlook*" AND NOT email_client="*Gmail*" | table user, email_client, _time

Detect attempts to use unauthorized remote access software.
index=SecnNet source="remote_access" action=* | search remote_access!="*approved_software*" | table user, remote_access, _time

Identify machines with unusually high numbers of outgoing network connections to foreign countries.
index=network source="network.log" earliest=-24h | iplocation dest_ip | stats count by host, Country | where Country!="United States" AND count > 10000 | table host, Country, count, _time

Search for attempts to access unauthorized database servers.
index=SecnNet source="database" action=* | search server!="*approved_server*" | table user, server, _time

Get a list of all successful logins with unusual email activity.
index=SecnNet action=login earliest=-24h | search NOT email_subject="*Welcome*" AND NOT email_subject="*Password Reset*" | table user, email_subject, _time

Detect attempts to use unauthorized disk encryption tools.
index=SecnNet source="file" action=* | search disk_encryption!="*approved_tool*" | table user, disk_encryption, _time

Identify machines with unusually high numbers of file modifications.
index=SecnNet source="file" action=modify earliest=-24h | stats count by host | where count > 500 | table host, count, _time

Search for attempts to escalate privileges through directory traversal.
index=SecnNet source="system" action=* | search description="*directory traversal*" | table user, description, _time

Identify machines with unusually high numbers of successful logins to cloud services from a single user account.
index=SecnNet source="cloud" action=success earliest=-24h | stats count by host, user | where count > 50 | table host, user, count, _time

Search for attempts to use unauthorized proxy servers.
index=SecnNet source="network" action=* | search proxy_server!="*approved_server*" | table user, proxy_server, _time

Get a list of all successful logins with unusual email attachments.
index=SecnNet action=login earliest=-24h | search NOT email_attachment="*Resume.pdf*" AND NOT email_attachment="*Invoice.docx*" | table user, email_attachment, _time

Detect attempts to use unauthorized virtualization software.
index=SecnNet source="system" action=* | search virtualization!="*approved_software*" | table user, virtualization, _time

Identify machines with unusually high numbers of incoming network connections from a single IP address.
index=network source="network.log" earliest=-24h | stats count by src_ip | where count > 5000 | table src_ip, count, _time

Search for attempts to access unauthorized cloud storage accounts.
index=SecnNet source="cloud" action=* | search storage_account!="*approved_account*" | table user, storage_account, _time

Get a list of all successful logins with unusual email sender addresses.
index=SecnNet action=login earliest=-24h | search NOT email_sender="*hr@company.com*" AND NOT email_sender="*it@company.com*" | table user, email_sender, _time

Detect attempts to use unauthorized disk wiping tools.
index=SecnNet source="file" action=* | search disk_wiping!="*approved_tool*" | table user, disk_wiping, _time

Identify machines with unusually high numbers of file renames.
index=SecnNet source="file" action=rename earliest=-24h | stats count by host | where count > 100 | table host, count, _time

Search for attempts to escalate privileges through unquoted service paths.
index=SecnNet source="system" action=* | search description="*unquoted service path*" | table user, description, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account.
index=SecnNet source="network" action=failure earliest=-24h | stats count by host, user | where count > 50 | table host, user, count, _time

Search for attempts to use unauthorized password cracking tools.
index=SecnNet source="password_cracking" action=* | search password_cracker!="*approved_tool*" | table user, password_cracker, _time

Get a list of all successful logins with unusual email activity based on timestamps.
index=SecnNet action=login earliest=-24h | search NOT email_subject="*Welcome*" AND NOT email_subject="*Password Reset*" | bin _time span=1h | stats count by user, email_subject, span | where count > 10 | table user, email_subject, span, count

Detect attempts to use unauthorized data exfiltration tools.
index=SecnNet source="data_exfiltration" action=* | search data_exfiltration!="*approved_tool*" | table user, data_exfiltration, _time

Identify machines with unusually high numbers of outbound network connections to known malicious IP addresses.
index=network source="network.log" earliest=-24h | iplocation dest_ip | where isnotnull(City) AND isnotnull(Country) AND Country!="United States" | lookup mal_ip_lookup ip as dest_ip OUTPUT threat_score, threat_category | stats count by host, dest_ip, threat_category, threat_score | where threat_score > 10 | table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud storage buckets.
index=SecnNet source="cloud" action=* | search storage_bucket!="*approved_bucket*" | table user, storage_bucket, _time

Get a list of all successful logins with unusual email recipient addresses.
index=SecnNet action=login earliest=-24h | search NOT email_recipient="*hr@company.com*" AND NOT email_recipient="*it@company.com*" | table user, email_recipient, _time

Detect attempts to use unauthorized data encryption tools.
index=SecnNet source="file" action=* | search data_encryption!="*approved_tool*" | table user, data_encryption, _time

Identify machines with unusually high numbers of file copies.
index=SecnNet source="file" action=copy earliest=-24h | stats count by host | where count > 100 | table host, count, _time

Search for attempts to escalate privileges through DLL search order hijacking.
index=SecnNet source="system" action=* | search description="*DLL search order hijacking*" | table user, description, _time

Identify machines with unusually high numbers of failed logins to cloud services from a single user account.
index=SecnNet source="cloud" action=failure earliest=-24h
| stats count by host, user
| where count > 50
| table host, user, count, _time

Search for attempts to use unauthorized VPN software.
index=SecnNet source="network" action=*
| search vpn!="*approved_software*"
| table user, vpn, _time

Get a list of all successful logins with unusual email content.
index=SecnNet action=login earliest=-24h
| search NOT email_body="*Welcome to our company!*" AND NOT email_body="*Please reset your password*"
| table user, email_body, _time

Detect attempts to use unauthorized browser extensions.
index=SecnNet source="browser" action=*
| search extension!="*approved_extension*"
| table user, extension, _time

Identify machines with unusually high numbers of outgoing network connections to known malicious domains.
index=network source="network.log" earliest=-24h
| rex "(?<domain>http| https)://(?<domainname>.*?)/"
| search NOT domainname="*company.com*"
| lookup mal_domain_lookup domainname as domainname OUTPUT threat_score, threat_category
| stats count by host, domainname, threat_category, threat_score
| where threat_score > 10
| table host, domainname, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services.
index=SecnNet source="cloud" action=*
| search cloud_service!="*approved_service*"
| table user, cloud_service, _time

Get a list of all successful logins with unusual email header information.
index=SecnNet action=login earliest=-24h
| search NOT email_header="*Received: from mail.company.com*" AND NOT email_header="*X-Mailer: Microsoft Outlook*"
| table user, email_header, _time

Detect attempts to use unauthorized data compression tools.
index=SecnNet source="file" action=*
| search data_compression!="*approved_tool*"
| table user, data_compression, _time

Identify machines with unusually high numbers of file deletions.
index=SecnNet source="file" action=delete earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to escalate privileges through named pipe impersonation.
index=SecnNet source="system" action=*
| search description="*named pipe impersonation*"
| table user, description, _time

Identify machines with unusually high numbers of failed logins to network resources from a single IP address.
index=SecnNet source="network" action=failure earliest=-24h
| stats count by host, src_ip
| where count > 50
| table host, src_ip, count, _time

Search for attempts to use unauthorized network scanning tools.
index=SecnNet source="network" action=*
| search network_scanner!="*approved_tool*"
| table user, network_scanner, _time

Get a list of all successful logins with unusual email addresses in the CC field.
index=SecnNet action=login earliest=-24h
| search NOT email_cc="*hr@company.com*" AND NOT email_cc="*it@company.com*"
| table user, email_cc, _time

Detect attempts to use unauthorized system administration tools.
index=SecnNet source="system" action=*
| search system_administration_tool!="*approved_tool*"
| table user, system_administration_tool, _time

Identify machines with unusually high numbers of outgoing network connections to unknown IP addresses.
index=network source="network.log" earliest=-24h
| iplocation dest_ip
| where isnull(City) AND isnull(Country)
| stats count by host, dest_ip
| where count > 100
| table host, dest_ip, count, _time

Search for attempts to access unauthorized cloud storage files.
index=SecnNet source="cloud" action=*
| search storage_file!="*approved_file*"
| table user, storage_file, _time

Get a list of all successful logins with unusual email addresses in the BCC field.
index=SecnNet action=login earliest=-24h
| search NOT email_bcc="*hr@company.com*" AND NOT email_bcc="*it@company.com*"
| table user, email_bcc, _time

Detect attempts to use unauthorized system backup tools.
index=SecnNet source="system" action=*
| search system_backup_tool!="*approved_tool*"
| table user, system_backup_tool, _time

Identify machines with unusually high numbers of file reads.
index=SecnNet source="file" action=read earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to escalate privileges through weak file permissions.
index=SecnNet source="file" action=*
| search file_permissions="*weak_permissions*"
| table user, file_permissions, _time

Identify machines with unusually high numbers of failed logins to cloud services from a single IP address.
index=SecnNet source="cloud" action=failure earliest=-24h
| stats count by host, src_ip
| where count > 50
| table host, src_ip, count, _time

Search for attempts to use unauthorized system monitoring tools.
index=SecnNet source="system" action=*
| search system_monitoring_tool!="*approved_tool*"
| table user, system_monitoring_tool, _time

Get a list of all successful logins with unusual email addresses in the reply-to field.
index=SecnNet action=login earliest=-24h
| search NOT email_reply_to="*hr@company.com*" AND NOT email_reply_to="*it@company.com*"
| table user, email_reply_to, _time

Detect attempts to use unauthorized registry editing tools.
index=SecnNet source="system" action=*
| search registry_editor!="*approved_tool*"
| table user, registry_editor, _time

Identify machines with unusually high numbers of outbound network connections to unknown domains.
index=network source="network.log" earliest=-24h
| rex "(?<domain>http| https)://(?<domainname>.*?)/"
| search NOT domainname="*company.com*"
| lookup mal_domain_lookup domainname as domainname OUTPUT threat_score, threat_category
| stats count by host, domainname, threat_category, threat_score
| where threat_score < 1
| table host, domainname, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved devices.
index=SecnNet source="cloud" action=*
| search device!="*approved_device*"
| table user, device, _time

Get a list of all successful logins with unusual email addresses in the from field.
index=SecnNet action=login earliest=-24h
| search NOT email_from="*hr@company.com*" AND NOT email_from="*it@company.com*"
| table user, email_from, _time

Detect attempts to use unauthorized software installation tools.
index=SecnNet source="system" action=*
| search software_installation_tool!="*approved_tool*"
| table user, software_installation_tool, _time

Identify machines with unusually high numbers of file modifications.
index=SecnNet source="file" action=modify earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to escalate privileges through weak service permissions.
index=SecnNet source="system" action=*
| search service_permissions="*weak_permissions*"
| table user, service_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account.
index=SecnNet source="network" action=failure earliest=-24h
| stats count by host, user
| where count > 50
| table host, user, count, _time

Search for attempts to use unauthorized USB devices.
index=SecnNet source="system" action=*
| search usb_device!="*approved_device*"
| table user, usb_device, _time

Get a list of all successful logins with unusual email attachments.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment="*resume.pdf*" AND NOT email_attachment="*project_report.docx*"
| table user, email_attachment, _time

Detect attempts to use unauthorized remote desktop software.
index=SecnNet source="system" action=*
| search remote_desktop!="*approved_software*"
| table user, remote_desktop, _time

Identify machines with unusually high numbers of outbound network connections to known malicious IP addresses.
index=network source="network.log" earliest=-24h
| iplocation dest_ip
| lookup mal_ip_lookup dest_ip as dest_ip OUTPUT threat_score, threat_category
| stats count by host, dest_ip, threat_category, threat_score
| where threat_score > 10
| table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved browsers.
index=SecnNet source="cloud" action=*
| search browser!="*approved_browser*"
| table user, browser, _time

Get a list of all successful logins with unusual email subjects.
index=SecnNet action=login earliest=-24h
| search NOT email_subject="*Login successful*" AND NOT email_subject="*Password reset*"
| table user, email_subject, _time

Detect attempts to use unauthorized virtualization software.
index=SecnNet source="system" action=*
| search virtualization!="*approved_software*"
| table user, virtualization, _time

Identify machines with unusually high numbers of failed logins.
index=SecnNet action=failure earliest=-24h
| stats count by host
| where count > 100
| table host, count, _time

Search for attempts to escalate privileges through weak user account permissions.
index=SecnNet source="system" action=*
| search user_account_permissions="*weak_permissions*"
| table user, user_account_permissions, _time

Identify machines with unusually high numbers of failed logins to cloud services from a single user account.
index=SecnNet source="cloud" action=failure earliest=-24h
| stats count by host, user
| where count > 50
| table host, user, count, _time

Search for attempts to use unauthorized system configuration tools.
index=SecnNet source="system" action=*
| search system_configuration_tool!="*approved_tool*"
| table user, system_configuration_tool, _time

Get a list of all successful logins with unusual email bodies.
index=SecnNet action=login earliest=-24h
| search NOT email_body="*Please find attached*" AND NOT email_body="*Dear Sir/Madam*"
| table user, email_body, _time

Detect attempts to use unauthorized data recovery tools.
index=SecnNet source="system" action=*
| search data_recovery_tool!="*approved_tool*"
| table user, data_recovery_tool, _time

Identify machines with unusually high numbers of outbound network connections to known malicious domains.
index=network source="network.log" earliest=-24h
| rex "(?<domain>http| https)://(?<domainname>.*?)/"
| lookup mal_domain_lookup domainname as domainname OUTPUT threat_score, threat_category
| stats count by host, domainname, threat_category, threat_score
| where threat_score > 10
| table host, domainname, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved mobile devices.
index=SecnNet source="cloud" action=*
| search device_type!="*approved_mobile_device*"
| table user, device_type, _time

Get a list of all successful logins with unusual email signatures.
index=SecnNet action=login earliest=-24h
| search NOT email_signature="*Best regards*" AND NOT email_signature="*Sincerely*"
| table user, email_signature, _time

Detect attempts to use unauthorized virtual private network (VPN) software.
index=SecnNet source="system" action=*
| search vpn_software!="*approved_software*"
| table user, vpn_software, _time

Identify machines with unusually high numbers of failed logins to web applications from a single IP address.
index=SecnNet source="web" action=failure earliest=-24h
| stats count by host, src_ip
| where count > 50
| table host, src_ip, count, _time

Search for attempts to escalate privileges through weak group policy permissions.
index=SecnNet source="system" action=*
| search group_policy_permissions="*weak_permissions*"
| table user, group_policy_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single domain account.
index=SecnNet source="network" action=failure earliest=-24h
| stats count by host, domain_account
| where count > 50
| table host, domain_account, count, _time

Search for attempts to use unauthorized system monitoring tools.
index=SecnNet source="system" action=*
| search system_monitoring_tool!="*approved_tool*"
| table user, system_monitoring_tool, _time

Get a list of all successful logins with unusual email senders and subjects.
index=SecnNet action=login earliest=-24h
| search NOT email_sender="*admin@company.com*" AND NOT email_sender="*support@company.com*" AND NOT email_subject="*Login successful*" AND NOT email_subject="*Password reset*"
| table user, email_sender, email_subject, _time

Detect attempts to use unauthorized disk encryption software.
index=SecnNet source="system" action=*
| search disk_encryption_software!="*approved_software*"
| table user, disk_encryption_software, _time

Identify machines with unusually high numbers of outbound network connections to unknown domains.
index=network source="network.log" earliest=-24h
| rex "(?<domain>http|https)://(?<domainname>.*?)/"
| lookup mal_domain_lookup domainname as domainname OUTPUT threat_score, threat_category
| stats count by host, domainname, threat_category, threat_score
| where threat_score < 1
| table host, domainname, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved operating system versions.
index=SecnNet source="cloud" action=*
| search os_version!="*approved_os_version*"
| table user, os_version, _time

Get a list of all successful logins with unusual email attachments and recipients.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment="*resume.pdf*" AND NOT email_attachment="*project_report.docx*" AND NOT email_recipient="*admin@company.com*" AND NOT email_recipient="*support@company.com*"
| table user, email_attachment, email_recipient, _time

Detect attempts to use unauthorized remote access software.
index=SecnNet source="system" action=*
| search remote_access_software!="*approved_software*"
| table user, remote_access_software, _time

Identify machines with unusually high numbers of failed logins to web applications from a single domain account.
index=SecnNet source="web" action=failure earliest=-24h
| stats count by host, domain_account
| where count > 50
| table host, domain_account, count, _time

Search for attempts to escalate privileges through weak registry permissions.
index=SecnNet source="system" action=*
| search registry_permissions="*weak_permissions*"
| table user, registry_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single domain group.
index=SecnNet source="network" action=failure earliest=-24h
| stats count by host, domain_group
| where count > 50
| table host, domain_group, count, _time

Search for attempts to use unauthorized database tools.
index=SecnNet source="database" action=*
| search database_tool!="*approved_tool*"
| table user, database_tool, _time

Get a list of all successful logins with unusual email attachment types.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment="*.pdf" AND NOT email_attachment="*.docx"
| table user, email_attachment, _time

Detect attempts to use unauthorized disk partitioning software.
index=SecnNet source="system" action=*
| search disk_partitioning_software!="*approved_software*"
| table user, disk_partitioning_software, _time

Identify machines with unusually high numbers of outbound network connections to known phishing domains.
index=network source="network.log" earliest=-24h
| rex "(?<domain>http|https)://(?<domainname>.*?)/"
| lookup phishing_domain_lookup domainname as domainname OUTPUT threat_score, threat_category
| stats count by host, domainname, threat_category, threat_score
| where threat_score > 10
| table host, domainname, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved web browsers.
index=SecnNet source="cloud" action=*
| search web_browser!="*approved_browser*"
| table user, web_browser, _time

Get a list of all successful logins with unusual email attachment sizes.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment_size="*1MB*" AND NOT email_attachment_size="*2MB*"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized remote execution tools.
index=SecnNet source="system" action=*
| search remote_execution_tool!="*approved_tool*"
| table user, remote_execution_tool, _time

Identify machines with unusually high numbers of failed logins to web applications from a single domain group.
index=SecnNet source="web" action=failure earliest=-24h
| stats count by host, domain_group
| where count > 50
| table host, domain_group, count, _time

Search for attempts to escalate privileges through weak service permissions.
index=SecnNet source="system" action=*
| search service_permissions="*weak_permissions*"
| table user, service_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account with non-standard characters in the username.
index=SecnNet source="network" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| stats count by host, user
| where count > 50
| table host, user, count, _time

Search for attempts to use unauthorized email clients.
index=SecnNet source="email" action=*
| search email_client!="*approved_client*"
| table user, email_client, _time

Get a list of all successful logins with unusual email attachment extensions.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment="*.pdf" AND NOT email_attachment="*.docx" AND NOT email_attachment="*.xls"
| table user, email_attachment, _time

Detect attempts to use unauthorized VPN software.
index=SecnNet source="network" action=*
| search vpn_software!="*approved_software*"
| table user, vpn_software, _time

Identify machines with unusually high numbers of outbound network connections to known command-and-control servers.
index=network source="network.log" earliest=-24h
| lookup cnc_ip_lookup dest_ip as dest_ip OUTPUT threat_score, threat_category
| stats count by host, dest_ip, threat_category, threat_score
| where threat_score > 10
| table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved VPN connections.
index=SecnNet source="cloud" action=*
| search vpn_connection!="*approved_connection*"
| table user, vpn_connection, _time

Get a list of all successful logins with unusual email body content.
index=SecnNet action=login earliest=-24h
| search NOT email_body="*Welcome to our platform*" AND NOT email_body="*Please reset your password*"
| table user, email_body, _time

Detect attempts to use unauthorized remote access tools.
index=SecnNet source="system" action=*
| search remote_access_tool!="*approved_tool*"
| table user, remote_access_tool, _time

Identify machines with unusually high numbers of failed logins to web applications from a single user account with non-standard characters in the username.
index=SecnNet source="web" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| stats count by host, user
| where count > 50
| table host, user, count, _time

Search for attempts to escalate privileges through weak user account permissions.
index=SecnNet source="system" action=*
| search user_account_permissions="*weak_permissions*"
| table user, user_account_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account with unusual IP addresses.
index=SecnNet source="network" action=failure earliest=-24h
| rex field=src_ip "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by host, src_ip
| where count > 50
| table host, src_ip, count, _time

Search for attempts to use unauthorized software development tools.
index=SecnNet source="development" action=*
| search software_development_tool!="*approved_tool*"
| table user, software_development_tool, _time

Get a list of all successful logins with unusual email body lengths.
index=SecnNet action=login earliest=-24h
| search NOT len(email_body)="*1000" AND NOT len(email_body)="*2000" AND NOT len(email_body)="*3000"
| table user, len(email_body), _time

Detect attempts to use unauthorized browser extensions.
index=SecnNet source="browser" action=*
| search browser_extension!="*approved_extension*"
| table user, browser_extension, _time

Identify machines with unusually high numbers of outbound network connections to known malware distribution sites.
index=network source="network.log" earliest=-24h
| lookup malware_distribution_site_lookup dest_ip as dest_ip OUTPUT threat_score, threat_category
| stats count by host, dest_ip, threat_category, threat_score
| where threat_score > 10
| table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved mobile devices.
index=SecnNet source="cloud" action=*
| search mobile_device!="*approved_device*"
| table user, mobile_device, _time

Get a list of all successful logins with unusual email body content types.
index=SecnNet action=login earliest=-24h
| search NOT email_body_type="*text*" AND NOT email_body_type="*html*"
| table user, email_body_type, _time

Detect attempts to use unauthorized privilege escalation tools.
index=SecnNet source="system" action=*
| search privilege_escalation_tool!="*approved_tool*"
| table user, privilege_escalation_tool, _time

Identify machines with unusually high numbers of failed logins to web applications from a single user account with unusual IP addresses.
index=SecnNet source="web" action=failure earliest=-24h
| rex field=src_ip "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by host, src_ip
| where count > 50
| table host, src_ip, count, _time

Search for attempts to escalate privileges through weak file system permissions.
index=SecnNet source="system" action=*
| search file_system_permissions="*weak_permissions*"
| table user, file_system_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account with non-standard timezones.
index=SecnNet source="network" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=_time "(?<timezone>[+-]\d{2}:?\d{2})"
| stats count by host, user, timezone
| where count > 50
| table host, user, timezone, count, _time

Search for attempts to use unauthorized FTP clients.
index=SecnNet source="network" action=* ftp_client!="*approved_client*"
| table user, ftp_client, _time

Get a list of all successful logins with unusual email attachment sizes.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment_size="*100KB" AND NOT email_attachment_size="*500KB" AND NOT email_attachment_size="*1MB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized SSH clients.
index=SecnNet source="network" action=* ssh_client!="*approved_client*"
| table user, ssh_client, _time

Identify machines with unusually high numbers of outbound network connections to known phishing sites.
index=network source="network.log" earliest=-24h
| lookup phishing_site_lookup dest_ip as dest_ip OUTPUT threat_score, threat_category
| stats count by host, dest_ip, threat_category, threat_score
| where threat_score > 10
| table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved browsers.
index=SecnNet source="cloud" action=*
| search browser!="*approved_browser*"
| table user, browser, _time

Get a list of all successful logins with unusual email attachment file types.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment_type="*doc*" AND NOT email_attachment_type="*pdf*" AND NOT email_attachment_type="*xls*"
| table user, email_attachment_type, _time

Detect attempts to use unauthorized privilege escalation techniques through system calls.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*"
| table user, privilege_escalation_technique, _time

Identify machines with unusually high numbers of failed logins to web applications from a single user account with non-standard timezones.
index=SecnNet source="web" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=_time "(?<timezone>[+-]\d{2}:?\d{2})"
| stats count by host, user, timezone
| where count > 50
| table host, user, timezone, count, _time

Search for attempts to escalate privileges through weak database permissions.
index=SecnNet source="database" action=*
| search database_permissions="*weak_permissions*"
| table user, database_permissions, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account with non-standard keyboard layouts.
index=SecnNet source="network" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=src_ip "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| rex field=_raw "(?<keyboard_layout>azerty|colemak|dvorak|qwerty)"
| stats count by host, user, src_ip, keyboard_layout
| where count > 50
| table host, user, src_ip, keyboard_layout, count, _time

Search for attempts to use unauthorized network mapping tools.
index=SecnNet source="network" action=*
| search network_mapping_tool!="*approved_tool*"
| table user, network_mapping_tool, _time

Get a list of all successful logins with unusual email attachment file names.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment_name="*resume*" AND NOT email_attachment_name="*invoice*" AND NOT email_attachment_name="*contract*"
| table user, email_attachment_name, _time

Detect attempts to use unauthorized VPN clients.
index=SecnNet source="network" action=* vpn_client!="*approved_client*"
| table user, vpn_client, _time

Identify machines with unusually high numbers of outbound network connections to known command and control servers.
index=network source="network.log" earliest=-24h
| lookup command_and_control_server_lookup dest_ip as dest_ip OUTPUT threat_score, threat_category
| stats count by host, dest_ip, threat_category, threat_score
| where threat_score > 10
| table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved operating systems.
index=SecnNet source="cloud" action=*
| search operating_system!="*approved_OS*"
| table user, operating_system, _time

Get a list of all successful logins with unusual email attachment file extensions.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment_extension="*docx*" AND NOT email_attachment_extension="*pdf*" AND NOT email_attachment_extension="*xlsx*"
| table user, email_attachment_extension, _time

Detect attempts to use unauthorized privilege escalation techniques through service accounts.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*service_account*"
| table user, privilege_escalation_technique, _time

Identify machines with unusually high numbers of failed logins to web applications from a single user account with non-standard keyboard layouts.
index=SecnNet source="web" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=src_ip "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| rex field=_raw "(?<keyboard_layout>azerty|colemak|dvorak|qwerty)"
| stats count by host, user, src_ip, keyboard_layout
| where count > 50
| table host, user, src_ip, keyboard_layout, count, _time

Search for attempts to use unauthorized network scanning tools.
index=SecnNet source="network" action=*
| search network_scanning_tool!="*approved_tool*"
| table user, network_scanning_tool, _time

Get a list of all successful logins with unusual email attachment MIME types.
index=SecnNet action=login earliest=-24h
| search NOT email_attachment_mime_type="*application/pdf*" AND NOT email_attachment_mime_type="*application/msword*" AND NOT email_attachment_mime_type="*application/vnd.ms-excel*"
| table user, email_attachment_mime_type, _time

Detect attempts to use unauthorized remote desktop software.
index=SecnNet source="network" action=* remote_desktop_software!="*approved_software*"
| table user, remote_desktop_software, _time

Identify machines with unusually high numbers of outbound network connections to known malicious IP addresses.
index=network source="network.log" earliest=-24h
| lookup malicious_ip_lookup dest_ip as dest_ip OUTPUT threat_score, threat_category
| stats count by host, dest_ip, threat_category, threat_score
| where threat_score > 10
| table host, dest_ip, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved mobile devices.
index=SecnNet source="cloud" action=*
| search mobile_device!="*approved_device*"
| table user, mobile_device, _time

Get a list of all successful logins with unusual email attachment sizes for financial reports.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*financial_report*" AND NOT email_attachment_size="*500KB" AND NOT email_attachment_size="*1MB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized privilege escalation techniques through file system manipulation.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*file_system_manipulation*"
| table user, privilege_escalation_technique, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account with non-standard browser versions.
index=SecnNet source="network" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=_raw "(?<browser_version>\d{1,2}\.\d{1,2})"
| stats count by host, user, browser_version
| where count > 50
| table host, user, browser_version, count, _time

Search for attempts to escalate privileges through unapproved scripts.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*scripting*"
| table user, privilege_escalation_technique, _time

Get a list of all successful logins with unusual email attachment file sizes for contracts.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*contract*" AND NOT email_attachment_size="*100KB" AND NOT email_attachment_size="*500KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized file transfer tools.
index=SecnNet source="network" action=*
| search file_transfer_tool!="*approved_tool*"
| table user, file_transfer_tool, _time

Identify machines with unusually high numbers of outbound network connections to known malicious domains.
index=network source="network.log" earliest=-24h
| lookup malicious_domain_lookup dest_domain as dest OUTPUT threat_score, threat_category
| stats count by host, dest, threat_category, threat_score
| where threat_score > 10
| table host, dest, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved browsers.
index=SecnNet source="cloud" action=*
| search browser!="*approved_browser*"
| table user, browser, _time

Get a list of all successful logins with unusual email attachment file sizes for resumes.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*resume*" AND NOT email_attachment_size="*200KB" AND NOT email_attachment_size="*500KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized remote access tools.
index=SecnNet source="network" action=* remote_access_tool!="*approved_tool*"
| table user, remote_access_tool, _time

Identify machines with unusually high numbers of failed logins to web applications from a single user account with non-standard browser types.
index=SecnNet source="web" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=_raw "(?<browser_type>chrome|firefox|safari|edge)"
| stats count by host, user, browser_type
| where count > 50
| table host, user, browser_type, count, _time

Search for attempts to use unauthorized privilege escalation techniques through suspicious processes.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*suspicious_processes*"
| table user, privilege_escalation_technique, _time

Get a list of all successful logins with unusual email attachment file sizes for invoices.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*invoice*" AND NOT email_attachment_size="*50KB" AND NOT email_attachment_size="*100KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized network sniffing tools.
index=SecnNet source="network" action=*
| search network_sniffing_tool!="*approved_tool*"
| table user, network_sniffing_tool, _time

Identify machines with unusually high numbers of outbound network connections to known phishing domains.
index=network source="network.log" earliest=-24h
| lookup phishing_domain_lookup dest_domain as dest OUTPUT threat_score, threat_category
| stats count by host, dest, threat_category, threat_score
| where threat_score > 10
| table host, dest, threat_category, threat_score, _time

Search for attempts to access unauthorized cloud services through unapproved operating systems.
index=SecnNet source="cloud" action=*
| search os!="*approved_os*"
| table user, os, _time

Get a list of all successful logins with unusual email attachment file sizes for legal documents.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*legal_document*" AND NOT email_attachment_size="*300KB" AND NOT email_attachment_size="*500KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized port scanning tools.
index=SecnNet source="network" action=*
| search port_scanning_tool!="*approved_tool*"
| table user, port_scanning_tool, _time

Identify machines with unusually high numbers of outbound network connections to known crypto mining domains.
index=network source="network.log" earliest=-24h
| lookup crypto_mining_domain_lookup dest_domain as dest OUTPUT threat_score, threat_category
| stats count by host, dest, threat_category, threat_score
| where threat_score > 10
| table host, dest, threat_category, threat_score, _time

Search for attempts to use unauthorized tools for privilege escalation through DLL hijacking.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*dll_hijacking*"
| table user, privilege_escalation_technique, _time

Get a list of all successful logins with unusual email attachment file sizes for resumes.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*resume*" AND NOT email_attachment_size="*200KB" AND NOT email_attachment_size="*500KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized password cracking tools.
index=SecnNet source="system" action=*
| search password_cracking_tool!="*approved_tool*"
| table user, password_cracking_tool, _time

Identify machines with unusually high numbers of failed logins to network resources from a single user account with non-standard operating system versions.
index=SecnNet source="network" action=failure earliest=-24h
| rex field=user "(?<user>[a-zA-Z0-9]+)"
| rex field=_raw "(?<os_version>\d{1,2}\.\d{1,2})"
| stats count by host, user, os_version
| where count > 50
| table host, user, os_version, count, _time

Search for attempts to use unauthorized network eavesdropping tools.
index=SecnNet source="network" action=*
| search network_eavesdropping_tool!="*approved_tool*"
| table user, network_eavesdropping_tool, _time

Identify machines with unusually high numbers of outbound network connections to known spamming domains.
index=network source="network.log" earliest=-24h
| lookup spamming_domain_lookup dest_domain as dest OUTPUT threat_score, threat_category
| stats count by host, dest, threat_category, threat_score
| where threat_score > 10
| table host, dest, threat_category, threat_score, _time

Search for attempts to use unauthorized tools for privilege escalation through Registry hijacking.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*registry_hijacking*"
| table user, privilege_escalation_technique, _time

Get a list of all successful logins with unusual email attachment file sizes for financial documents.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*financial_document*" AND NOT email_attachment_size="*100KB" AND NOT email_attachment_size="*200KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized network monitoring tools.
index=SecnNet source="network" action=*
| search network_monitoring_tool!="*approved_tool*"
| table user, network_monitoring_tool, _time

Identify machines with unusually high numbers of outbound network connections to known ransomware domains.
index=network source="network.log" earliest=-24h
| lookup ransomware_domain_lookup dest_domain as dest OUTPUT threat_score, threat_category
| stats count by host, dest, threat_category, threat_score
| where threat_score > 10
| table host, dest, threat_category, threat_score, _time

Search for attempts to use unauthorized tools for privilege escalation through system file manipulation.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*system_file_manipulation*"
| table user, privilege_escalation_technique, _time

Get a list of all successful logins with unusual email attachment file sizes for contracts.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*contract*" AND NOT email_attachment_size="*150KB" AND NOT email_attachment_size="*300KB"
| table user, email_attachment_size, _time

Detect attempts to use unauthorized network sniffing tools.
index=SecnNet source="network" action=*
| search network_sniffing_tool!="*approved_tool*"
| table user, network_sniffing_tool, _time

Identify machines with unusually high numbers of outbound network connections to known C2 servers.
index=network source="network.log" earliest=-24h
| lookup C2_domain_lookup dest_domain as dest OUTPUT threat_score, threat_category
| stats count by host, dest, threat_category, threat_score
| where threat_score > 10
| table host, dest, threat_category, threat_score, _time

Search for attempts to use unauthorized tools for privilege escalation through impersonation.
index=SecnNet source="system" action=*
| search privilege_escalation_technique!="*approved_technique*" AND user="*impersonation*"
| table user, privilege_escalation_technique, _time

Get a list of all successful logins with unusual email attachment file sizes for confidential documents.
index=SecnNet action=login earliest=-24h
| search email_attachment_name="*confidential*" AND NOT email_attachment_size="*250KB" AND NOT email_attachment_size="*500KB"
| table user, email_attachment_size, _time

