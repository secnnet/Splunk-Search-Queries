Search for failed logins from all stakeholders:
index=security sourcetype=auth fail* host=bank.com 
| stats count by user 
| sort -count

Search for successful logins from a specific stakeholder:
index=security sourcetype=auth success host=bank.com user="SecnNet"

Search for all access to sensitive data from a specific stakeholder:
index=security sourcetype=access_logs path="/sensitive_data/*" user="SecnNet"

Search for all transactions above a certain amount:
index=banking sourcetype=transactions amount>=10000

Search for all transactions that occurred during non-business hours:
index=banking sourcetype=transactions earliest=-2d@d latest=@d 
| where strftime(_time, "%H") < "08" OR strftime(_time, "%H") >= "17"

Search for all failed transactions with a specific error code:
index=banking sourcetype=transactions error_code="1234"

Search for all changes to user accounts:
index=security sourcetype=auth action=modify 
| stats count by user 
| sort -count

Search for all changes to user accounts made by a specific stakeholder:
index=security sourcetype=auth action=modify user="SecnNet"

Search for all connections to external IP addresses:
index=networking sourcetype=connections dest_ip!="bank.com"

Search for all connections to specific IP addresses:
index=networking sourcetype=connections dest_ip="192.168.1.1"

Search for all connections from specific IP addresses:
index=networking sourcetype=connections src_ip="192.168.1.1"

Search for all connections over non-standard ports:
index=networking sourcetype=connections port!=80 port!=443

Search for all connections that lasted for a specific amount of time:
index=networking sourcetype=connections duration>600

Search for all connections that were initiated during non-business hours:
index=networking sourcetype=connections earliest=-2d@d latest=@d 
| where strftime(_time, "%H") < "08" OR strftime(_time, "%H") >= "17"

Search for all firewall events:
index=security sourcetype=firewall

Search for all firewall events that match a specific rule:
index=security sourcetype=firewall rule_name="allow_ftp"

Search for all antivirus events:
index=security sourcetype=antivirus

Search for all antivirus events that match a specific signature:
index=security sourcetype=antivirus signature="worm.win32"

Search for all web traffic:
index=web sourcetype=access_logs

Search for all web traffic to a specific domain:
index=web sourcetype=access_logs domain="bank.com"

Search for all web traffic that resulted in HTTP error codes:
index=web sourcetype=access_logs status>=400

Search for all web traffic from a specific IP address:
index=web sourcetype=access_logs clientip="192.168.1.1"

Search for all DNS requests:
index=networking sourcetype=dns

Search for all DNS requests for a specific domain:
index=networking sourcetype=dns query="bank.com"

Search for all file access events:
index=security sourcetype=file_audit

Search for all file access events for a specific file:
index=security sourcetype=file_audit path="/sensitive_data/file.txt"

Search for all file access events by a specific user:
index=security sourcetype=file_audit user="SecnNet"

Search for all file access events that match a specific operation:
index=security sourcetype=file_audit operation="write"

Search for all email events:
index=email sourcetype=email_logs

Search for all email events with a specific subject line:
index=email sourcetype=email_logs subject="Important Message"

Search for all VPN connections:
index=security sourcetype=vpn_logs

Search for all VPN connections initiated by a specific user:
index=security sourcetype=vpn_logs user="SecnNet"

Search for all VPN connections from a specific IP address:
index=security sourcetype=vpn_logs src_ip="192.168.1.1"

Search for all VPN connections to a specific IP address:
index=security sourcetype=vpn_logs dest_ip="10.0.0.1"

Search for all IDS events:
index=security sourcetype=ids_logs

Search for all IDS events that match a specific signature:
index=security sourcetype=ids_logs signature="alert_tcp_port_scan"

Search for all IDS events from a specific IP address:
index=security sourcetype=ids_logs src_ip="192.168.1.1"

Search for all IDS events to a specific IP address:
index=security sourcetype=ids_logs dest_ip="10.0.0.1"

Search for all changes to firewall rules:
index=security sourcetype=firewall_changes

Search for all changes to firewall rules made by a specific user:
index=security sourcetype=firewall_changes user="SecnNet"

Search for all traffic to and from a specific subnet:
(index=networking sourcetype=connections) OR (index=networking sourcetype=dns) 
| search (src_ip="10.0.0.0/24" OR dest_ip="10.0.0.0/24")

Search for all changes to user roles:
index=security sourcetype=user_roles_changes

Search for all changes to user roles made by a specific user:
index=security sourcetype=user_roles_changes user="SecnNet"

Search for all SSH sessions:
index=security sourcetype=ssh_logs

Search for all SSH sessions initiated by a specific user:
index=security sourcetype=ssh_logs user="SecnNet"

Search for all SSH sessions to a specific host:
index=security sourcetype=ssh_logs dest_host="10.0.0.1"

Search for all HTTPS traffic:
index=web sourcetype=access_logs method=GET status=200 
| search uri_path="https://*"

Search for all HTTP traffic from a specific IP address:
index=web sourcetype=access_logs clientip="192.168.1.1" uri_path!="https://*"

Search for all DNS requests for non-existent domains:
index=networking sourcetype=dns error_code="NXDOMAIN"

Search for all connections that were active for more than a specific amount of time:
index=networking sourcetype=connections duration>=3600

Search for all changes to file permissions:
index=security sourcetype=file_permissions_changes

Search for all changes to file permissions made by a specific user:
index=security sourcetype=file_permissions_changes user="SecnNet"

Search for all FTP sessions:
index=security sourcetype=ftp_logs

Search for all FTP sessions initiated by a specific user:
index=security sourcetype=ftp_logs user="SecnNet"

Search for all FTP sessions to a specific host:
index=security sourcetype=ftp_logs dest_host="10.0.0.1"

Search for all changes to database permissions:
index=security sourcetype=db_permissions_changes

Search for all changes to database permissions made by a specific user:
index=security sourcetype=db_permissions_changes user="SecnNet"

Search for all database access events:
index=security sourcetype=db_audit_logs

Search for all database access events from a specific IP address:
index=security sourcetype=db_audit_logs src_ip="192.168.1.1"

Search for all database access events to a specific table:
index=security sourcetype=db_audit_logs table="customer_info"

Search for all SSH failed login attempts:
index=security sourcetype=ssh_logs failed_login=true

Search for all SSH login attempts from a specific IP address:
index=security sourcetype=ssh_logs src_ip="192.168.1.1" 
| search login_success=true

Search for all login events across all systems:
index=* sourcetype=login_events

Search for all login events from a specific user:
index=* sourcetype=login_events user="SecnNet"

Search for all RDP connections:
index=security sourcetype=rdp_logs

Search for all RDP connections initiated by a specific user:
index=security sourcetype=rdp_logs user="SecnNet"

0Search for all RDP connections to a specific host:
index=security sourcetype=rdp_logs dest_host="10.0.0.1"

Search for all changes to group membership:
index=security sourcetype=group_membership_changes

Search for all changes to group membership made by a specific user:
index=security sourcetype=group_membership_changes user="SecnNet"

Search for all connections to a specific database:
index=security sourcetype=db_connections_logs db_name="my_database"

Search for all failed login attempts across all systems:
index=* sourcetype=login_events login_success=false

Search for all login attempts from a specific IP address:
index=* sourcetype=login_events src_ip="192.168.1.1"

Search for all login attempts to a specific system:
index=* sourcetype=login_events dest_ip="10.0.0.1"

Search for all traffic to a specific domain:
index=web sourcetype=access_logs uri_domain="bank.com"

Search for all traffic to and from a specific domain:
(index=web sourcetype=access_logs) OR (index=networking sourcetype=connections) OR (index=networking sourcetype=dns) 
| search uri_domain="bank.com"

Search for all connections to a specific port:
index=networking sourcetype=connections dest_port=80

Search for all traffic to a specific IP address:
index=* sourcetype=access_logs dest_ip="10.0.0.1"

Search for all traffic to and from a specific IP address:
(index=web sourcetype=access_logs) OR (index=networking sourcetype=connections) OR (index=networking sourcetype=dns) 
| search (src_ip="10.0.0.1" OR dest_ip="10.0.0.1")

Search for all changes to system configurations:
index=security sourcetype=system_config_changes

Search for all changes to system configurations made by a specific user:
index=security sourcetype=system_config_changes user="SecnNet"

Search for all traffic from a specific IP address to a specific domain:
index=web sourcetype=access_logs src_ip="192.168.1.1" uri_domain="bank.com"

Search for all traffic from a specific user agent:
index=web sourcetype=access_logs useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

Search for all traffic to a specific user agent:
index=web sourcetype=access_logs useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

Search for all traffic to and from a specific user agent:
(index=web sourcetype=access_logs) OR (index=networking sourcetype=connections) OR (index=networking sourcetype=dns) 
| search useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

Search for all changes to system accounts:
index=security sourcetype=system_account_changes

Search for all changes to system accounts made by a specific user:
index=security sourcetype=system_account_changes user="SecnNet"

Search for all changes to group membership of a specific user:
index=security sourcetype=group_membership_changes user="SecnNet"

Search for all changes to firewall rules that were denied:
index=security sourcetype=firewall_changes action="deny"

Search for all changes to firewall rules that were allowed:
index=security sourcetype=firewall_changes action="allow"

Search for all changes to firewall rules that were made by a specific user:
index=security sourcetype=firewall_changes user="SecnNet"

Search for all changes to system accounts made in the past week:
index=security sourcetype=system_account_changes earliest=-7d@d

Search for all changes to file permissions made in the past week:
index=security sourcetype=file_permissions_changes earliest=-7d@d

Search for all changes to group membership made in the past week:
index=security sourcetype=group_membership_changes earliest=-7d@d

Search for all changes to database permissions made in the past week:
index=security sourcetype=db_permissions_changes earliest=-7d@d

Search for all failed login attempts in the past week:
index=* sourcetype=login_events login_success=false earliest=-7d@d

Search for all successful login attempts in the past week:
index=* sourcetype=login_events login_success=true earliest=-7d@d

Search for all changes to firewall rules in the past week:
index=security sourcetype=firewall_changes earliest=-7d@d

Search for all RDP connections made in the past week:
index=security sourcetype=rdp_logs earliest=-7d@d

Search for all FTP sessions made in the past week:
index=security sourcetype=ftp_logs earliest=-7d@d

Search for all traffic to and from a specific IP address in the past week:
(index=web sourcetype=access_logs) OR (index=networking sourcetype=connections) OR (index=networking sourcetype=dns) earliest=-7d@d 
| search (src_ip="10.0.0.1" OR dest_ip="10.0.0.1")

Search for all changes to user accounts made by a specific admin user:
index=security sourcetype=system_account_changes user=admin_user changed_user=*

Search for all changes to group memberships made in the past 24 hours:
index=security sourcetype=group_membership_changes earliest=-1d@d

Search for all HTTP error status codes:
index=web sourcetype=access_logs status_code>=400

Search for all successful login attempts made in the past 24 hours:
index=* sourcetype=login_events login_success=true earliest=-1d@d

Search for all failed login attempts from a specific IP address:
index=* sourcetype=login_events src_ip=192.168.1.1 login_success=false

Search for all changes to Windows registry keys made in the past week:
index=security sourcetype=registry_changes earliest=-7d@d

Search for all connections to a specific database made in the past 24 hours:
index=database sourcetype=connections earliest=-1d@d db_name="my_database"

Search for all traffic to a specific URL made in the past 24 hours:
index=web sourcetype=access_logs earliest=-1d@d uri="https://www.bank.com"

Search for all changes to DNS settings made in the past week:
index=networking sourcetype=dns_changes earliest=-7d@d

Search for all changes to DHCP settings made in the past week:
index=networking sourcetype=dhcp_changes earliest=-7d@d

Search for all changes to Active Directory made in the past week:
index=security sourcetype=ad_changes earliest=-7d@d

Search for all SSH connections made in the past 24 hours:
index=security sourcetype=ssh_logs earliest=-1d@d

Search for all changes to FTP server configurations made in the past week:
index=security sourcetype=ftp_server_config_changes earliest=-7d@d

Search for all changes to firewall rules made in the past week for a specific source IP address:
index=security sourcetype=firewall_changes earliest=-7d@d src_ip="192.168.1.1"

Search for all changes to firewall rules made in the past week for a specific destination IP address:
index=security sourcetype=firewall_changes earliest=-7d@d dest_ip="10.0.0.1"

Search for all changes to printer configurations made in the past week:
index=security sourcetype=printer_config_changes earliest=-7d@d

Search for all changes to Active Directory group memberships made by a specific user:
index=security sourcetype=ad_group_membership_changes user="SecnNet"

Search for all changes to security policies made in the past week:
index=security sourcetype=security_policy_changes earliest=-7d@d

Search for all traffic from a specific IP address made in the past 24 hours:
index=web sourcetype=access_logs earliest=-1d@d src_ip="192.168.1.1"

Search for all traffic to a specific IP address made in the past 24 hours:
index=web sourcetype=access_logs earliest=-1d@d dest_ip="10.0.0.1"

Search for all changes to server configurations made in the past week:
index=security sourcetype=server_config_changes earliest=-7d@d

Search for all changes to DNS zone configurations made in the past week:
index=networking sourcetype=dns_zone_changes earliest=-7d@d

Search for all changes to DHCP server configurations made in the past week:
index=networking sourcetype=dhcp_server_config_changes earliest=-7d@d

Search for all changes to firewall configurations made in the past week:
index=security sourcetype=firewall_config_changes earliest=-7d@d

Search for all changes to VPN configurations made in the past week:
index=security sourcetype=vpn_config_changes earliest=-7d@d

Search for all traffic from a specific subnet in the past 24 hours:
index=web sourcetype=access_logs earliest=-1d@d src_ip="192.168.1.0/24"

Search for all traffic to a specific subnet in the past 24 hours:
index=web sourcetype=access_logs earliest=-1d@d dest_ip="10.0.0.0/24"

Search for all failed authentication attempts on a specific server in the past 24 hours:
index=security sourcetype=authentication_events earliest=-1d@d host="server01" success=false

Search for all successful authentication attempts by a specific user in the past week:
index=security sourcetype=authentication_events earliest=-7d@d user="SecnNet" success=true

Search for all changes to AWS security group configurations made in the past week:
index=security sourcetype=aws_sg_changes earliest=-7d@d

Search for all changes to Azure Virtual Network configurations made in the past week:
index=security sourcetype=azure_vnet_changes earliest=-7d@d

Search for all changes to Azure Resource Manager configurations made in the past week:
index=security sourcetype=azure_rm_changes earliest=-7d@d

Search for all changes to Azure Active Directory configurations made in the past week:
index=security sourcetype=azure_ad_changes earliest=-7d@d

Search for all changes to Google Cloud Platform configurations made in the past week:
index=security sourcetype=gcp_config_changes earliest=-7d@d

Search for all changes to Kubernetes configurations made in the past week:
index=security sourcetype=kubernetes_config_changes earliest=-7d@d

Search for all changes to Docker configurations made in the past week:
index=security sourcetype=docker_config_changes earliest=-7d@d

Search for all changes to network device configurations made in the past week:
index=networking sourcetype=device_config_changes earliest=-7d@d

Search for all changes to backup configurations made in the past week:
index=security sourcetype=backup_config_changes earliest=-7d@d

Search for all traffic to or from a specific URL in the past 24 hours:
index=web sourcetype=access_logs earliest=-1d@d uri="https://www.bank.com/*"

Search for all changes to antivirus software configurations made in the past week:
index=security sourcetype=av_config_changes earliest=-7d@d

Search for all changes to email server configurations made in the past week:
index=security sourcetype=email_server_config_changes earliest=-7d@d

Search for all changes to file server configurations made in the past week:
index=security sourcetype=file_server_config_changes earliest=-7d@d

Search for all changes to database server configurations made in the past week:
index=security sourcetype=db_server_config_changes earliest=-7d@d

Search for all changes to web server configurations made in the past week:
index=security sourcetype=web_server_config_changes earliest=-7d@d

Search for all changes to load balancer configurations made in the past week:
index=security sourcetype=lb_config_changes earliest=-7d@d

Search for all changes to intrusion detection system (IDS) configurations made in the past week:
index=security sourcetype=ids_config_changes earliest=-7d@d

Search for all changes to intrusion prevention system (IPS) configurations made in the past week:
index=security sourcetype=ips_config_changes earliest=-7d@d

Search for all changes to firewall rule sets made in the past week:
index=security sourcetype=firewall_rule_set_changes earliest=-7d@d

Search for all changes to network switch configurations made in the past week:
index=networking sourcetype=switch_config_changes earliest=-7d@d

Search for all changes to network router configurations made in the past week:
index=networking sourcetype=router_config_changes earliest=-7d@d

Search for all changes to network security group configurations made in the past week:
index=security sourcetype=nsg_config_changes earliest=-7d@d

Search for all changes to network access control list (NACL) configurations made in the past week:
index=networking sourcetype=nacl_config_changes earliest=-7d@d

Search for all changes to virtual private cloud (VPC) configurations made in the past week:
index=security sourcetype=vpc_config_changes earliest=-7d@d

Search for all changes to wireless network configurations made in the past week:
index=security sourcetype=wireless_config_changes earliest=-7d@d

Search for all changes to multi-factor authentication (MFA) configurations made in the past week:
index=security sourcetype=mfa_config_changes earliest=-7d@d

Search for all changes to identity and access management (IAM) configurations made in the past week:
index=security sourcetype=iam_config_changes earliest=-7d@d

Search for all changes to network load balancer (NLB) configurations made in the past week:
index=networking sourcetype=nlb_config_changes earliest=-7d@d

Search for all changes to web application firewall (WAF) configurations made in the past week:
index=security sourcetype=waf_config_changes earliest=-7d@d

Search for all changes to endpoint protection configurations made in the past week:
index=security sourcetype=endpoint_protection_config_changes earliest=-7d@d

Search for all changes to container security configurations made in the past week:
index=security sourcetype=container_security_config_changes earliest=-7d@d

Search for all changes to identity provider (IdP) configurations made in the past week:
index=security sourcetype=idp_config_changes earliest=-7d@d

Search for all changes to firewall policy configurations made in the past week:
index=security sourcetype=firewall_policy_changes earliest=-7d@d

Search for all changes to proxy server configurations made in the past week:
index=security sourcetype=proxy_config_changes earliest=-7d@d

Search for all changes to intrusion detection and prevention system (IDPS) configurations made in the past week:
index=security sourcetype=idps_config_changes earliest=-7d@d

Search for all changes to security information and event management (SIEM) configurations made in the past week:
index=security sourcetype=siem_config_changes earliest=-7d@d

Search for all changes to disaster recovery (DR) configurations made in the past week:
index=security sourcetype=dr_config_changes earliest=-7d@d

Search for all changes to privileged access management (PAM) configurations made in the past week:
index=security sourcetype=pam_config_changes earliest=-7d@d

Search for all changes to software-defined networking (SDN) configurations made in the past week:
index=security sourcetype=sdn_config_changes earliest=-7d@d

Search for all changes to unified threat management (UTM) configurations made in the past week:
index=security sourcetype=utm_config_changes earliest=-7d@d

Search for all changes to data loss prevention (DLP) configurations made in the past week:
index=security sourcetype=dlp_config_changes earliest=-7d@d

Search for all changes to access control system (ACS) configurations made in the past week:
index=security sourcetype=acs_config_changes earliest=-7d@d

Search for all changes to privileged identity management (PIM) configurations made in the past week:
index=security sourcetype=pim_config_changes earliest=-7d@d

Search for all changes to security operations center (SOC) configurations made in the past week:
index=security sourcetype=soc_config_changes earliest=-7d@d

Search for all changes to mobile device management (MDM) configurations made in the past week:
index=security sourcetype=mdm_config_changes earliest=-7d@d

Search for all changes to remote access system configurations made in the past week:
index=security sourcetype=remote_access_config_changes earliest=-7d@d

Search for all changes to security analytics configurations made in the past week:
index=security sourcetype=security_analytics_config_changes earliest=-7d@d

Search for all changes to physical access control system (PACS) configurations made in the past week:
index=security sourcetype=pacs_config_changes earliest=-7d@d

Search for all changes to secure file transfer protocol (SFTP) configurations made in the past week:
index=security sourcetype=sftp_config_changes earliest=-7d@d

Search for all changes to security information management (SIM) configurations made in the past week:
index=security sourcetype=sim_config_changes earliest=-7d@d

Search for all changes to anti-malware configurations made in the past week:
index=security sourcetype=antimalware_config_changes earliest=-7d@d

Search for all changes to network packet capture (PCAP) configurations made in the past week:
index=security sourcetype=pcap_config_changes earliest=-7d@d

Search for all changes to security information governance (SIG) configurations made in the past week:
index=security sourcetype=sig_config_changes earliest=-7d@d

Search for all changes to security data lake (SDL) configurations made in the past week:
index=security sourcetype=sdl_config_changes earliest=-7d@d

Search for all changes to access governance and intelligence (AGI) configurations made in the past week:
index=security sourcetype=agi_config_changes earliest=-7d@d

Search for all changes to unified endpoint management (UEM) configurations made in the past week:
index=security sourcetype=uem_config_changes earliest=-7d@d

Search for all changes to security posture management (SPM) configurations made in the past week:
index=security sourcetype=spm_config_changes earliest=-7d@d

Search for all changes to cloud security configurations made in the past week:
index=security sourcetype=cloud_security_config_changes earliest=-7d@d

Search for all changes to security incident and event management (SIEM) rules made in the past week:
index=security sourcetype=siem_rule_changes earliest=-7d@d

Search for all changes to vulnerability management configurations made in the past week:
index=security sourcetype=vulnerability_management_config_changes earliest=-7d@d

Search for all changes to web content filtering configurations made in the past week:
index=security sourcetype=web_content_filtering_config_changes earliest=-7d@d

Search for all changes to security event management (SEM) configurations made in the past week:
index=security sourcetype=sem_config_changes earliest=-7d@d

Search for all changes to security orchestration, automation and response (SOAR) configurations made in the past week:
index=security sourcetype=soar_config_changes earliest=-7d@d

Search for all changes to digital rights management (DRM) configurations made in the past week:
index=security sourcetype=drm_config_changes earliest=-7d@d

Search for all changes to threat intelligence (TI) configurations made in the past week:
index=security sourcetype=ti_config_changes earliest=-7d@d

Search for all changes to security risk management (SRM) configurations made in the past week:
index=security sourcetype=srm_config_changes earliest=-7d@d

Search for all changes to cloud access security broker (CASB) configurations made in the past week:
index=security sourcetype=casb_config_changes earliest=-7d@d

Search for all changes to security awareness and training (SAT) configurations made in the past week:
index=security sourcetype=sat_config_changes earliest=-7d@d

Search for all changes to security information system (SIS) configurations made in the past week:
index=security sourcetype=sis_config_changes earliest=-7d@d

Search for all changes to security data loss protection (DLP) configurations made in the past week:
index=security sourcetype=dlp_config_changes earliest=-7d@d

Search for all changes to security analytics and intelligence (SAI) configurations made in the past week:
index=security sourcetype=sai_config_changes earliest=-7d@d

Search for all changes to application security (AppSec) configurations made in the past week:
index=security sourcetype=appsec_config_changes earliest=-7d@d

Search for all changes to data governance (DG) configurations made in the past week:
index=security sourcetype=dg_config_changes earliest=-7d@d

Search for all changes to security information sharing and analysis center (ISAC) configurations made in the past week:
index=security sourcetype=isac_config_changes earliest=-7d@d

Search for all changes to security control system (SCS) configurations made in the past week:
index=security sourcetype=scs_config_changes earliest=-7d@d

Search for all changes to security configuration management (SCM) configurations made in the past week:
index=security sourcetype=scm_config_changes earliest=-7d@d

Search for all changes to security content management (SCM) configurations made in the past week:
index=security sourcetype=scm_config_changes earliest=-7d@d

Search for all changes to security data analytics (SDA) configurations made in the past week:
index=security sourcetype=sda_config_changes earliest=-7d@d

Search for all changes to security risk assessment (SRA) configurations made in the past week:
index=security sourcetype=sra_config_changes earliest=-7d@d

Search for all changes to security operations management (SOM) configurations made in the past week:
index=security sourcetype=som_config_changes earliest=-7d@d

Search for all changes to security governance, risk management and compliance (GRC) configurations made in the past week:
index=security sourcetype=grc_config_changes earliest=-7d@d

Search for all changes to security audit and compliance (SAC) configurations made in the past week:
index=security sourcetype=sac_config_changes earliest=-7d@d

Search for all changes to security incident response (SIR) configurations made in the past week:
index=security sourcetype=sir_config_changes earliest=-7d@d

Search for all changes to security user behavior analytics (SUBA) configurations made in the past week:
index=security sourcetype=suba_config_changes earliest=-7d@d

Search for all changes to security threat hunting (STH) configurations made in the past week:
index=security sourcetype=sth_config_changes earliest=-7d@d

Search for all changes to security data visualization (SDV) configurations made in the past week:
index=security sourcetype=sdv_config_changes earliest=-7d@d

Search for all changes to security application performance monitoring (SAPM) configurations made in the past week:
index=security sourcetype=sapm_config_changes earliest=-7d@d

Search for all changes to security data lake management (SDLM) configurations made in the past week:
index=security sourcetype=sdlm_config_changes earliest=-7d@d

Search for all changes to security configuration audit (SCA) configurations made in the past week:
index=security sourcetype=sca_config_changes earliest=-7d@d

Search for all changes to security certificate management (SCM) configurations made in the past week:
index=security sourcetype=scm_config_changes earliest=-7d@d

Search for all changes to security network segmentation (SNS) configurations made in the past week:
index=security sourcetype=sns_config_changes earliest=-7d@d

Search for all changes to security data classification (SDC) configurations made in the past week:
index=security sourcetype=sdn_config_changes earliest=-7d@d

Search for all changes to security access management (SAM) configurations made in the past week:
index=security sourcetype=sam_config_changes earliest=-7d@d

Search for all changes to security encryption management (SEM) configurations made in the past week:
index=security sourcetype=sem_config_changes earliest=-7d@d

Search for all changes to security firewall management (SFM) configurations made in the past week:
index=security sourcetype=sfm_config_changes earliest=-7d@d

Search for all changes to security intrusion detection system (IDS) configurations made in the past week:
index=security sourcetype=ids_config_changes earliest=-7d@d

Search for all changes to security intrusion prevention system (IPS) configurations made in the past week:
index=security sourcetype=ips_config_changes earliest=-7d@d

Search for all changes to security network access control (NAC) configurations made in the past week:
index=security sourcetype=nac_config_changes earliest=-7d@d

Search for all changes to security remote access management (SRAM) configurations made in the past week:
index=security sourcetype=sram_config_changes earliest=-7d@d

Search for all changes to security virtual private network (VPN) configurations made in the past week:
index=security sourcetype=vpn_config_changes earliest=-7d@d

Search for all changes to security web application firewall (WAF) configurations made in the past week:
index=security sourcetype=waf_config_changes earliest=-7d@d

Search for all changes to security perimeter defense (SPD) configurations made in the past week:
index=security sourcetype=spd_config_changes earliest=-7d@d

Search for all changes to security mobile device management (MDM) configurations made in the past week:
index=security sourcetype=mdm_config_changes earliest=-7d@d

Search for all changes to security security information and event management (SIEM) configurations made in the past week:
index=security sourcetype=siem_config_changes earliest=-7d@d

Search for all changes to security network security management (NSM) configurations made in the past week:
index=security sourcetype=nsm_config_changes earliest=-7d@d

Search for all changes to security data security management (DSM) configurations made in the past week:
index=security sourcetype=dsm_config_changes earliest=-7d@d

Search for all changes to security identity and access management (IAM) configurations made in the past week:
index=security sourcetype=iam_config_changes earliest=-7d@d

Search for all changes to security privileged access management (PAM) configurations made in the past week:
index=security sourcetype=pam_config_changes earliest=-7d@d

Search for all changes to security security operations center (SOC) configurations made in the past week:
index=security sourcetype=soc_config_changes earliest=-7d@d

Search for all changes to security vulnerability management (VM) configurations made in the past week:
index=security sourcetype=vm_config_changes earliest=-7d@d

Search for all changes to security security engineering (SE) configurations made in the past week:
index=security sourcetype=se_config_changes earliest=-7d@d

Search for all changes to security user activity monitoring (UAM) configurations made in the past week:
index=security sourcetype=uam_config_changes earliest=-7d@d

Search for all changes to security encryption key management (EKM) configurations made in the past week:
index=security sourcetype=ekm_config_changes earliest=-7d@d

Search for all changes to security incident management (SIM) configurations made in the past week:
index=security sourcetype=sim_config_changes earliest=-7d@d

Search for all changes to security fraud detection (FD) configurations made in the past week:
index=security sourcetype=fd_config_changes earliest=-7d@d

Search for all changes to security threat intelligence (TI) configurations made in the past week:
index=security sourcetype=ti_config_changes earliest=-7d@d

Search for all changes to security asset management (SAM) configurations made in the past week:
index=security sourcetype=sam_config_changes earliest=-7d@d

Search for all changes to security security orchestration, automation and response (SOAR) configurations made in the past week:
index=security sourcetype=soar_config_changes earliest=-7d@d

Search for all changes to security deception technology (DT) configurations made in the past week:
index=security sourcetype=dt_config_changes earliest=-7d@d

Search for all changes to security compliance management (CM) configurations made in the past week:
index=security sourcetype=cm_config_changes earliest=-7d@d

Search for all changes to security security analytics (SA) configurations made in the past week:
index=security sourcetype=sa_config_changes earliest=-7d@d

Search for all changes to security identity governance and administration (IGA) configurations made in the past week:
index=security sourcetype=iga_config_changes earliest=-7d@d

Search for all changes to security network traffic analysis (NTA) configurations made in the past week:
index=security sourcetype=nta_config_changes earliest=-7d@d

Search for all changes to security cloud security (CS) configurations made in the past week:
index=security sourcetype=cs_config_changes earliest=-7d@d

Search for all changes to security threat detection (TD) configurations made in the past week:
index=security sourcetype=td_config_changes earliest=-7d@d

Search for all changes to security data loss prevention (DLP) configurations made in the past week:
index=security sourcetype=dlp_config_changes earliest=-7d@d

Search for all changes to security network segmentation and microsegmentation (NSMS) configurations made in the past week:
index=security sourcetype=nsms_config_changes earliest=-7d@d

Search for all changes to security network detection and response (NDR) configurations made in the past week:
index=security sourcetype=ndr_config_changes earliest=-7d@d

Search for all changes to security incident response automation and orchestration (IRAO) configurations made in the past week:
index=security sourcetype=irao_config_changes earliest=-7d@d

Search for all changes to security governance, risk management and compliance (GRC) configurations made in the past week:
index=security sourcetype=grc_config_changes earliest=-7d@d

Search for all changes to security security information management (SIM) configurations made in the past week:
index=security sourcetype=sim_config_changes earliest=-7d@d

Search for all changes to security security operations (SecOps) configurations made in the past week:
index=security sourcetype=secops_config_changes earliest=-7d@d

Search for all changes to security supply chain security (SCS) configurations made in the past week:
index=security sourcetype=scs_config_changes earliest=-7d@d

Search for all changes to security network security (NS) configurations made in the past week:
index=security sourcetype=ns_config_changes earliest=-7d@d

Search for all changes to security data protection (DP) configurations made in the past week:
index=security sourcetype=dp_config_changes earliest=-7d@d

Search for all changes to security cloud access security brokers (CASB) configurations made in the past week:
index=security sourcetype=casb_config_changes earliest=-7d@d

Search for all changes to security security ratings services (SRS) configurations made in the past week:
index=security sourcetype=srs_config_changes earliest=-7d@d

Search for all changes to security security training and awareness (STA) configurations made in the past week:
index=security sourcetype=sta_config_changes earliest=-7d@d

Search for all changes to security security automation (SA) configurations made in the past week:
index=security sourcetype=sa_config_changes earliest=-7d@d

Search for all changes to security artificial intelligence (AI) and machine learning (ML) configurations made in the past week:
index=security sourcetype=ai_ml_config_changes earliest=-7d@d

Search for all changes to security zero trust (ZT) configurations made in the past week:
index=security sourcetype=zt_config_changes earliest=-7d@d

Search for all changes to security security culture and behavior (SCB) configurations made in the past week:
index=security sourcetype=scb_config_changes earliest=-7d@d

Search for all changes to security blockchain security (BS) configurations made in the past week:
index=security sourcetype=bs_config_changes earliest=-7d@d

Search for all changes to security threat hunting (TH) configurations made in the past week:
index=security sourcetype=th_config_changes earliest=-7d@d

Search for all changes to security critical infrastructure protection (CIP) configurations made in the past week:
index=security sourcetype=cip_config_changes earliest=-7d@d

Search for all changes to security internet of things (IoT) security configurations made in the past week:
index=security sourcetype=iot_config_changes earliest=-7d@d

Search for all changes to security operational technology (OT) security configurations made in the past week:
index=security sourcetype=ot_config_changes earliest=-7d@d

Search for all changes to security threat and vulnerability management (TVM) configurations made in the past week:
index=security sourcetype=tvm_config_changes earliest=-7d@d

Search for all changes to security industrial control systems (ICS) security configurations made in the past week:
index=security sourcetype=ics_config_changes earliest=-7d@d

Search for all changes to security penetration testing (PT) configurations made in the past week:
index=security sourcetype=pt_config_changes earliest=-7d@d

Search for all changes to security physical security (PS) configurations made in the past week:
index=security sourcetype=ps_config_changes earliest=-7d@d

Search for all changes to security container security (CS) configurations made in the past week:
index=security sourcetype=cs_config_changes earliest=-7d@d

Search for all changes to security application security (AS) configurations made in the past week:
index=security sourcetype=as_config_changes earliest=-7d@d

Search for all changes to security endpoint security (ES) configurations made in the past week:
index=security sourcetype=es_config_changes earliest=-7d@d

Search for all changes to security software defined perimeter (SDP) configurations made in the past week:
index=security sourcetype=sdp_config_changes earliest=-7d@d

Search for all changes to security security information and event management (SIEM) configurations made in the past week:
index=security sourcetype=siem_config_changes earliest=-7d@d

Search for all changes to security disaster recovery (DR) configurations made in the past week:
index=security sourcetype=dr_config_changes earliest=-7d@d

Search for all changes to security secure access service edge (SASE) configurations made in the past week:
index=security sourcetype=sase_config_changes earliest=-7d@d

Search for all changes to security privileged access management (PAM) configurations made in the past week:
index=security sourcetype=pam_config_changes earliest=-7d@d

Search for all changes to security user and entity behavior analytics (UEBA) configurations made in the past week:
index=security sourcetype=ueba_config_changes earliest=-7d@d

Search for all changes to security cyber threat intelligence (CTI) configurations made in the past week:
index=security sourcetype=cti_config_changes earliest=-7d@d

Search for all changes to security identity and access management (IAM) configurations made in the past week:
index=security sourcetype=iam_config_changes earliest=-7d@d

Search for all changes to security data security (DS) configurations made in the past week:
index=security sourcetype=ds_config_changes earliest=-7d@d

Search for all changes to security email security (ES) configurations made in the past week:
index=security sourcetype=es_config_changes earliest=-7d@d

Search for all changes to security web application firewall (WAF) configurations made in the past week:
index=security sourcetype=waf_config_changes earliest=-7d@d

Search for all changes to security encryption and key management (EKM) configurations made in the past week:
index=security sourcetype=ekm_config_changes earliest=-7d@d

Search for all changes to security next generation firewalls (NGFW) configurations made in the past week:
index=security sourcetype=ngfw_config_changes earliest=-7d@d

Search for all changes to security security incident and event management (SIEM) configurations made in the past week:
index=security sourcetype=siem_config_changes earliest=-7d@d

Search for all changes to security multi-factor authentication (MFA) configurations made in the past week:
index=security sourcetype=mfa_config_changes earliest=-7d@d

Search for all changes to security wireless security (WS) configurations made in the past week:
index=security sourcetype=ws_config_changes earliest=-7d@d

Search for all changes to security network access control (NAC) configurations made in the past week:
index=security sourcetype=nac_config_changes earliest=-7d@d

Search for all changes to security virtual private networks (VPN) configurations made in the past week:
index=security sourcetype=vpn_config_changes earliest=-7d@d

Search for all changes to security access control (AC) configurations made in the past week:
index=security sourcetype=ac_config_changes earliest=-7d@d

Search for all changes to security perimeter security (PS) configurations made in the past week:
index=security sourcetype=ps_config_changes earliest=-7d@d

Search for all changes to security security orchestration and automation (SOA) configurations made in the past week:
index=security sourcetype=soa_config_changes earliest=-7d@d

Search for all changes to security security analytics and intelligence (SAI) configurations made in the past week:
index=security sourcetype=sai_config_changes earliest=-7d@d

Search for all changes to security network segmentation (NS) configurations made in the past week:
index=security sourcetype=ns_config_changes earliest=-7d@d

Search for all changes to security web security (WS) configurations made in the past week:
index=security sourcetype=ws_config_changes earliest=-7d@d

Search for all changes to security cloud security (CS) configurations made in the past week:
index=security sourcetype=cs_config_changes earliest=-7d@d

Search for all changes to security security controls (SC) configurations made in the past week:
index=security sourcetype=sc_config_changes earliest=-7d@d

Search for all changes to security security architecture (SA) configurations made in the past week:
index=security sourcetype=sa_config_changes earliest=-7d@d

Search for all changes to security security operations center (SOC) configurations made in the past week:
index=security sourcetype=soc_config_changes earliest=-7d@d

Search for all changes to security network security (NS) configurations made in the past week:
index=security sourcetype=ns_config_changes earliest=-7d@d

Search for all changes to security firewall (FW) configurations made in the past week:
index=security sourcetype=fw_config_changes earliest=-7d@d

Search for all changes to security security monitoring (SM) configurations made in the past week:
index=security sourcetype=sm_config_changes earliest=-7d@d

Search for all changes to security security governance (SG) configurations made in the past week:
index=security sourcetype=sg_config_changes earliest=-7d@d

Search for all changes to security log management (LM) configurations made in the past week:
index=security sourcetype=lm_config_changes earliest=-7d@d

Search for all changes to security data loss prevention (DLP) configurations made in the past week:
index=security sourcetype=dlp_config_changes earliest=-7d@d

Search for all changes to security security risk management (SRM) configurations made in the past week:
index=security sourcetype=srm_config_changes earliest=-7d@d

Search for all changes to security security awareness training (SAT) configurations made in the past week:
index=security sourcetype=sat_config_changes earliest=-7d@d

Search for all changes to security cloud access security broker (CASB) configurations made in the past week:
index=security sourcetype=casb_config_changes earliest=-7d@d

Search for all changes to security privileged access management (PAM) configurations made in the past week:
index=security sourcetype=pam_config_changes earliest=-7d@d

Search for all changes to security intrusion detection and prevention (IDP) configurations made in the past week:
index=security sourcetype=idp_config_changes earliest=-7d@d

Search for all changes to security security assessments (SA) configurations made in the past week:
index=security sourcetype=sa_config_changes earliest=-7d@d

Search for all changes to security security information and event management (SIEM) configurations made in the past week:
index=security sourcetype=siem_config_changes earliest=-7d@d

Search for all changes to security threat intelligence (TI) configurations made in the past week:
index=security sourcetype=ti_config_changes earliest=-7d@d

Search for all changes to security anti-virus (AV) configurations made in the past week:
index=security sourcetype=av_config_changes earliest=-7d@d

Search for all changes to security endpoint detection and response (EDR) configurations made in the past week:
index=security sourcetype=edr_config_changes earliest=-7d@d

Search for all changes to security vulnerability management (VM) configurations made in the past week:
index=security sourcetype=vm_config_changes earliest=-7d@d

Search for all changes to security incident response (IR) configurations made in the past week:
index=security sourcetype=ir_config_changes earliest=-7d@d

Search for all changes to security network segmentation (NS) configurations made in the past week:
index=security sourcetype=ns_config_changes earliest=-7d@d

Search for all changes to security multi-factor authentication (MFA) configurations made in the past week:
index=security sourcetype=mfa_config_changes earliest=-7d@d

Search for all changes to security identity and access management (IAM) configurations made in the past week:
index=security sourcetype=iam_config_changes earliest=-7d@d

Search for all changes to security unified threat management (UTM) configurations made in the past week:
index=security sourcetype=utm_config_changes earliest=-7d@d

Search for all changes to security penetration testing (PT) configurations made in the past week:
index=security sourcetype=pt_config_changes earliest=-7d@d

Search for all changes to security disaster recovery (DR) configurations made in the past week:
index=security sourcetype=dr_config_changes earliest=-7d@d

Search for all changes to security network traffic analysis (NTA) configurations made in the past week:
index=security sourcetype=nta_config_changes earliest=-7d@d

Search for all changes to security mobile device management (MDM) configurations made in the past week:
index=security sourcetype=mdm_config_changes earliest=-7d@d

Search for all changes to security security awareness training (SAT) configurations made in the past week:
index=security sourcetype=sat_config_changes earliest=-7d@d

Search for all changes to security security architecture (SA) configurations made in the past week:
index=security sourcetype=sa_config_changes earliest=-7d@d

Search for all changes to security security orchestration, automation and response (SOAR) configurations made in the past week:
index=security sourcetype=soar_config_changes earliest=-7d@d

Search for all login attempts made to the bank's online banking system from IP addresses outside the country in the past 24 hours:
index=security sourcetype=online_banking_logs earliest=-24h 
| search login_attempt="*" AND src_ip!="*.*.*.*" AND src_ip!="*.**.*.*" AND src_ip!="*.*.**.*" AND src_ip!="*.*.*.**" AND NOT src_ip IN ("country_ip_range") 

Search for all failed login attempts made to the bank's online banking system with invalid usernames in the past week:
index=security sourcetype=online_banking_logs earliest=-7d
| search login_attempt="*" AND login_success="false" AND NOT username IN ("list_of_valid_usernames")

Search for all successful login attempts made to the bank's online banking system from new devices in the past day:
index=security sourcetype=online_banking_logs earliest=-1d
| stats count by src_ip, user_agent
| where count=1

Search for all changes made to the bank's privileged user account permissions in the past week:
index=security sourcetype=pam_config_changes earliest=-7d
| search action="edit" AND account_type="privileged"

Search for all changes made to the bank's system and application configurations in the past week:
index=security sourcetype=sys_config_changes OR sourcetype=app_config_changes earliest=-7d

Search for all changes made to the bank's access control lists (ACLs) in the past week:
index=security sourcetype=acl_config_changes earliest=-7d
| search action="edit"

Search for all file deletions made on the bank's file server in the past day:
index=security sourcetype=file_server_logs earliest=-1d
| search action="delete"

Search for all network traffic to known malicious IP addresses in the past week:
index=security sourcetype=network_logs earliest=-7d
| search dest_ip IN ("list_of_known_malicious_IP_addresses")

Search for all system logons made outside of normal business hours in the past week:
index=security sourcetype=system_logs earliest=-7d
| search logon="*" AND NOT time>=9:00 AND NOT time<=17:00

Search for all database query failures made to the bank's database server in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search query_success="false"
As always, make sure to customize the search queries based on the specific security needs and requirements of the bank and its stakeholders.

Search for all failed login attempts made to the bank's internal network from outside the company's IP address range in the past day:
index=security sourcetype=network_logs earliest=-1d
| search login_attempt="*" AND NOT src_ip IN ("company_ip_range")

Search for all changes made to the bank's firewall configurations in the past week:
index=security sourcetype=firewall_config_changes earliest=-7d

Search for all successful login attempts made to the bank's internal network from unauthorized devices in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address
| where count=1

Search for all failed attempts to access sensitive data on the bank's file server in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| search action="access" AND NOT file_path IN ("path_to_sensitive_data") AND access_success="false"

Search for all successful attempts to access sensitive data on the bank's file server by unauthorized users in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| search action="access" AND file_path IN ("path_to_sensitive_data") AND NOT username IN ("list_of_authorized_users")

Search for all attempts to access the bank's database server from unauthorized locations in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search NOT src_ip IN ("list_of_authorized_IP_addresses")

Search for all attempts to access the bank's database server with invalid credentials in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search query_success="false" AND NOT username IN ("list_of_valid_usernames")

Search for all changes made to the bank's identity and access management (IAM) system configurations in the past week:
index=security sourcetype=iam_config_changes earliest=-7d

Search for all changes made to the bank's multi-factor authentication (MFA) configurations in the past week:
index=security sourcetype=mfa_config_changes earliest=-7d

Search for all changes made to the bank's security architecture (SA) configurations in the past week:
index=security sourcetype=sa_config_changes earliest=-7d

Search for all attempts to access the bank's web applications with invalid parameters in the past week:
index=security sourcetype=web_logs earliest=-7d
| search NOT http_status_code=200 AND NOT http_status_code=404

Search for all changes made to the bank's anti-virus configurations in the past week:
index=security sourcetype=av_config_changes earliest=-7d

Search for all changes made to the bank's intrusion detection system (IDS) configurations in the past week:
index=security sourcetype=ids_config_changes earliest=-7d

Search for all successful attempts to access the bank's database server with admin credentials from outside the company's IP address range in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search query_success="true" AND username="admin" AND NOT src_ip IN ("company_ip_range")

Search for all attempts to access the bank's internal network from known malicious IP addresses in the past week:
index=security sourcetype=network_logs earliest=-7d
| search NOT src_ip IN ("list_of_known_malicious_IP_addresses")

Search for all successful attempts to access sensitive data on the bank's file server from unauthorized devices in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| stats count by src_ip, mac_address, file_path
| where count=1 AND file_path IN ("path_to_sensitive_data")

Search for all changes made to the bank's vulnerability scanning configurations in the past week:
index=security sourcetype=vuln_scan_config_changes earliest=-7d

Search for all changes made to the bank's security incident and event management (SIEM) system configurations in the past week:
index=security sourcetype=siem_config_changes earliest=-7d

Search for all failed attempts to access the bank's database server with admin credentials in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search query_success="false" AND username="admin"

Search for all attempts to access the bank's internal network from unauthorized devices with suspicious MAC addresses in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses")
As always, customize the search queries based on the specific security needs and requirements of the bank and its stakeholders.

Search for all attempts to access the bank's internal network from unauthorized devices with suspicious hostnames in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, hostname
| where count=1 AND NOT hostname IN ("list_of_authorized_hostnames")

Search for all changes made to the bank's security policy configurations in the past week:
index=security sourcetype=security_policy_config_changes earliest=-7d

Search for all failed attempts to access the bank's web applications in the past week:
index=security sourcetype=web_logs earliest=-7d
| search http_status_code=401 OR http_status_code=403

Search for all attempts to access the bank's database server with invalid  queries in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search query_success="false" AND query_type=""

Search for all successful attempts to access the bank's internal network from unauthorized devices with administrative privileges in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address, username
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND username="admin"

Search for all attempts to download suspicious files from the bank's file server in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| search action="download" AND file_extension="exe" OR file_extension="bat" OR file_extension="dll"

Search for all changes made to the bank's data loss prevention (DLP) configurations in the past week:
index=security sourcetype=dlp_config_changes earliest=-7d

Search for all changes made to the bank's access control list (ACL) configurations in the past week:
index=security sourcetype=acl_config_changes earliest=-7d

Search for all successful attempts to access the bank's web applications from known malicious IP addresses in the past week:
index=security sourcetype=web_logs earliest=-7d
| search http_status_code=200 AND src_ip IN ("list_of_known_malicious_IP_addresses")

Search for all changes made to the bank's threat intelligence configurations in the past week:
index=security sourcetype=threat_intelligence_config_changes earliest=-7d

Search for all changes made to the bank's multi-factor authentication (MFA) configurations in the past week:
index=security sourcetype=mfa_config_changes earliest=-7d

Search for all successful attempts to access the bank's internal network from unauthorized devices with remote desktop protocol (RDP) enabled in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address, rdp_enabled
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND rdp_enabled="true"

Search for all attempts to access the bank's web applications with known web application attack signatures in the past week:
index=security sourcetype=web_logs earliest=-7d
| search signature="web_application_attack"

Search for all attempts to access the bank's database server with invalid credentials in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| search query_success="false" AND NOT username="admin" AND NOT username="root"

Search for all successful attempts to access sensitive data on the bank's file server from unauthorized devices with administrative privileges in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| stats count by src_ip, mac_address, username, file_path
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND username="admin" AND file_path IN ("path_to_sensitive_data")

Search for all changes made to the bank's firewall configurations in the past week:
index=security sourcetype=firewall_config_changes earliest=-7d

Search for all changes made to the bank's network segmentation configurations in the past week:
index=security sourcetype=network_segmentation_config_changes earliest=-7d

Search for all successful attempts to access the bank's web applications with suspicious user agent strings in the past week:
index=security sourcetype=web_logs earliest=-7d
| search http_status_code=200 AND user_agent IN ("list_of_suspicious_user_agent_strings")

Search for all attempts to access the bank's internal network from unauthorized devices with suspicious user agent strings in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, user_agent
| where count=1 AND NOT user_agent IN ("list_of_authorized_user_agent_strings")

Search for all successful attempts to access the bank's database server from authorized devices outside of normal working hours in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| stats count by src_ip, mac_address, username
| where count=1 AND mac_address IN ("list_of_authorized_MAC_addresses") AND NOT day_of_week="Monday" AND NOT day_of_week="Tuesday" AND NOT day_of_week="Wednesday" AND NOT day_of_week="Thursday" AND NOT day_of_week="Friday" AND NOT hour_of_day>17 AND NOT hour_of_day<8

Search for all successful attempts to access the bank's web applications from unauthorized locations in the past week:
index=security sourcetype=web_logs earliest=-7d
| stats count by src_ip, geo_location
| where count=1 AND NOT geo_location IN ("list_of_authorized_locations")

Search for all attempts to access the bank's internal network from unauthorized devices with expired certificates in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, certificate_expiry_date
| where count=1 AND certificate_expiry_date < now()

Search for all changes made to the bank's intrusion detection system (IDS) configurations in the past week:
index=security sourcetype=ids_config_changes earliest=-7d

Search for all successful attempts to access the bank's internal network from unauthorized devices with spoofed MAC addresses in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses")

Search for all attempts to access the bank's web applications with invalid or malformed cookies in the past week:
index=security sourcetype=web_logs earliest=-7d
| search http_status_code=401 AND cookie="*Invalid*" OR cookie="*Malformed*"

Search for all successful attempts to access the bank's database server from unauthorized devices with administrative privileges in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| stats count by src_ip, mac_address, username
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND username="admin"

Search for all attempts to access the bank's internal network from unauthorized devices with spoofed IP addresses in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, src_mac_address
| where count=1 AND NOT src_mac_address IN ("list_of_authorized_MAC_addresses") AND src_ip="*"

Search for all changes made to the bank's endpoint detection and response (EDR) configurations in the past week:
index=security sourcetype=edr_config_changes earliest=-7d

Search for all successful attempts to access sensitive data on the bank's file server from unauthorized devices with non-standard file transfer protocols in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| stats count by src_ip, mac_address, file_path, file_transfer_protocol
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND file_path IN ("path_to_sensitive_data") AND NOT file_transfer_protocol="sftp" AND NOT file_transfer_protocol="scp"

Search for all attempts to access the bank's web applications with suspicious referrer headers in the past week:
index=security sourcetype=web_logs earliest=-7d
| search http_status_code=401 AND referrer IN ("list_of_suspicious_referrer_headers")

Search for all successful attempts to access the bank's internal network from unauthorized devices with known malware infections in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address, malware_signature
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND malware_signature="*known_malware*"

Search for all attempts to access the bank's web applications with known phishing attack signatures in the past week:
index=security sourcetype=web_logs earliest=-7d
| search signature="phishing_attack"

Search for all successful attempts to access the bank's internal network from unauthorized devices with known vulnerability exploits in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address, vulnerability_exploit_signature
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND vulnerability_exploit_signature="*known_vulnerability*"

Search for all changes made to the bank's security information and event management (SIEM) configurations in the past week:
index=security sourcetype=siem_config_changes earliest=-7d

Search for all successful attempts to access sensitive data on the bank's file server from unauthorized devices with non-standard file transfer protocols and suspicious user agent strings in the past week:
index=security sourcetype=file_server_logs earliest=-7d
| stats count by src_ip, mac_address, file_path, file_transfer_protocol, user_agent
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND file_path IN ("path_to_sensitive_data") AND NOT file_transfer_protocol="sftp" AND NOT file_transfer_protocol="scp" AND user_agent IN ("list_of_suspicious_user_agent_strings")

Search for all attempts to access the bank's web applications with invalid or malformed HTTP headers in the past week:
index=security sourcetype=web_logs earliest=-7d
| search http_status_code=401 AND NOT http_user_agent="*"

Search for all successful attempts to access the bank's database server from unauthorized devices with known  injection attacks in the past week:
index=security sourcetype=db_server_logs earliest=-7d
| stats count by src_ip, mac_address, _injection_signature
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND _injection_signature="*known__injection*"

Search for all attempts to access the bank's internal network from unauthorized devices with known Trojan horse malware in the past week:
index=security sourcetype=network_logs earliest=-7d
| stats count by src_ip, mac_address, trojan_horse_signature
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND trojan_horse_signature="*known_Trojan_horse_malware*"

Search for all successful attempts to access the bank's web applications from unauthorized devices with known cross-site scripting (XSS) attacks in the past week:
index=security sourcetype=web_logs earliest=-7d
| stats count by src_ip, mac_address, xss_attack_signature
| where count=1 AND NOT mac_address IN ("list_of_authorized_MAC_addresses") AND xss_attack_signature="*known_XSS_attack*"
