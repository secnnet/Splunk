# 1. Top Sources by Event Volume
| top source
# Lists all log sources and ranks them by total event count. Helps identify noisy data sources.

# 2. Failed SSH Logins
index=linux sourcetype=secure "Failed password"
# Detects failed SSH login attempts for security auditing.

# 3. High CPU Utilization
index=perf sourcetype=cpu usage>90
# Finds servers with CPU usage exceeding 90% for performance troubleshooting.

# 4. Web Server Errors (5xx)
sourcetype=access_* status>=500
# Identifies server-side HTTP errors (5xx) in web applications.

# 5. Newly Deployed Hosts
| metadata type=hosts | eval firstSeen=relative_time(now(), "-7d@d")
# Lists hosts first seen in the last 7 days for change tracking.

# 6. Brute-Force Attack Detection
sourcetype=firewall action=denied | stats count by src_ip | where count > 50
# Flags IPs with >50 denied firewall events (possible brute-force attacks).

# 7. File Change Monitoring
sourcetype=audittrail file_path="/etc/*" action=modified
# Tracks modifications to critical system files (e.g., /etc directory).

# 8. Application Exception Stack Traces
sourcetype=app_logs "Exception" OR "Error"
# Finds application errors/exceptions in logs for debugging.

# 9. Bandwidth Top Talkers
sourcetype=netflow | top 10 src_ip by bytes
# Shows top 10 IPs consuming the most network bandwidth.

# 10. User Account Lockouts
sourcetype=WinEventLog EventCode=4740
# Windows event: detects active directory account lockouts.

# 11. Database Slow Queries
sourcetype=db_logs query_duration>5s
# Identifies database queries taking longer than 5 seconds.

# 12. Critical System Alerts
sourcetype=syslog severity="critical" OR "emerg"
# Filters syslog for highest-severity messages.

# 13. AWS S3 Bucket Access
sourcetype=aws:cloudtrail eventName=GetObject | bucket _time span=1h
# Audits hourly access patterns to AWS S3 objects.

# 14. Memory Leak Detection
sourcetype=perf metric=memory_usage | timechart avg(usage) by host
# Charts memory usage trends to identify potential leaks.

# 15. Phishing Email Detection
sourcetype=mail_logs "phish" OR "malware" OR "suspicious"
# Scans email logs for security threats.

# 16. API Endpoint Latency
sourcetype=api_logs | stats avg(latency) by endpoint
# Calculates average latency per API endpoint.

# 17. Windows Process Execution
sourcetype=WinEventLog EventCode=4688
# Audits new process creation on Windows systems.

# 18. Login Success/Failure Ratio
sourcetype=auth_logs | eval result=if(action="success","Success","Failure") | stats count by result
# Computes authentication success vs. failure rates.

# 19. IIS Slow Page Loads
sourcetype=IIS time_taken>3000
# Finds web pages taking >3 seconds to load in IIS logs.

# 20. Container Restarts
sourcetype=docker "Container started" OR "Container stopped"
# Monitors container lifecycle events in Docker environments.

# 21. DNS Query Failures
sourcetype=dns response_code=NXDOMAIN
# Identifies failed DNS lookups (useful for troubleshooting).

# 22. GCP Bucket Changes
sourcetype=gcp:audit resource.type="gcs_bucket"
# Tracks modifications to Google Cloud Storage buckets.

# 23. Sysmon File Creation
sourcetype=sysmon EventID=11 | search target_filename="*.exe"
# Detects new .exe files created via Sysmon monitoring.

# 24. VPN Connection Trends
sourcetype=vpn | timechart count by user
# Visualizes VPN usage patterns over time.

# 25. Java OutOfMemory Errors
sourcetype=java_logs "OutOfMemoryError"
# Flags JVM memory exhaustion errors in Java applications.

# 26. Azure AD Sign-Ins
sourcetype=azure:audit operationName="Sign-in activity"
# Reviews Azure Active Directory authentication events.

# 27. Apache Top URIs
sourcetype=access_* | top 10 uri
# Lists most frequently accessed URIs in Apache logs.

# 28. Certificate Expiry
sourcetype=ssl_logs "expir" | table cert_name, expiry_date
# Tracks SSL/TLS certificate expiration dates.

# 29. Kubernetes Pod Crashes
sourcetype=kube:pod "CrashLoopBackOff"
# Detects Kubernetes pods in crash-loop state.

# 30. Antivirus Detections
sourcetype=av_logs signature=*
| stats count by signature, host
# Aggregates malware detections by signature and host.

# 31. Network Port Scans
sourcetype=ids | stats dc(dest_port) by src_ip | where dc>50
# Identifies port scans (IPs probing >50 unique ports).

# 32. Salesforce Apex Errors
sourcetype=sfdc:apex "FATAL_ERROR"
# Monitors critical errors in Salesforce Apex code.

# 33. RDP Session Logons
sourcetype=WinEventLog EventCode=4624 LogonType=10
# Tracks Remote Desktop Protocol (RDP) sessions on Windows.

# 34. Nginx 404 Errors
sourcetype=nginx status=404 | top 10 url
# Lists top missing URLs (404s) in Nginx logs.

# 35. AWS EC2 Instance State
sourcetype=aws:ec2 | stats count by instance_state
# Summarizes EC2 instances by running/stopped state.