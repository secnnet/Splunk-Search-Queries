Troubleshooting search performance:
index=_internal sourcetype=splunkd component=SearchEvaluator | stats avg(evalDuration) by search_id | sort - avg(evalDuration)

Identifying slow searches:
index=_internal sourcetype=splunkd component=SearchPerformance search_id=* | stats max(total_run_time) as MaxRunTime by search_id | sort - MaxRunTime | head 10

Troubleshooting indexers:
index=_internal sourcetype=splunkd component=TailingProcessor | stats count by host, source, sourcetype

Troubleshooting forwarders:
index=_internal sourcetype=splunkd component=Forwarder host=* | stats count by host, source, sourcetype

Troubleshooting license usage:
index=_internal sourcetype=splunkd component=LicenseUsage | timechart sum(b) as volume by pool

Troubleshooting login failures:
index=_internal sourcetype=audittrail action=failure | stats count by user, action, info

Monitoring resource usage by Splunk processes:
index=_introspection sourcetype=resource_usage data.processType=* | stats avg(data.pctCPU) as AvgCPU, avg(data.pctMemory) as AvgMemory by data.processType | sort - AvgCPU, -AvgMemory

Troubleshooting data input errors:
index=_internal sourcetype=splunkd component=ExecProcessor log_level=ERROR | stats count by log_level, message

Identifying failed searches:
index=_audit action=search status=failure | stats count by user, search, reason | sort - count

Monitoring concurrent searches:
index=_internal sourcetype=scheduler status=success | timechart count by user









