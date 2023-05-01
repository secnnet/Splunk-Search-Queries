Troubleshooting search performance:
index=_internal sourcetype=splunkd component=SearchEvator
| stats avg(evalDuration) by search_id
| sort - avg(evalDuration)

Identifying slow searches:
index=_internal sourcetype=splunkd component=SearchPerformance search_id=*
| stats max(total_run_time) as MaxRunTime by search_id
| sort - MaxRunTime
| head 10

Troubleshooting indexers:
index=_internal sourcetype=splunkd component=TailingProcessor
| stats count by host, source, sourcetype

Troubleshooting forwarders:
index=_internal sourcetype=splunkd component=Forwarder host=*
| stats count by host, source, sourcetype

Troubleshooting license usage:
index=_internal sourcetype=splunkd component=LicenseUsage
| timechart sum(b) as volume by pool

Troubleshooting login failures:
index=_internal sourcetype=audittrail action=failure
| stats count by user, action, info

Monitoring resource usage by Splunk processes:
index=_introspection sourcetype=resource_usage data.processType=*
| stats avg(data.pctCPU) as AvgCPU, avg(data.pctMemory) as AvgMemory by data.processType
| sort - AvgCPU, -AvgMemory

Troubleshooting data input errors:
index=_internal sourcetype=splunkd component=ExecProcessor log_level=ERROR
| stats count by log_level, message

Identifying failed searches:
index=_audit action=search status=failure
| stats count by user, search, reason
| sort - count

Monitoring concurrent searches:
index=_internal sourcetype=scheduler status=success
| timechart count by user

Identifying indexing delays:
index=_internal sourcetype=splunkd component=TailingProcessor
| eval delay=(_indextime - _time)
| stats avg(delay) as AvgDelay, max(delay) as MaxDelay, min(delay) as MinDelay by source, sourcetype
| sort - AvgDelay

Monitoring search concurrency per user:
index=_audit action=search
| stats count by user, search_id
| sort - count

Troubleshooting search errors:
index=_internal sourcetype=splunkd component=SearchMessages log_level=ERROR
| stats count by log_level, message

Investigating missing data:
| tstats count where index=* by index, sourcetype
| sort - count

Identifying high disk usage by index:
| dbinspect index=*
| stats sum(sizeOnDiskMB) as totalSize by index
| sort - totalSize

Monitoring Splunk Web access:
index=_internal sourcetype=access_combined
| stats count by uri_path, status, user
| sort - count

Finding errors in index configuration:
index=_internal sourcetype=splunkd component=Indexes
| search log_level=ERROR
| stats count by log_level, message

Analyzing search head clustering activity:
index=_internal sourcetype=splunkd_search_head_cluster
| stats count by action, log_level

Identifying searches with high memory usage:
index=_internal sourcetype=splunk_resource_usage data.search_props.sid=*
| stats max(data.search_props.mem_used_mb) as MaxMemUsed by data.search_props.sid
| sort - MaxMemUsed
| head 10

Monitoring distributed search errors:
index=_internal sourcetype=distsearch component=DistSched log_level=ERROR
| stats count by log_level, message

Identifying skipped searches due to search concurrency limit:
index=_internal sourcetype=scheduler status=skipped
| stats count by app, user, search

Monitoring data ingestion rate:
index=_internal source=*/metrics.log* group=pipeline
| timechart span=1h sum(eval(eps*.001)) as IngestionRate

Finding searches with high disk usage:
index=_internal sourcetype=splunk_resource_usage data.search_props.sid=*
| stats max(data.search_props.disk_used_mb) as MaxDiskUsed by data.search_props.sid
| sort - MaxDiskUsed
| head 10

Investigating search head pooling activity:
index=_internal sourcetype=splunkd_shpooling
| stats count by log_level, message

Monitoring deployment server activity:
index=_internal sourcetype=splunkd_deploy_server
| stats count by log_level, message

Troubleshooting KV Store issues:
index=_internal sourcetype=splunkd component=kvstore log_level=ERROR
| stats count by log_level, message

Identifying top event types:
index=*
| stats count by eventtype
| sort - count

Analyzing indexer clustering activity:
index=_internal sourcetype=splunkd_indexer_cluster
| stats count by action, log_level

Monitoring search head cluster captain activity:
index=_internal sourcetype=splunkd_search_head_cluster component=SHCCaptain
| stats count by log_level, message

Identifying throttled searches:
index=_internal sourcetype=scheduler status=throttled
| stats count by app, user, search

Investigating bundle replication issues in search head cluster:
index=_internal sourcetype=splunkd_shcluster_replication
| stats count by log_level, message

Monitoring indexer cluster peer activity:
index=_internal sourcetype=splunkd_indexer_cluster component=IndexerClusterPeer
| stats count by log_level, message

Identifying rare sourcetypes:
index=*
| stats count by sourcetype
| sort count

Troubleshooting search head cluster member activity:
index=_internal sourcetype=splunkd_search_head_cluster component=SHCMember
| stats count by log_level, message

Finding real-time searches:
index=_audit action=search earliest=-1h
| search search=*rt*
| stats count by user, search

Analyzing search dispatch directory disk usage:
| rest splunk_server=local /services/server/status/resource-usage/dispatch_usage
| stats sum(size_on_disk) as DispatchSize by splunk_server
| sort - DispatchSize

Monitoring Universal Forwarder data throughput:
index=_internal source=*/metrics.log* group=tcpin_connections
| stats sum(eval(agg_size*.001)) as Throughput by hostname
| sort - Throughput

Troubleshooting search job failures:
index=_internal sourcetype=splunkd component=SearchJob status=failure
| stats count by log_level, message

Identifying users with the most scheduled searches:
index=_internal sourcetype=scheduler
| stats count by user
| sort - count

Investigating distributed search activity:
index=_internal sourcetype=distsearch component=DistSearch
| stats count by log_level, message

Identifying top data generating hosts:
index=*
| stats count by host
| sort - count

Monitoring search artifact disk usage:
| rest splunk_server=local /services/server/status/resource-usage/search_artifacts
| stats sum(size_on_disk) as ArtifactSize by splunk_server
| sort - ArtifactSize

Investigating search head cluster election activity:
index=_internal sourcetype=splunkd_search_head_cluster component=SHCElection
| stats count by log_level, message

Troubleshooting data model acceleration issues:
index=_internal sourcetype=splunkd component=DataModelAccelerator log_level=ERROR
| stats count by log_level, message

Monitoring heavy forwarder data throughput:
index=_internal source=*/metrics.log* group=tcpout_connections
| stats sum(eval(agg_size*.001)) as Throughput by hostname
| sort - Throughput

Identifying top sources by event count:
index=*
| stats count by source
| sort - count

Troubleshooting saved search failures:
index=_internal sourcetype=scheduler savedsearch_name=* status=failure
| stats count by savedsearch_name, reason
| sort - count

Monitoring average search run time per user:
index=_audit action=search
| stats avg(run_time) as AvgRunTime by user
| sort - AvgRunTime

Investigating search head cluster rolling restart activity:
index=_internal sourcetype=splunkd_search_head_cluster component=SHCRollingRestart
| stats count by log_level, message

Identifying top indexes by event count:
index=*
| stats count by index
| sort - count







