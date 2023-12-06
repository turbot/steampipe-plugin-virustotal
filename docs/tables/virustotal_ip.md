---
title: "Steampipe Table: virustotal_ip - Query VirusTotal IP Addresses using SQL"
description: "Allows users to query IP Addresses in VirusTotal, providing insights into the detection of URLs, downloadable files, and additional information related to IP addresses."
---

# Table: virustotal_ip - Query VirusTotal IP Addresses using SQL

VirusTotal is a service that analyzes files and URLs for viruses, worms, trojans, and other kinds of malicious content. It aggregates many antivirus products and online scan engines to check for viruses that the user's own antivirus may have missed. VirusTotal also provides information regarding IP addresses, including the detection of URLs, downloadable files, and additional data.

## Table Usage Guide

The `virustotal_ip` table provides insights into IP addresses within VirusTotal. As a cybersecurity analyst, explore IP-specific details through this table, including detections of URLs, downloadable files, and additional information. Utilize it to uncover information about IP addresses, such as those associated with malicious activities, and to verify the safety of certain IPs.

**Important Notes**
- You must specify the `id` (IP address) in the `where` clause to query this table.

## Examples

### Get IP information
Discover the details of a specific IP address to understand its associated risks and behavior. This can be particularly useful in cybersecurity investigations or network monitoring.

```sql
select
  *
from
  virustotal_ip
where
  id = '76.76.21.21'
```

### Find all scanner results where result was not clean
Explore scanner results that identified potential threats or issues, providing a valuable tool for cyber security assessments and threat detection.

```sql
select
  analysis.key as scanner,
  analysis.value ->> 'result' as result
from
  virustotal.virustotal_ip,
  jsonb_each(last_analysis_results) as analysis
where
  id = '76.76.21.21'
  and analysis.value ->> 'result' != 'clean'
order by
  scanner
```