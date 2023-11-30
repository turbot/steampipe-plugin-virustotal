---
title: "Steampipe Table: virustotal_url - Query VirusTotal URL Reports using SQL"
description: "Allows users to query URL reports in VirusTotal, providing insights into URL scanning and detection data."
---

# Table: virustotal_url - Query VirusTotal URL Reports using SQL

VirusTotal is a service that analyzes files and URLs for viruses, worms, trojans, and other kinds of malicious content. It uses an array of antivirus engines and website scanners, as well as a comprehensive dataset that is updated in real time. VirusTotal's URL reports provide detailed information about the URLs analyzed, including the scan results, detection ratios, and the time of the last analysis.

## Table Usage Guide

The `virustotal_url` table provides insights into URL reports within VirusTotal. As a cybersecurity analyst, explore URL-specific details through this table, including scan dates, detection ratios, and scan results. Utilize it to uncover information about URLs, such as their safety status, the details of the scans performed on them, and the detection ratios associated with each URL.

## Examples

### Get URL information
Discover the segments that are associated with a specific website by analyzing its URL. This can be beneficial for identifying potential security risks or understanding the website's online footprint.

```sql
select
  *
from
  virustotal_url
where
  url = 'https://github.com'
```

### Get URL information by ID
Discover the specifics of a particular URL by using its unique ID. This can be particularly useful when investigating potentially harmful or suspicious URLs for cybersecurity purposes.

```sql
select
  *
from
  virustotal_url
where
  id = '09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57'
```

### Find all scanner results where result was not clean
Identify instances where the scan results were not clean for a specific URL. This could be used to assess the security and safety of the website, highlighting any potential threats or issues.

```sql
select
  analysis.key as scanner,
  analysis.value ->> 'result' as result
from
  virustotal.virustotal_url,
  jsonb_each(last_analysis_results) as analysis
where
  url = 'https://github.com'
  and analysis.value ->> 'result' != 'clean'
order by
  scanner
```