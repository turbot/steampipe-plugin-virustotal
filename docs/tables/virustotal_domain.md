---
title: "Steampipe Table: virustotal_domain - Query VirusTotal Domain Reports using SQL"
description: "Allows users to query Domain Reports in VirusTotal, specifically providing detailed information about a domain, including the detection of potentially malicious activities."
---

# Table: virustotal_domain - Query VirusTotal Domain Reports using SQL

VirusTotal is a free online service that analyzes files and URLs for viruses, worms, trojans and other kinds of malicious content. It aggregates many antivirus products and online scan engines to check for viruses that the user's own antivirus solution may have missed, or to verify against any false positives. Domain Reports in VirusTotal provide detailed information about a domain, including the detection of potentially malicious activities.

## Table Usage Guide

The `virustotal_domain` table provides insights into Domain Reports within VirusTotal. As a cybersecurity analyst, explore domain-specific details through this table, including detections, resolutions, and subdomains. Utilize it to uncover information about domains, such as those linked with malicious activities, the resolved IPs, and the detection of potentially harmful subdomains.

**Important Notes**
- You must specify the `id` (registered domain name) in the `where` clause to query this table.

## Examples

### Get domain information
Explore the detailed information associated with a specific domain to understand its characteristics and potential security risks. This can be particularly useful for cybersecurity analysis and threat detection.

```sql
select
  *
from
  virustotal_domain
where
  id = 'steampipe.io'
```