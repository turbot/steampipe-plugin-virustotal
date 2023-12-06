---
title: "Steampipe Table: virustotal_search - Query VirusTotal Search Results using SQL"
description: "Allows users to query VirusTotal search results. This table provides a comprehensive view of the antivirus scan results, website scanning, and URL/domain blacklisting."
---

# Table: virustotal_search - Query VirusTotal Search Results using SQL

VirusTotal is a service that analyzes files and URLs for viruses, worms, trojans, and other kinds of malicious content. It aggregates information from many antivirus and URL scanners to provide a comprehensive view of antivirus scan results, website scanning, and URL/domain blacklisting. This service is useful for detecting malicious content and understanding the security landscape.

## Table Usage Guide

The `virustotal_search` table provides insights into the search results from VirusTotal. As a security analyst, explore the details of antivirus scan results, website scanning, and URL/domain blacklisting through this table. Utilize it to uncover information about potential security threats, such as malware, trojans, and other malicious content.

**Important Notes**
- You must specify the `query` in the `where` clause to query this table.

## Examples

### Simple searches (free tier)
Explore various internet entities like websites, IP addresses, and file hashes for potential security threats by cross-referencing them with the VirusTotal database. This is useful for identifying potential risks associated with these entities, helping to maintain cybersecurity.
The free tier only supports simple search terms for hashes and IDs.

This example combines simple searches of different types into a single
consistent result set.


```sql
select * from virustotal_search where query = 'github.com'
union
select * from virustotal_search where query = 'https://turbot.com'
union
select * from virustotal_search where query = '76.76.21.21'
union
select * from virustotal_search where query = '8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85'
```