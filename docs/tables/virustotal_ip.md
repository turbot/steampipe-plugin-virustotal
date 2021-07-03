# Table: virustotal_ip

Get information about an IP including WHOIS, popularity, DNS and more.

Note: An `id` (IP address) must be provided in all queries to this table.

## Examples

### Get IP information

```sql
select
  *
from
  virustotal_ip
where
  id = '76.76.21.21'
```

### Find all scanner results where result was not clean

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
