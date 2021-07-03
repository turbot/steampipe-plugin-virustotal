# Table: virustotal_url

Get information about an URL including WHOIS, popularity, DNS and more.

Note: A `url` (URL address) or `id` (hash of the URL) must be provided in all queries to this table.

## Examples

### Get URL information

```sql
select
  *
from
  virustotal_url
where
  url = 'https://github.com'
```

### Get URL information by ID

```sql
select
  *
from
  virustotal_url
where
  id = '09a8b930c8b79e7c313e5e741e1d59c39ae91bc1f10cdefa68b47bf77519be57'
```

### Find all scanner results where result was not clean

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
