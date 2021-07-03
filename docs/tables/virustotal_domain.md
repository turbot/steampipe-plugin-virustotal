# Table: virustotal_domain

Get information about a domain including WHOIS, popularity, DNS and more.

Note: An `id` (registered domain name) must be provided in all queries to this table.

## Examples

### Get domain information

```sql
select
  *
from
  virustotal_domain
where
  id = 'steampipe.io'
```
