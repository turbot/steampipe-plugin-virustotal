# Table: virustotal_search

Perform simple searches for VirusTotal.

Note: A search `query` must be provided in all queries to this table.

## Examples

### Simple searches (free tier)

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
