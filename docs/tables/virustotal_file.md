# Table: virustotal_file

Get information about a file including scan results, names often used for the file and more.

Note: A `path` (local path to a file) or `id` (hash of the file) must be provided in all queries to this table.

## Examples

### Get VirusTotal information for a local file

Uses a local file to generate the hash to query VirusTotal for information
about the file.

The file will not be uploaded for scanning, but just used to generate the hash
to search existing results.

```sql
select
  *
from
  virustotal_file
where
  path = '/Users/michael/Downloads/terraform_1.0.1_darwin_amd64.zip'
```

### Get file information by ID

```sql
select
  *
from
  virustotal_file
where
  id = '8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85'
```

### List alternate names for a file

```sql
select
  jsonb_array_elements_text(names) as name
from
  virustotal_file
where
  id = '8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85'
order by
  name
```

### Find all scanner results by engine

```sql
select
  analysis.key as engine,
  analysis.value ->> 'category' as result
from
  virustotal.virustotal_file,
  jsonb_each(last_analysis_results) as analysis
where
  id = '8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85'
order by
  engine
```
