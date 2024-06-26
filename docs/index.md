---
organization: Turbot
category: ["security"]
icon_url: "/images/plugins/turbot/virustotal.svg"
brand_color: "#394eff"
display_name: "VirusTotal"
short_name: "virustotal"
description: "Steampipe plugin to query file, domain, URL and IP scanning results from VirusTotal."
og_description: "Query VirusTotal with SQL! Open source CLI. No DB required."
og_image: "/images/plugins/turbot/virustotal-social-graphic.png"
engines: ["steampipe", "sqlite", "postgres", "export"]
---

# VirusTotal + Steampipe

[VirusTotal](https://virustotal.com) is an Internet security, file and URL analyzer.

[Steampipe](https://steampipe.io) is an open-source zero-ETL engine to instantly query cloud APIs using SQL.

Get VirusTotal scan data for a local file:

```sql
select
  meaningful_name,
  reputation
from
  virustotal_file
where
  path = '/full/path/to/file'
```

```
+----------------------------------+------------+
| meaningful_name                  | reputation |
+----------------------------------+------------+
| terraform_1.0.1_darwin_amd64.zip | 0          |
+----------------------------------+------------+
```

## Documentation

- **[Table definitions & examples →](/plugins/turbot/virustotal/tables)**

## Get started

### Install

Download and install the latest VirusTotal plugin:

```bash
steampipe plugin install virustotal
```

### Credentials

| Item        | Description                                                                                                               |
| :---------- | :------------------------------------------------------------------------------------------------------------------------ |
| Credentials | VirusTotal requires a [free API key](https://docs.virustotal.com/docs/please-give-me-an-api-key) for all requests. |
| Radius      | Each connection represents a single VirusTotal account.                                                                   |

### Configuration

Installing the latest virustotal plugin will create a config file (`~/.steampipe/config/virustotal.spc`) with a single connection named `virustotal`:

```hcl
connection "virustotal" {
  plugin  = "virustotal"
  api_key = "beec40da46647b5e31d5377af470c0c525fd4185fb14ed2d0b38a038718ae3bf"
}
```

- `api_key` - Your VirusTotal API key.


