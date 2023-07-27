![image](https://hub.steampipe.io/images/plugins/turbot/virustotal-social-graphic.png)

# VirusTotal Plugin for Steampipe

Use SQL to query file, domain, URL and IP scanning results from VirusTotal.

- **[Get started →](https://hub.steampipe.io/plugins/turbot/virustotal)**
- Documentation: [Table definitions & examples](https://hub.steampipe.io/plugins/turbot/virustotal/tables)
- Community: [Join #steampipe on Slack →](https://turbot.com/community/join)
- Get involved: [Issues](https://github.com/turbot/steampipe-plugin-virustotal/issues)

## Quick start

Install the plugin with [Steampipe](https://steampipe.io):

```shell
steampipe plugin install virustotal
```

Run a query:

```sql
select
  meaningful_name,
  reputation
from
  virustotal_file
where
  path = '/full/path/to/file'
```

## Developing

Prerequisites:

- [Steampipe](https://steampipe.io/downloads)
- [Golang](https://golang.org/doc/install)

Clone:

```sh
git clone https://github.com/turbot/steampipe-plugin-virustotal.git
cd steampipe-plugin-virustotal
```

Build, which automatically installs the new version to your `~/.steampipe/plugins` directory:

```
make
```

Configure the plugin:

```
cp config/* ~/.steampipe/config
vi ~/.steampipe/config/virustotal.spc
```

Try it!

```
steampipe query
> .inspect virustotal
```

Further reading:

- [Writing plugins](https://steampipe.io/docs/develop/writing-plugins)
- [Writing your first table](https://steampipe.io/docs/develop/writing-your-first-table)

## Contributing

Please see the [contribution guidelines](https://github.com/turbot/steampipe/blob/main/CONTRIBUTING.md) and our [code of conduct](https://github.com/turbot/steampipe/blob/main/CODE_OF_CONDUCT.md). All contributions are subject to the [Apache 2.0 open source license](https://github.com/turbot/steampipe-plugin-virustotal/blob/main/LICENSE).

`help wanted` issues:

- [Steampipe](https://github.com/turbot/steampipe/labels/help%20wanted)
- [VirusTotal Plugin](https://github.com/turbot/steampipe-plugin-virustotal/labels/help%20wanted)
