package main

import (
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-virustotal/virustotal"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: virustotal.Plugin})
}
