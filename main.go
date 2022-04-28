package main

import (
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-virustotal/virustotal"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: virustotal.Plugin})
}
