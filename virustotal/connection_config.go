package virustotal

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

type virustotalConfig struct {
	APIKey *string `hcl:"api_key"`
}

func ConfigInstance() interface{} {
	return &virustotalConfig{}
}

// GetConfig :: retrieve and cast connection config from query data
func GetConfig(connection *plugin.Connection) virustotalConfig {
	if connection == nil || connection.Config == nil {
		return virustotalConfig{}
	}
	config, _ := connection.Config.(virustotalConfig)
	return config
}
