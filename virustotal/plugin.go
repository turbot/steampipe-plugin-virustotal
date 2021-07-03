package virustotal

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/plugin"
	"github.com/turbot/steampipe-plugin-sdk/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name: "steampipe-plugin-virustotal",
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
			Schema:      ConfigSchema,
		},
		DefaultTransform: transform.FromGo(),
		DefaultGetConfig: &plugin.GetConfig{
			ShouldIgnoreError: isNotFoundError,
		},
		TableMap: map[string]*plugin.Table{
			"virustotal_domain": tableVirusTotalDomain(ctx),
			"virustotal_file":   tableVirusTotalFile(ctx),
			"virustotal_ip":     tableVirusTotalIP(ctx),
			"virustotal_search": tableVirusTotalSearch(ctx),
			"virustotal_url":    tableVirusTotalURL(ctx),
		},
	}
	return p
}
