package virustotal

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name: "steampipe-plugin-virustotal",
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
		},
		DefaultTransform: transform.FromGo(),
		DefaultGetConfig: &plugin.GetConfig{
			IgnoreConfig: &plugin.IgnoreConfig{ShouldIgnoreErrorFunc: func(_ context.Context, _ *plugin.QueryData, _ *plugin.HydrateData, err error) bool {
				return isNotFoundError(err)
			}},
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
