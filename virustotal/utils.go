package virustotal

import (
	"context"
	"encoding/base64"
	"errors"
	"os"

	virustotal "github.com/VirusTotal/vt-go"

	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func connect(_ context.Context, d *plugin.QueryData) (*virustotal.Client, error) {

	// Load connection from cache, which preserves throttling protection etc
	cacheKey := "virustotal"
	if cachedData, ok := d.ConnectionManager.Cache.Get(cacheKey); ok {
		return cachedData.(*virustotal.Client), nil
	}

	// Default to using env vars
	apiKey := os.Getenv("VTCLI_APIKEY")

	// But prefer the config
	virustotalConfig := GetConfig(d.Connection)
	if virustotalConfig.APIKey != nil {
		apiKey = *virustotalConfig.APIKey
	}

	if apiKey == "" {
		// Credentials not set
		return nil, errors.New("api_key must be configured")
	}

	conn := virustotal.NewClient(apiKey)
	conn.Agent = "Steampipe/0.x (+https://steampipe.io)"

	// Save to cache
	d.ConnectionManager.Cache.Set(cacheKey, conn)

	return conn, nil
}

func getAttribute(ctx context.Context, d *transform.TransformData) (interface{}, error) {
	obj := d.Value.(*virustotal.Object)
	name := d.Param.(string)
	i, err := obj.Get(name)
	if err != nil {
		// Log the error, but return nil. This covers various cases such as fields that are
		// only available in the premium tier being missing in results.
		plugin.Logger(ctx).Error("virustotal.getAttribute", "err", err)
		return nil, nil
	}
	return i, nil
}

func getJSON(_ context.Context, d *transform.TransformData) (interface{}, error) {
	obj := d.Value.(*virustotal.Object)
	bytes, err := obj.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}

func urlToID(u string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(u))
}
