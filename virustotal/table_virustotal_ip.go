package virustotal

import (
	"context"

	virustotal "github.com/VirusTotal/vt-go"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableVirusTotalIP(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "virustotal_ip",
		Description: "Information and analysis for an IP address.",
		List: &plugin.ListConfig{
			Hydrate:    listIP,
			KeyColumns: plugin.SingleColumn("id"),
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "id", Type: proto.ColumnType_IPADDR, Hydrate: ipQual, Transform: transform.FromValue(), Description: "The IP to retrieve."},
			// Other columns
			{Name: "as_owner", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "as_owner"), Description: "Owner of the Autonomous System to which the IP belongs."},
			{Name: "asn", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "asn"), Description: "Autonomous System Number to which the IP belongs."},
			{Name: "category", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "category"), Description: "Normalized result: harmlaess, undetected, suspicious, malicious."},
			{Name: "continent", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "continent"), Description: "Continent where the IP is placed (ISO-3166 continent code)."},
			{Name: "country", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "country"), Description: "Country where the IP is placed (ISO-3166 country code)."},
			{Name: "engine_name", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "engine_name"), Description: "Complete name of the URL scanning service."},
			{Name: "last_analysis_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_results"), Description: "Result from URL scanners. Dict with scanner name as key and a dict with notes/result from that scanner as value."},
			{Name: "last_analysis_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_stats"), Description: "Number of different results from this scans."},
			{Name: "last_https_certificate", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_https_certificate"), Description: "SSL Certificate object retrieved last time the IP was analysed."},
			{Name: "last_https_certificate_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_https_certificate_date").Transform(transform.UnixToTimestamp), Description: "Date when the certificate was retrieved by VirusTotal."},
			{Name: "last_modification_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_modification_date").Transform(transform.UnixToTimestamp), Description: "Date when any of IP's information was last updated."},
			{Name: "method", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "method"), Description: "Type of service given by that URL scanning service, e.g. blacklist."},
			{Name: "network", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "network"), Description: "IPv4 network range to which the IP belongs."},
			{Name: "regional_internet_registry", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "regional_internet_registry"), Description: "One of the current regional internet registries: AFRINIC, ARIN, APNIC, LACNIC or RIPE NCC."},
			{Name: "reputation", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "reputation"), Description: "IP's score calculated from the votes of the VirusTotal's community."},
			{Name: "result", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "result"), Description: "Raw value returned by the URL scanner: e.g. clean, malicious, suspicious, phishing. It may vary from scanner to scanner, hence the need for the category field for normalisation."},
			{Name: "tags", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "tags"), Description: "List of representative attributes."},
			{Name: "total_votes", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "total_votes"), Description: "Unweighted number of total votes from the community, divided into harmless and malicious."},
			{Name: "whois", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "whois"), Description: "WHOIS information as returned from the pertinent whois server."},
			{Name: "whois_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "whois_date").Transform(transform.UnixToTimestamp), Description: "Date of the last update of the whois record in VirusTotal."},
		},
	}
}

func ipQual(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	quals := d.KeyColumnQuals
	id := quals["id"].GetInetValue().GetAddr()
	return id, nil
}

func listIP(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	conn, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_ip.listIP", "connection_error", err)
		return nil, err
	}
	quals := d.KeyColumnQuals
	id := quals["id"].GetInetValue().GetAddr()
	u := virustotal.URL("ip_addresses/" + id)
	it, err := conn.Iterator(u)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_ip.listIP", "query_error", err, "it", it)
		return nil, err
	}
	defer it.Close()
	for it.Next() {
		i := it.Get()
		d.StreamListItem(ctx, i)
	}
	if err := it.Error(); err != nil {
		if !isNotFoundError(err) {
			plugin.Logger(ctx).Error("virustotal_ip.listIP", "query_error", err, "it", it)
			return nil, err
		}
	}
	return nil, nil
}
