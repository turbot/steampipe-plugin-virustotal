package virustotal

import (
	"context"

	virustotal "github.com/VirusTotal/vt-go"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableVirusTotalDomain(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "virustotal_domain",
		Description: "Information and analysis for a domain.",
		List: &plugin.ListConfig{
			Hydrate:    listDomain,
			KeyColumns: plugin.SingleColumn("id"),
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "id", Type: proto.ColumnType_STRING, Transform: transform.FromQual("id"), Description: "The domain name to retrieve."},
			// Other columns
			{Name: "categories", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "categories"), Description: "Mapping that relates categorisation services with the category it assigns the domain to. These services are, among others: Alexa, BitDefender, TrendMicro, Websense ThreatSeeker, etc."},
			{Name: "creation_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "creation_date").Transform(transform.UnixToTimestamp), Description: "Creation date extracted from the Domain's whois."},
			{Name: "favicon", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "favicon"), Description: "Dictionary including difference hash and md5 hash of the domain's favicon. Only available for premium users."},
			{Name: "jarm", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "jarm"), Description: "JARM is an active Transport Layer Security (TLS) server fingerprint."},
			{Name: "last_analysis_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_results"), Description: "Result from URL scanners. dict with scanner name as key and a dict with notes/result from that scanner as value."},
			{Name: "last_analysis_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_stats"), Description: "Number of different results from this scans."},
			{Name: "last_dns_records", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_dns_records"), Description: "Domain's DNS records on its last scan."},
			{Name: "last_dns_records_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_dns_records_date").Transform(transform.UnixToTimestamp), Description: "Date when the dns records list was retrieved by VirusTotal."},
			{Name: "last_https_certificate", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_https_certificate"), Description: "SSL Certificate object retrieved last time the domain was analysed."},
			{Name: "last_https_certificate_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_https_certificate_date").Transform(transform.UnixToTimestamp), Description: "Date when the certificate was retrieved by VirusTotal."},
			{Name: "last_modification_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_modification_date").Transform(transform.UnixToTimestamp), Description: "Date when any of domain's information was last updated."},
			{Name: "last_update_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_update_date").Transform(transform.UnixToTimestamp), Description: "Updated date extracted from whois."},
			{Name: "popularity_ranks", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "popularity_ranks"), Description: "Domain's position in popularity ranks such as Alexa, Quantcast, Statvoo, etc."},
			{Name: "registrar", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "registrar"), Description: "Company that registered the domain."},
			{Name: "reputation", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "reputation"), Description: "Domain's score calculated from the votes of the VirusTotal's community."},
			{Name: "tags", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "tags"), Description: "List of representative attributes."},
			{Name: "total_votes", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "total_votes"), Description: "Unweighted number of total votes from the community, divided into harmless and malicious."},
			{Name: "whois", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "whois"), Description: "WHOIS information as returned from the pertinent whois server."},
			{Name: "whois_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "whois_date").Transform(transform.UnixToTimestamp), Description: "Date of the last update of the whois record in VirusTotal."},
		},
	}
}

func listDomain(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	conn, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_domain.listDomain", "connection_error", err)
		return nil, err
	}
	quals := d.KeyColumnQuals
	id := quals["id"].GetStringValue()
	u := virustotal.URL("domains/" + id)
	it, err := conn.Iterator(u)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_domain.listDomain", "query_error", err, "it", it)
		return nil, err
	}
	defer it.Close()
	for it.Next() {
		i := it.Get()
		d.StreamListItem(ctx, i)
	}
	if err := it.Error(); err != nil {
		if !isNotFoundError(err) {
			plugin.Logger(ctx).Error("virustotal_domain.listDomain", "query_error", err, "it", it)
			return nil, err
		}
	}
	return nil, nil
}
