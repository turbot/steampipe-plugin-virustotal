package virustotal

import (
	"context"

	virustotal "github.com/VirusTotal/vt-go"

	"github.com/turbot/steampipe-plugin-sdk/v4/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin/transform"
)

func tableVirusTotalSearch(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "virustotal_search",
		Description: "",
		List: &plugin.ListConfig{
			Hydrate:    listSearch,
			KeyColumns: plugin.SingleColumn("query"),
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "id", Type: proto.ColumnType_STRING, Transform: transform.FromMethod("ID"), Description: ""},
			{Name: "object_type", Type: proto.ColumnType_STRING, Transform: transform.FromMethod("Type"), Description: ""},
			// Other columns
			{Name: "attributes", Type: proto.ColumnType_JSON, Transform: transform.FromValue().Transform(getJSON), Description: ""},
			{Name: "last_analysis_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_results"), Description: "Result from URL scanners. Dict with scanner name as key and a dict with notes/result from that scanner as value."},
			{Name: "last_analysis_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_stats"), Description: "Number of different results from this scans."},
			{Name: "last_modification_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_modification_date").Transform(transform.UnixToTimestamp), Description: "Date when any of IP's information was last updated."},
			{Name: "query", Type: proto.ColumnType_STRING, Transform: transform.FromQual("query"), Description: "The search query."},
			{Name: "reputation", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "reputation"), Description: "IP's score calculated from the votes of the VirusTotal's community."},
			{Name: "tags", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "tags"), Description: "List of representative attributes."},
			{Name: "total_votes", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "total_votes"), Description: "Unweighted number of total votes from the community, divided into harmless and malicious."},
		},
	}
}

func listSearch(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	quals := d.KeyColumnQuals
	query := quals["query"].GetStringValue()
	conn, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_search.listSearch", "connection_error", err)
		return nil, err
	}
	u := virustotal.URL("search")
	q := u.Query()
	q.Add("query", query)
	u.RawQuery = q.Encode()
	it, err := conn.Iterator(u)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_search.listSearch", "query_error", err, "it", it)
		return nil, err
	}
	defer it.Close()
	for it.Next() {
		d.StreamListItem(ctx, it.Get())
	}
	if err := it.Error(); err != nil {
		plugin.Logger(ctx).Error("virustotal_search.listSearch", "query_error", err, "it", it)
		return nil, err
	}
	return nil, nil
}
