package virustotal

import (
	"context"

	virustotal "github.com/VirusTotal/vt-go"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableVirusTotalURL(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "virustotal_url",
		Description: "Information and analysis for a URL.",
		List: &plugin.ListConfig{
			Hydrate:    listURL,
			KeyColumns: plugin.AnyColumn([]string{"id", "url"}),
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "url", Type: proto.ColumnType_STRING, Hydrate: urlQual, Transform: transform.FromValue(), Description: "The URL to retrieve."},
			{Name: "id", Type: proto.ColumnType_STRING, Transform: transform.FromMethod("ID"), Description: "ID of the URL."},
			// Other columns
			{Name: "categories", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "categories"), Description: "Mapping that relates categorisation services with the category it assigns the url to. These services are, among others: Alexa, BitDefender, TrendMicro, Websense ThreatSeeker, etc."},
			{Name: "category", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "category"), Description: "Normalized result: harmlaess, undetected, suspicious, malicious."},
			{Name: "engine_name", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "engine_name"), Description: "Complete name of the URL scanning service."},
			{Name: "favicon", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "favicon"), Description: "Dictionary including difference hash and md5 hash of the url's favicon. Only available for premium users."},
			{Name: "first_submission_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "first_submission_date").Transform(transform.UnixToTimestamp), Description: "UTC timestamp of the date where the URL was first submitted to VirusTotal."},
			{Name: "html_meta", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "html_meta"), Description: "All meta tags (only for URLs downloading a HTML). Keys are the meta tag name and value is a list containing all values of that meta tag."},
			{Name: "last_analysis_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_date").Transform(transform.UnixToTimestamp), Description: "UTC timestamp representing last time the URL was scanned."},
			{Name: "last_analysis_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_results"), Description: "Result from URL scanners. dict with scanner name as key and a dict with notes/result from that scanner as value."},
			{Name: "last_analysis_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_stats"), Description: "Number of different results from this scans."},
			{Name: "last_final_url", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "last_final_url"), Description: "If the original URL redirects, where does it end."},
			{Name: "last_http_response_code", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "last_http_response_code"), Description: "HTTP response code of the last response."},
			{Name: "last_http_response_content_length", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "last_http_response_content_length"), Description: "Length in bytes of the content received."},
			{Name: "last_http_response_content_sha256", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "last_http_response_content_sha256"), Description: "URL response body's SHA256 hash."},
			{Name: "last_http_response_cookies", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_http_response_cookies"), Description: "The website's cookies."},
			{Name: "last_http_response_headers", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_http_response_headers"), Description: "Headers and values of last HTTP response."},
			{Name: "last_modification_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_modification_date").Transform(transform.UnixToTimestamp), Description: "Date when any of IP's information was last updated."},
			{Name: "last_submission_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_submission_date").Transform(transform.UnixToTimestamp), Description: "UTC timestamp representing last time it was sent to be analysed."},
			{Name: "method", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "method"), Description: "Type of service given by that URL scanning service, e.g. blacklist."},
			{Name: "outgoing_links", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "outgoing_links"), Description: "Links to different domains."},
			{Name: "reputation", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "reputation"), Description: "URL's score calculated from the votes of the VirusTotal's community."},
			{Name: "result", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "result"), Description: "Raw value returned by the URL scanner: e.g. clean, malicious, suspicious, phishing. It may vary from scanner to scanner, hence the need for the category field for normalisation."},
			{Name: "tags", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "tags"), Description: "List of representative attributes."},
			{Name: "targeted_brand", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "targeted_brand"), Description: "Targeted brand info extracted from phishing engines."},
			{Name: "times_submitted", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "times_submitted"), Description: "Number of times that URL has been checked."},
			{Name: "title", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "title"), Description: "Web page title."},
			{Name: "total_votes", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "total_votes"), Description: "Unweighted number of total votes from the community, divided into harmless and malicious."},
			{Name: "trackers", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "trackers"), Description: "contains all found trackers in that URL in a historical manner. Every key is a tracker name, which is a dictionary containing."},
		},
	}
}

func urlQual(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
	// The URL may change between being passed in and being returned. For example
	// a query for 'https://github.com' returns a URL of 'https://github.com/'.
	// To ensure they match the original query the order is:
	// * If URL qual is passed, return that; otherwise
	// * Return the URL field from the object
	quals := d.KeyColumnQuals
	if quals["url"] != nil {
		return quals["url"].GetStringValue(), nil
	}
	obj := h.Item.(*virustotal.Object)
	i, err := obj.Get("url")
	if err != nil {
		// Log the error, but return nil. This covers various cases such as fields that are
		// only available in the premium tier being missing in results.
		plugin.Logger(ctx).Error("virustotal.urlQual", "err", err)
		return nil, nil
	}
	return i, nil
}

func listURL(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	conn, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_url.listURL", "connection_error", err)
		return nil, err
	}
	quals := d.KeyColumnQuals
	var key string
	if quals["id"] != nil {
		key = quals["id"].GetStringValue()
	} else if quals["url"] != nil {
		key = urlToID(quals["url"].GetStringValue())
	}
	u := virustotal.URL("urls/" + key)
	it, err := conn.Iterator(u)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_url.listURL", "query_error", err, "it", it)
		return nil, err
	}
	defer it.Close()
	for it.Next() {
		d.StreamListItem(ctx, it.Get())
	}
	if err := it.Error(); err != nil {
		if !isNotFoundError(err) {
			plugin.Logger(ctx).Error("virustotal_url.listURL", "query_error", err, "it", it)
			return nil, err
		}
	}
	return nil, nil
}
