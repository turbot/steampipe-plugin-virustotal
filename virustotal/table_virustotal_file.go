package virustotal

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	virustotal "github.com/VirusTotal/vt-go"

	"github.com/turbot/steampipe-plugin-sdk/v4/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin/transform"
)

func tableVirusTotalFile(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "virustotal_file",
		Description: "Information and analysis for a File.",
		List: &plugin.ListConfig{
			Hydrate:    listFile,
			KeyColumns: plugin.AnyColumn([]string{"id", "path"}),
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "path", Type: proto.ColumnType_STRING, Transform: transform.FromQual("path"), Description: "File path to check with VirusTotal."},
			{Name: "id", Type: proto.ColumnType_STRING, Transform: transform.FromMethod("ID"), Description: "ID of the File."},
			{Name: "meaningful_name", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "meaningful_name"), Description: "The most interesting name out of all file's names."},
			// Other columns
			{Name: "capabilities_tags", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "names"), Description: "List of representative tags related to the file's capabilities. Only available for Premium API users."},
			{Name: "creation_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "creation_date").Transform(transform.UnixToTimestamp), Description: "Extracted when possible from the file's metadata. Indicates when it was built or compiled. It can also be faked by malware creators. UTC timestamp."},
			{Name: "crowdsourced_ids_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "crowdsourced_ids_results"), Description: "IDS (Snort and Suricata) matches for the file. If the file it's not a PCAP, the matches are taken from a PCAP generated after running the file in a sandbox. Results are sorted by severity level, there is only one item per matched alert and every item on the list contains:"},
			{Name: "crowdsourced_ids_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "crowdsourced_ids_stats"), Description: "Result statistics by severity level."},
			{Name: "crowdsourced_yara_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "crowdsourced_yara_results"), Description: "YARA matches for the file."},
			{Name: "downloadable", Type: proto.ColumnType_BOOL, Transform: transform.FromValue().TransformP(getAttribute, "downloadable"), Description: "True if the file can be downloaded, false otherwise. Only available for Premium API users."},
			{Name: "first_submission_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "first_submission_date").Transform(transform.UnixToTimestamp), Description: "UTC timestamp of the date where the File was first submitted to VirusTotal."},
			{Name: "last_analysis_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_date").Transform(transform.UnixToTimestamp), Description: "UTC timestamp representing last time the File was scanned."},
			{Name: "last_analysis_results", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_results"), Description: "Result from File scanners. dict with scanner name as key and a dict with notes/result from that scanner as value."},
			{Name: "last_analysis_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "last_analysis_stats"), Description: "Number of different results from this scans."},
			{Name: "last_modification_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_modification_date").Transform(transform.UnixToTimestamp), Description: "Date when any of IP's information was last updated."},
			{Name: "last_submission_date", Type: proto.ColumnType_TIMESTAMP, Transform: transform.FromValue().TransformP(getAttribute, "last_submission_date").Transform(transform.UnixToTimestamp), Description: "UTC timestamp representing last time it was sent to be analysed."},
			{Name: "main_icon", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "main_icon"), Description: "Icon's relevant hashes."},
			{Name: "md5", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "md5"), Description: "File's MD5 hash."},
			{Name: "names", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "names"), Description: "All file names associated with the file."},
			{Name: "reputation", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "reputation"), Description: "File's score calculated from the votes of the VirusTotal's community."},
			{Name: "sandbox_verdicts", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "sandbox_verdicts"), Description: "A summary of all sandbox verdicts for a given file."},
			{Name: "sha1", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "sha1"), Description: "File's SHA1 hash."},
			{Name: "sha256", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "sha256"), Description: "File's SHA256 hash."},
			{Name: "sigma_analysis_stats", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "sigma_analysis_stats"), Description: "Dictionary containing the number of matched sigma rules, grouped by its severity."},
			{Name: "sigma_analysis_summary", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "sigma_analysis_summary"), Description: "Dictionary containing the number of matched sigma rules group by its severity, same as sigma_analysis_stats but split by ruleset. Dictionary key is the ruleset name and value is the stats for that specific ruleset."},
			{Name: "size", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "size"), Description: "File size in bytes."},
			{Name: "tags", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "tags"), Description: "List of representative attributes."},
			{Name: "times_submitted", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "times_submitted"), Description: "Number of times that File has been checked."},
			{Name: "total_votes", Type: proto.ColumnType_JSON, Transform: transform.FromValue().TransformP(getAttribute, "total_votes"), Description: "Unweighted number of total votes from the community, divided into harmless and malicious."},
			{Name: "type_description", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "type_description"), Description: "Describtes the file type."},
			{Name: "type_extension", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "type_extension"), Description: "Specifies the file extension."},
			{Name: "type_tag", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "type_tag"), Description: "Tag representing the file type. Can be used to filter by file type in VirusTotal intelligence searches."},
			{Name: "unique_sources", Type: proto.ColumnType_INT, Transform: transform.FromValue().TransformP(getAttribute, "unique_sources"), Description: "Indicates from how many different sources the file has been posted from."},
			{Name: "vhash", Type: proto.ColumnType_STRING, Transform: transform.FromValue().TransformP(getAttribute, "vhash"), Description: "In-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files."},
		},
	}
}

func getFileSHA256SUM(filename string) (string, error) {
	var hashsum string
	f, err := os.Open(filename)
	if err != nil {
		return hashsum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return hashsum, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func listFile(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	conn, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_file.listFile", "connection_error", err)
		return nil, err
	}
	quals := d.KeyColumnQuals
	var key string
	if quals["id"] != nil {
		key = quals["id"].GetStringValue()
	} else if quals["path"] != nil {
		hash, err := getFileSHA256SUM(quals["path"].GetStringValue())
		if err != nil {
			plugin.Logger(ctx).Error("virustotal_file.listFile", "path_error", err)
			return nil, err
		}
		key = hash
	}
	u := virustotal.URL("files/" + key)
	it, err := conn.Iterator(u)
	if err != nil {
		plugin.Logger(ctx).Error("virustotal_file.listFile", "query_error", err, "it", it)
		return nil, err
	}
	defer it.Close()
	for it.Next() {
		d.StreamListItem(ctx, it.Get())
	}
	if err := it.Error(); err != nil {
		if !isNotFoundError(err) {
			plugin.Logger(ctx).Error("virustotal_file.listFile", "query_error", err, "it", it)
			return nil, err
		}
	}
	return nil, nil
}
