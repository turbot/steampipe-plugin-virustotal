package virustotal

import (
	virustotal "github.com/VirusTotal/vt-go"
)

func isNotFoundError(err error) bool {
	if virustotalErr, ok := err.(virustotal.Error); ok {
		switch virustotalErr.Code {
		case "NotFoundError":
			return true
		}
	}
	return false
}
