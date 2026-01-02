package reporter

import (
	"fmt"
	"strings"
	"time"

	"go.com/go-project/internal/model"
)


type ComplaintData struct {
	Trace          *model.EmailRouteTrace
	RawEmail       string
	TargetIP       string
	WhoisResult    string
	AbuseEmail     string 
}

func GenerateComplaint(data *ComplaintData) (string, error) {
	if data.AbuseEmail == "" {
		return "", fmt.Errorf("cannot generate complaint; missing AbuseEmail")
	}
	
	var b strings.Builder
	fmt.Fprintf(&b, "To: %s\n", data.AbuseEmail)
	fmt.Fprintf(&b, "Subject: Abuse Report: Unsolicited from IP %s\n\n", data.TargetIP)
	
	b.WriteString("Detected spam email\n")
	fmt.Fprintf(&b, "Date/Time of detection: %s\n\n", time.Now().Format(time.RFC1123))

	// evidence
	b.WriteString("Evidence\n")
	fmt.Fprintf(&b, "Source IP: %s\n", data.TargetIP)
	b.WriteString("Activity: Unsolicited Email\n")
	if data.WhoisResult != "" {
		fmt.Fprintf(&b, "Network Info: %s\n", data.WhoisResult)
	}
	b.WriteString("\n")


	b.WriteString("Network route\n")
	if data.Trace != nil {
		for _, segment := range data.Trace.Segments {
			fmt.Fprintf(&b, "IP: %s , Host: %s , Received: %s\n", 
				segment.IP, segment.Host, segment.ReceivedTime.Format(time.RFC822))
		}
	}
	b.WriteString("\n")

	
	b.WriteString("Original email\n")
	b.WriteString(data.RawEmail)
	b.WriteString("\n\n")


	b.WriteString("Please investigate this spam email.\n")
	b.WriteString("Thank you.\n")

	return b.String(), nil// convert builder to one string for ret
}