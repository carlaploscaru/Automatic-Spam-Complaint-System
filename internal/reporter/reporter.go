package reporter

import (
	"fmt"

	"go.com/go-project/internal/model"
)


type ComplaintData struct {
	Trace          *model.EmailRouteTrace
	RawEmail       string
	TargetIP       string
	WhoisResult    string
	AbuseEmail     string // final email addr to sendd report 
}

func GenerateComplaint(data *ComplaintData) (string, error) {
	if data.AbuseEmail == "" {
		return "", fmt.Errorf("cannot generate complaint; missing AbuseEmail")
	}
	return fmt.Sprintf("Report sent to %s, from %s......next ", data.AbuseEmail, data.TargetIP), nil
}