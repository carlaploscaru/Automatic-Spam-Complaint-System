package model

import (
	"time"
)

type ServerSegment struct { // one "Received:"; one transfer point in the email path
	IP string
	Host string
	ReceivedTime time.Time
	AdminContact string
	RawHeaderLine string
}

type EmailRouteTrace struct {//the complete routing history
	Segments []ServerSegment
	OriginatingSegment ServerSegment
	OriginalHeaders string
	OriginalBody string
}


type ComplaintReport struct {// the final generated output that will be sent to SpamerContact 
	TargetSpamerContact string
	Subject string
	Body string
	EvidenceBlock string // contains original header, smaall text
}
