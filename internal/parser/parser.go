package parser

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"go.com/go-project/internal/model" //from go.mod
)

// Regex gets IP, host, time
var receivedRegex = regexp.MustCompile(
	`(?i)Received:.*?` +
		// host
		`(?:\s+from\s+(?P<host>[^\s\(\);]+)\s*)?` +
		// IP
		`(?:.*?\[?\s*(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\]?.*?)?` +
		// time
		`(?P<time>[A-Z][a-z]{2},\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[\-+][\d]{4}(?:\s+\([A-Z]+\))?)` +
		`.*$`,
)

func ParseRawEmail(rawInput string) (*model.EmailRouteTrace, error) {
	parts := strings.SplitN(rawInput, "\n\n", 2) // split headers from body,stie exact unde e /n/n in email ca sa le separe
	var rawHeaders, rawBody string

	if len(parts) > 0 {
		rawHeaders = strings.TrimSpace(parts[0])
	}
	if len(parts) > 1 {
		rawBody = strings.TrimSpace(parts[1])
	}

	if rawHeaders == "" {
		return nil, fmt.Errorf("could not find any headers in the input")
	}

	trace := &model.EmailRouteTrace{ //stores text in EmailRouteTrace struct
		OriginalHeaders: rawHeaders,
		OriginalBody:    rawBody,
		Segments:        []model.ServerSegment{},
	}

	headerLines := strings.Split(rawHeaders, "\n") // curatare spatii
	var unfoldedHeaders []string
	currentHeader := ""

	for _, line := range headerLines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			currentHeader += strings.TrimSpace(line) // tai spatiul pt ca e in acelasi "receive"
		} else {
			if currentHeader != "" { // receive nou, save
				unfoldedHeaders = append(unfoldedHeaders, currentHeader)
			}
			currentHeader = strings.TrimSpace(line) //contruirea noului receive
		}
	}
	if currentHeader != "" { // save last receive
		unfoldedHeaders = append(unfoldedHeaders, currentHeader)
	}

	for _, line := range unfoldedHeaders { //parse headers
		if !strings.HasPrefix(strings.ToLower(line), "received:") {
			continue
		}

		segment, err := parseReceivedLine(line) //check time, ip...
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse Received header line '%s': %v\n", line, err)
			continue
		}

		trace.Segments = append(trace.Segments, *segment)
	}

	if len(trace.Segments) > 0 {
		trace.OriginatingSegment = trace.Segments[len(trace.Segments)-1] //get origin segment/last
	}

	return trace, nil
}

func parseReceivedLine(rawLine string) (*model.ServerSegment, error) { // gets time, ip...from one segments
	segment := &model.ServerSegment{
		RawHeaderLine: rawLine,
	}

	match := receivedRegex.FindStringSubmatch(rawLine)
	if len(match) == 0 {
		return segment, fmt.Errorf("no match found for IP, host or time")
	}

	result := make(map[string]string)
	for i, name := range receivedRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	segment.Host = result["host"]
	segment.IP = result["ip"]

	timeStr := strings.TrimSpace(result["time"])
	if timeStr != "" {
		layouts := []string{
			"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
			"Mon, 2 Jan 2006 15:04:05 -0700",
			"Mon, 2 Jan 2006 15:04:05 MST",
			"2 Jan 2006 15:04:05 -0700",
		}

		for _, layout := range layouts {
			t, err := time.Parse(layout, timeStr)
			if err == nil {
				segment.ReceivedTime = t
				break
			}
		}

		if segment.ReceivedTime.IsZero() {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse time '%s'\n", timeStr)
		}
	}

	return segment, nil
}
