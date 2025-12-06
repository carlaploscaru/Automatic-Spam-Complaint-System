// package main

// import (
//     "fmt"
//     "go.com/go-project/internal/example"
// )

// func main() {
//     fmt.Println("Starting Go Project...")
//     example.SayHello()
// }





// package main

// import (
// 	"bufio"
// 	"fmt"
// 	"os"
// 	"strings"
// 	"time"

// 	"go.com/go-project/internal/parser"
// )

// func main() {
// 	fmt.Println("Paste full email(headers + body). Ctrl+D/Ctrl+Z(Windows) = end of file.")

// 	scanner := bufio.NewScanner(os.Stdin)
// 	var rawInput string

// 	for scanner.Scan() { //Read input line by line until ctrl Z
// 		rawInput += scanner.Text() + "\n"
// 	}

// 	if err := scanner.Err(); err != nil {
// 		fmt.Fprintf(os.Stderr, "Error reading email: %v\n", err)
// 		os.Exit(1)
// 	}

// 	if strings.TrimSpace(rawInput) == "" {
// 		fmt.Println("No input exists.")
// 		os.Exit(0)
// 	}

// 	fmt.Println("\n ----Parsing email, generating TraceRoute.")
// 	trace, err := parser.ParseRawEmail(rawInput)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Error processing email: %v\n", err)
// 		os.Exit(1)
// 	}

// 	fmt.Printf("\n Email Trace Route has %d segments\n", len(trace.Segments))

// 	for i, s := range trace.Segments { //segmentele printate de la most recipient to oldest
// 		var age string
// 		if !s.ReceivedTime.IsZero() {
// 			age = time.Since(s.ReceivedTime).Round(time.Second).String()
// 		} else {
// 			age = "-"
// 		}

// 		fmt.Printf("Segment %d since: %s:\n", i+1, age)
// 		fmt.Printf("IP: %s, Host: %s\n", s.IP, s.Host)

// 		var timeFmt string
// 		if !s.ReceivedTime.IsZero() {
// 			timeFmt = s.ReceivedTime.Format(time.RFC822)
// 		} else {
// 			timeFmt = "-"
// 		}
// 		fmt.Printf("Time: %s\n", timeFmt)

// 		fmt.Printf("Raw: %s\n", s.RawHeaderLine[:min(len(s.RawHeaderLine), 80)])
// 		fmt.Println("----------------------")
// 	}

// 	if len(trace.Segments) > 0 {
// 		origin := trace.OriginatingSegment
// 		fmt.Println("Origin:")
// 		fmt.Printf("IP: %s | Host: %s\n", origin.IP, origin.Host)
// 		fmt.Println("---")
// 	}

// }

// func min(a, b int) int {
// 	if a < b {
// 		return a
// 	}
// 	return b
// }




package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time" 

	"go.com/go-project/internal/parser"
	"go.com/go-project/internal/whoisf"
	"go.com/go-project/internal/reporter"
)

func main() {
	fmt.Println("Paste full email(headers + body). Ctrl+D/Ctrl+Z(Windows) = end of file.")

	scanner := bufio.NewScanner(os.Stdin)
	var rawInput strings.Builder
	
	for scanner.Scan() {
		rawInput.WriteString(scanner.Text())
		rawInput.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	fullRawText := rawInput.String()
	if strings.TrimSpace(fullRawText) == "" {
		fmt.Println("No input exists.")
		os.Exit(0)
	}

	fmt.Println("\n ----Parsing email, generating TraceRoute.")
	trace, err := parser.ParseRawEmail(fullRawText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error processing email: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n Email Trace Route has %d segments\n", len(trace.Segments))
	for i, s := range trace.Segments {
		age := "-"
		if !s.ReceivedTime.IsZero() {//segmentele printate de la most recipient to oldest
			age = time.Since(s.ReceivedTime).Round(time.Second).String()
		}
		
		fmt.Printf("Hop %d (Age: %s):\n", len(trace.Segments)-i, age)
		fmt.Printf("  IP/Host: %s (%s)\n", s.IP, s.Host)
		fmt.Printf("  Raw:     %s...\n", s.RawHeaderLine[:min(len(s.RawHeaderLine), 60)])
		fmt.Println("---")

		
	}
	
	fmt.Printf("Identified Last Recorded IP (Originator): %s \n", trace.OriginatingSegment.IP)
	fmt.Println("-----------------------------------\n")


	fmt.Println("WHOIS ")
	
	targetIP, err := whoisf.GetFirstPublicIP(trace)
	if err != nil {
		fmt.Printf("WARNING: %v\n", err)
	}
	
	whoisResult, lookupErr := whoisf.PerformWhoisLookup(targetIP)
	
	abuseEmail, extractErr := whoisf.ExtractAbuseEmail(whoisResult)
	if extractErr != nil {
		fmt.Printf("WARNING: %v\n", extractErr)
		abuseEmail = "[NOT FOUND: Please manually check the WHOIS record for the abuse contact email address.]"
	}

	// Display the results of Stage 2
	fmt.Println("\n--- NETWORK RESULTS ---")
	if lookupErr != nil {
		fmt.Printf("[CRITICAL WARNING] WHOIS Lookup failed. The provided WHOIS result will be incomplete. Error: %v\n", lookupErr)
	}
	fmt.Printf("WHOIS Target IP: %s\n", targetIP)
	fmt.Printf("Extracted Abuse Email: %s\n", abuseEmail)
	fmt.Println("--- RAW WHOIS RECORD (Snippet) ---")
	fmt.Println(whoisResult[:min(len(whoisResult), 250)])
	fmt.Println("--------------------------------------\n")
	
	
	fmt.Println(" Complaint Report")
	
	reportData := &reporter.ComplaintData{
		Trace:       trace,
		RawEmail:    fullRawText,
		TargetIP:    targetIP,
		WhoisResult: whoisResult,
		AbuseEmail:  abuseEmail,
	}
	
	complaint, err := reporter.GenerateComplaint(reportData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n Complaint generation failed: %v\n", err)
		os.Exit(1)
	}


	fmt.Println(" FINAL COMPLAINT REPORT READY")
	fmt.Println(complaint)
	fmt.Println("can be sent, by copy paste")
}

// Simple helper to prevent slicing panics
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}