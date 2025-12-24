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
		
		hopNum := len(trace.Segments) - i
		fmt.Printf(" Hop %d | IP: %-15s | Host: %-20s | Age: %s\n", hopNum, s.IP, s.Host, age)

		
	}
	
	fmt.Printf("Identified Last Recorded IP (Originator): %s \n", trace.OriginatingSegment.IP)



	fmt.Println("WHOIS ")
	
	targetIP, err := whoisf.GetFirstPublicIP(trace)
	targetHost := ""

		if err != nil {
		fmt.Printf("NOTICE: %v. Using originator as fallback.\n", err)
		targetIP = trace.OriginatingSegment.IP
		targetHost = trace.OriginatingSegment.Host
	} else {
		// Find associated hostname for the public IP found
		for _, s := range trace.Segments {
			if s.IP == targetIP {
				targetHost = s.Host
				break
			}
		}
	}
	
	whoisResult, lookupErr := whoisf.PerformWhoisLookup(targetIP, targetHost)
	if lookupErr != nil {
		fmt.Printf("WHOIS Error: %v\n", lookupErr)
	}

	// extract abuse contact
	abuseEmail, extractErr := whoisf.ExtractAbuseEmail(whoisResult)
	if extractErr != nil {
		fmt.Printf("WARNING: %v\n", extractErr)
		abuseEmail = "not found."
	}

	// results stage 2
	fmt.Println("\n--- RESULTS ---")
	if lookupErr != nil {
		fmt.Printf("WHOIS failed. Err: %v\n", lookupErr)
	}
	fmt.Printf("WHOIS Target IP: %s\n", targetIP)
	fmt.Printf("Extracted Abuse Email: %s\n", abuseEmail)

	fmt.Println(whoisResult[:min(len(whoisResult), 250)])
	
	
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