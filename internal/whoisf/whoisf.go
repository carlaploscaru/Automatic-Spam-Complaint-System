// package whois

// import (
// 	"fmt"
// 	"net"
// 	"regexp"
// 	"strings"
// 	"time"

// 	"go.com/go-project/internal/model"
// )

// //https://pkg.go.dev/github.com/ioj/whois-go


// // --- Core WHOIS and Extraction Logic ---

// // PerformWhoisLookup simulates a WHOIS lookup for a given IP address.
// // In a real application, this would connect to WHOIS servers.
// func PerformWhoisLookup(ipAddress string) (string, error) {
// 	fmt.Printf("--- Performing WHOIS Lookup for IP: %s ---\n", ipAddress)

// 	// Simulate network delay
// 	time.Sleep(50 * time.Millisecond)

// 	// Mock response based on the IP address
// 	if ipAddress == "203.0.113.42" {
// 		// Mock WHOIS record with the necessary abuse contact field
// 		return `
// WHOIS Record for 203.0.113.42
// NetRange:       203.0.113.0 - 203.0.113.255
// CIDR:           203.0.113.0/24
// Organization:   Spam Distribution Corp. (SDC)
// OrgName:        Spam Distribution Corporation
// OrgAbuseHandle: SPAMLORD-ABUSE-AP
// OrgAbuseEmail:  abuse@evil.com  <-- This is what we extract
// Updated:        2024-01-01
// `, nil
// 	}
	
// 	if IsPrivateIP(ipAddress) {
// 		return fmt.Sprintf("IP %s is a private/reserved address. No WHOIS available.", ipAddress), nil
// 	}

// 	// Generic success message for any other public IP
// 	return fmt.Sprintf("IP %s is a public IP. Real lookup would reveal Network Owner/Abuse Contact.", ipAddress), nil
// }

// // ExtractAbuseEmail uses a simple regex to find the most common abuse contact fields 
// // within a WHOIS record string.
// func ExtractAbuseEmail(whoisRecord string) (string, error) {
// 	// Pattern looks for common fields like OrgAbuseEmail, abuse-mailbox, or abuse-c.
// 	// It is case-insensitive and captures the email address following the colon.
// 	regex := regexp.MustCompile(`(?i)(OrgAbuseEmail|abuse-mailbox|abuse-c|abuse-contact):\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	
// 	match := regex.FindStringSubmatch(whoisRecord)
	
// 	if len(match) > 2 {
// 		// The captured email is at index 2 of the submatches
// 		return strings.TrimSpace(match[2]), nil
// 	}

// 	return "", fmt.Errorf("could not reliably extract abuse contact email from WHOIS record")
// }

// // --- IP Analysis and Selection Logic (The core intelligence) ---

// // IsPrivateIP checks if an IP belongs to standard private/reserved ranges (RFC 1918).
// func IsPrivateIP(ipStr string) bool {
// 	if ipStr == "" {
// 		return false
// 	}
// 	// Check for common private ranges
// 	if strings.HasPrefix(ipStr, "127.") || strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
// 		return true
// 	}
// 	// Check 172.16.0.0/12 range
// 	if strings.HasPrefix(ipStr, "172.") {
// 		ip := net.ParseIP(ipStr)
// 		// Check for specific RFC 1918 range
// 		_, private172, _ := net.ParseCIDR("172.16.0.0/12")
// 		if ip != nil && private172 != nil && private172.Contains(ip) {
// 			return true
// 		}
// 	}
// 	return false
// }

// // GetFirstPublicIP iterates the segments from oldest to newest (the true path) and returns the IP
// // of the first server that is NOT a private IP. This is the correct target for WHOIS.
// // This implements the core intelligence gathering. 
// func GetFirstPublicIP(trace *model.EmailRouteTrace) (string, error) {
// 	// Segments are stored newest-to-oldest in the slice, so we iterate from the end (oldest hop) backwards.
// 	for i := len(trace.Segments) - 1; i >= 0; i-- {
// 		segment := trace.Segments[i]
// 		if segment.IP != "" && !IsPrivateIP(segment.IP) {
// 			return segment.IP, nil
// 		}
// 	}

// 	// Fallback to the last segment's IP if no public IP is found.
// 	if len(trace.Segments) > 0 {
// 		return trace.Segments[len(trace.Segments)-1].IP, fmt.Errorf("could not find a public IP; defaulting to last IP in trace: %s", trace.Segments[len(trace.Segments)-1].IP)
// 	}

// 	return "", fmt.Errorf("trace route is empty")
// }


package whoisf

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"go.com/go-project/internal/model"
	whois "github.com/likexian/whois-go" 
)


func PerformWhoisLookup(ipAddress string) (string, error) {
	fmt.Printf("WHOIS lookup for IP: %s \n", ipAddress)

	if IsPrivateIP(ipAddress) {
		return fmt.Sprintf("IP %s is private address. No WHOIS lookup made.", ipAddress), nil
	}

	result, err := whois.Whois(ipAddress)
	
	if err != nil {
		return fmt.Sprintf("WHOIS Failed. Error: %v\n", ipAddress, err), 
			fmt.Errorf("real WHOIS query failed: %w", err)
	}

	return result, nil
}

func ExtractAbuseEmail(whoisRecord string) (string, error) {
	regex := regexp.MustCompile(`(?i)(OrgAbuseEmail|abuse-mailbox|abuse-c|abuse-contact):\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	
	match := regex.FindStringSubmatch(whoisRecord)
	
	if len(match) > 2 {
		return strings.TrimSpace(match[2]), nil
	}

	return "", fmt.Errorf("could not reliably extract abuse contact email from WHOIS record")
}


func IsPrivateIP(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	if strings.HasPrefix(ipStr, "127.") || strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
		return true
	}
	if strings.HasPrefix(ipStr, "172.") {
		ip := net.ParseIP(ipStr)
		_, private172, _ := net.ParseCIDR("172.16.0.0/12")
		if ip != nil && private172 != nil && private172.Contains(ip) {
			return true
		}
	}
	return false
}

func GetFirstPublicIP(trace *model.EmailRouteTrace) (string, error) {
	
	for i := len(trace.Segments) - 1; i >= 0; i-- {
		segment := trace.Segments[i]
		if segment.IP != "" && !IsPrivateIP(segment.IP) {
			return segment.IP, nil
		}
	}

	if len(trace.Segments) > 0 {
		return trace.Segments[len(trace.Segments)-1].IP, fmt.Errorf("could not find public IP; adding last recorded IP in trace: %s", trace.Segments[len(trace.Segments)-1].IP)
	}

	return "", fmt.Errorf("trace route empty")
}