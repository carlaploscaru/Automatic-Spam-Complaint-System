package whoisf

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	whois "github.com/likexian/whois-go"
	"go.com/go-project/internal/model"
)

func PerformWhoisLookup(ipAddress string, hostName string) (string, error) {
	fmt.Printf("WHOIS lookup for IP: %s \n", ipAddress)

	if ipAddress == "" {
		return "", fmt.Errorf("empty IP address provided")
	}

	//mock whois
	if isMockIP(ipAddress) {
		fmt.Println("Generate mock WHOIS ")
		return generateMockWhois(ipAddress), nil
	}

	//real whois
	if !IsPrivateIP(ipAddress) && ipAddress != "" {
		result, err := whois.Whois(ipAddress)
		if err == nil && (strings.Contains(result, "LEGACY") || !strings.Contains(result, "@")){
			fmt.Println("REAL WHOIS returned legacy(incomplete data). Retrying")
			detailedResult, errDetail := whois.Whois("n + " + ipAddress)
			if errDetail == nil {
				result = detailedResult
			}
		}
		if err == nil {
			fmt.Println("REAL WHOIS data retrieved.")
			return result, nil
		}
		fmt.Printf("Real WHOIS failed: %v. Try buse.net\n", err)
	} else {
		fmt.Println("IP is private. Skip WHOIS, try buse.net")
	}

	//mock abuse.net
	fmt.Printf("both whois tries failed. Abuse.net for: %s\n", hostName)
	return performAbuseNetMapping(hostName), nil

}

func generateMockWhois(ip string) string {
	return fmt.Sprintf(`
		# MOCK WHOIS for %s
		NetRange:       203.0.113.0 - 203.0.113.255
		NetName:        TEST_SPAM_NETWORK
		OrgName:        Test Spam 
		Address:        str. tmi nr. 4
		City:           TM
		Country:        RO
		RegDate:        2023-01-01
		OrgAbuseEmail:  abuse@simulated-spam-corp.net
		# End of Mock`, ip)
}

func performAbuseNetMapping(host string) string {
	domain := strings.ToLower(host)

	contacts := map[string]string{
		"gmail.com":     "abuse@google.com",
		"google.com":    "abuse@google.com",
		"outlook.com":   "abuse@microsoft.com",
		"microsoft.com": "abuse@microsoft.com",
		"yahoo.com":     "abuse@yahoo.com",
		"amazon.com":    "abuse@amazon.com",
	}

	for key, email := range contacts {
		if strings.Contains(domain, key) {
			return fmt.Sprintf("Abuse.net data: Domain: %s\nAbuseContact: %s\n", host, email)
		}
	}

	return fmt.Sprintf("Abuse.net no data found for Domain %s.", host)
}

// check RFC 5737
func isMockIP(ip string) bool {
	return strings.HasPrefix(ip, "203.0.113") || strings.HasPrefix(ip, "192.0.2") || strings.HasPrefix(ip, "198.51.100")
}

func ExtractAbuseEmail(record string) (string, error) {
	patterns := []string{
		`(?i)OrgAbuseEmail:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
		`(?i)abuse-mailbox:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
		`(?i)Abuse-Contact:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
		`(?i)Contact Email:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		match := re.FindStringSubmatch(record)
		if len(match) > 1 {
			return strings.TrimSpace(match[1]), nil
		}
	}

	return "", fmt.Errorf("can't find abuse contact")
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
		_, priv, _ := net.ParseCIDR("172.16.0.0/12")
		if ip != nil && priv.Contains(ip) {
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
