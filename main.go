package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"go.com/go-project/internal/parser"
	"go.com/go-project/internal/reporter"
	"go.com/go-project/internal/whoisf"
)

type AnalyzeRequest struct {
	RawEmail string `json:"rawEmail"`
}

type AnalyzeResponse struct {
	TargetIP      string `json:"targetIP"`
	AbuseEmail    string `json:"abuseEmail"`
	TraceRoute    string `json:"traceRoute"`
	ComplaintText string `json:"complaintText"`
	Error         string `json:"error,omitempty"`
}

func main() {
	fs := http.FileServer(http.Dir("./web"))
	http.Handle("/", fs)

	http.HandleFunc("/api/analyze", handleFullAnalysis)

	port := ":8080"
	fmt.Printf("Server starting at http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func handleFullAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, AnalyzeResponse{Error: "Invalid input"}, 400)
		return
	}

	
	trace, err := parser.ParseRawEmail(req.RawEmail)
	if err != nil {
		sendJSON(w, AnalyzeResponse{Error: "Parsing failed: " + err.Error()}, 500)
		return
	}

	var traceStr strings.Builder
	for i, s := range trace.Segments {
		hopNum := len(trace.Segments) - i
		traceStr.WriteString(fmt.Sprintf("Hop %d | IP: %-15s | Host: %-20s\n", hopNum, s.IP, s.Host))
	}

	// whois
	targetIP, err := whoisf.GetFirstPublicIP(trace)
	targetHost := ""
	if err != nil {
		targetIP = trace.OriginatingSegment.IP
		targetHost = trace.OriginatingSegment.Host
	} else {
		for _, s := range trace.Segments {
			if s.IP == targetIP {
				targetHost = s.Host
				break
			}
		}
	}

	whoisResult, _ := whoisf.PerformWhoisLookup(targetIP, targetHost)
	abuseEmail, _ := whoisf.ExtractAbuseEmail(whoisResult)
	if abuseEmail == "" { abuseEmail = "Not Found" }

	reportData := &reporter.ComplaintData{
		Trace:       trace,
		RawEmail:    req.RawEmail,
		TargetIP:    targetIP,
		WhoisResult: whoisResult,
		AbuseEmail:  abuseEmail,
	}
	complaint, _ := reporter.GenerateComplaint(reportData)

	sendJSON(w, AnalyzeResponse{
		TargetIP:      targetIP,
		AbuseEmail:    abuseEmail,
		TraceRoute:    traceStr.String(),
		ComplaintText: complaint,
	}, 200)
}

func sendJSON(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}