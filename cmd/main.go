// package main

// import (
//     "fmt"
//     "go.com/go-project/internal/example"
// )

// func main() {
//     fmt.Println("Starting Go Project...")
//     example.SayHello()
// }

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"go.com/go-project/internal/parser"
)

func main() {
	fmt.Println("Paste full email(headers + body). Ctrl+D/Ctrl+Z(Windows) = end of file.")

	scanner := bufio.NewScanner(os.Stdin)
	var rawInput string

	for scanner.Scan() { //Read input line by line until ctrl Z
		rawInput += scanner.Text() + "\n"
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading email: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(rawInput) == "" {
		fmt.Println("No input provided. Exiting.")
		os.Exit(0)
	}

	fmt.Println("\n 1. Parsing email headers and generating TraceRoute.")
	trace, err := parser.ParseRawEmail(rawInput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error processing email: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n Email Trace Route (%d segments)\n", len(trace.Segments))

	for i, s := range trace.Segments { //segmentele printate de la most recipient to oldest
		var age string
		if !s.ReceivedTime.IsZero() {
			age = time.Since(s.ReceivedTime).Round(time.Second).String()
		} else {
			age = "-"
		}

		fmt.Printf("Segment %d (Age: %s):\n", i+1, age)
		fmt.Printf("  IP,Host: %s,%s)\n", s.IP, s.Host)

		var timeFmt string
		if !s.ReceivedTime.IsZero() {
			timeFmt = s.ReceivedTime.Format(time.RFC822)
		} else {
			timeFmt = "N/A"
		}
		fmt.Printf("  Time: %s\n", timeFmt)

		fmt.Printf("  Raw: %s\n", s.RawHeaderLine[:min(len(s.RawHeaderLine), 80)])
		fmt.Println("++++++++++++++")
	}

	if len(trace.Segments) > 0 {
		origin := trace.OriginatingSegment
		fmt.Println("||| Identify Origin |||")
		fmt.Printf("IP: %s | Host: %s\n", origin.IP, origin.Host)
		fmt.Println("--------------")
	}

}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
