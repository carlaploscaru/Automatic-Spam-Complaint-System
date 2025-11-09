9. Project: Automatic Spam Complaint System

Current Structure of directory 

Automatic-Spam-Complaint-System/
├── cmd/
│ └── main.go 
├── internal/ 
│ └── example/
│ └── package.go 
| └── model/
| └── model.go 
| └── parser/
| └── parser.go 
├── tests/
│ └── example_test.go 
├── docs/
│ ├── architecture.md 
│ ├── decisions.md 
│ └── screenshots/
│ └── generateTraceRouteTest.png 
| └── email.txt
├── go.mod 
└── README.md 

1. First step implemented: Parsing email, generating TraceRoute.
• As a user, I can paste spam email headers or full source
• As a user, I can see the complete trace route of the email
using 
• Parse email headers to extract routing information
• Identify originating IP addresses and intermediate servers

Files used for implementing: 
• /internal/model/model.go (defies the structure of the data using "struct" and creates 3 categories for: one segment(ServerSegment), all segments(EmailRouteTrace) and new generated email(ComplaintReport))
• /internal/parser/parser.go (contains 2 functions: ParseRawEmail() and parseReceivedLine())
• /cmd/main.go (main gets the full email input and calls parser.ParseRawEmail function from parser.go to convert the input email text into the structured EmailRouteTrace form from model.go)


Flow scheme:
add input email into console -> extract email header -> parse email header -> identify origin IP 

2. WHOIS
