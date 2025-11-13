9. Project: Automatic Spam Complaint System

Architecture Scheme:

USER ─────────> Console/UI  ─────────> add input email
                            |               |
                            |   email header gets extracted 
                            |               |
                            |    original IP is identified
                            |
                            └─────────> get abuse contact (WHOIS)
                            └─────────> receive generated complaint email 
                            |                           |
                            |                      customizable
                            |                           |
                            |               save complaint in database
                            |                           |
                            |                      send complaint
                            |
                            └─────────> see complaints list(track which complaints were sent)


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


2. WHOIS





