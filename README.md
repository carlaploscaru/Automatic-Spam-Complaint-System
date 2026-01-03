# Project 9: Automatic Spam Complaint System

# Overview

Build a tool that analyzes spam messages, extracts originating IP addresses and network
information, identifies the appropriate abuse contact, and generates personalized complaint
emails to help fight spam at its source.

# Why This Project?

This project combines email header parsing, network intelligence gathering, WHOIS lookups, and
automated report generation. You'll learn about email protocols, network abuse handling
procedures, and building tools that help maintain internet hygiene.

# User Stories

• As a user, I can paste spam email headers or full source\
• As a user, I can see the complete trace route of the email\
• As a user, I get the abuse contact for each hop\
• As a user, I receive a generated complaint email with evidence\
• As a user, I can customize complaint templates\
• As a user, I can track which complaints I've sent\

# Technical Requirements

• Parse email headers to extract routing information\
• Identify originating IP addresses and intermediate servers\
• Perform WHOIS lookups to find network owners\
• Query abuse contact databases (abuse.net, WHOIS)\
• Generate complaint emails with:\
          o Evidence (headers, timestamps)\
          o Clear violation description\
          o Professional tone\
• Template system for different types of spam\
• Optional: Direct sending via SMTP\

Terminal: AutomaticSpamComplaintSystemProject/Automatic-Spam-Complaint-System/cmd ->“go run main.go” -> paste raw copie email from clipboard -> "ctrl + z" -> "enter" -> see results
UI: Automatic-Spam-Complaint-System/web/index.html -> double click
Last run method: terminal -> AutomaticSpamComplaintSystemProject/Automatic-Spam-Complaint-System/ ->“go run main.go” -> open http://localhost:8080


The UI shows a interactive interface with three tabs: "Analyse", "Edit template" and "Send and see Hystory". Before analysing a spam email we can customize the template as we wish and then save it. The email can then be analysed in the "Analyse" tab. We can paste the email into the textarea and click the "Analyse email" button to see informations about it. The results panel will apear with data such as IP, WHOIS Analysis, Email Trace Route, Generated Abuse Complaint. The email can then be saved in history by pressing the button. In the History panel we can see the sent and saved complaints with aditional informations. The complaints that were recently saved can be sent by pressing the "send" buttom from the right.