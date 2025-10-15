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

