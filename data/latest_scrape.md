---
timestamp: 2024-12-19T16:47:32Z
source: https://news.ycombinator.com
---

# TTP Description

The HTML content provided is from Hacker News, a technology news aggregation website. However, one article stands out as security-relevant:

**Obsidian Plugin Abuse Campaign**: A malicious campaign that abused an Obsidian plugin to deploy a remote access trojan (RAT) called "Phantom Pulse RAT."

# IOCs (Indicators of Compromise)

## Malware Names
- **Phantom Pulse RAT** - Remote Access Trojan deployed via compromised Obsidian plugin

## Domains
- **netsecops.io** - Source reporting the security incident
- **cyber.netsecops.io** - Full URL path for the security report

## File/Application Names
- **Obsidian plugin** - The attack vector used to deliver the RAT

# TTP Uniqueness Assessment

The use of Obsidian plugins as an attack vector appears to be a relatively novel approach. Obsidian is a popular note-taking application that supports community plugins, and targeting its plugin ecosystem represents an interesting supply chain attack vector that may not have been widely observed before.

# Threat Actor and Tooling Information

## Threat Actor
- **Unknown/Unspecified** - The reporting article does not provide specific attribution to known threat actors

## Tools and Techniques
- **Attack Vector**: Malicious Obsidian plugin
- **Payload**: Phantom Pulse RAT
- **Technique**: Supply chain compromise through plugin ecosystem
- **Target Application**: Obsidian (note-taking software)

## Campaign Details
- The campaign specifically targeted users of the Obsidian note-taking application
- Used the plugin distribution mechanism as a delivery method
- Successfully deployed remote access capabilities through the Phantom Pulse RAT

*Note: The majority of the HTML content consists of standard Hacker News article listings and does not contain security-relevant TTPs or IOCs beyond the single security-focused article mentioned above.*
