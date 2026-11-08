# Caveman.PrivacyGuard.Mcp

MCP (Model Context Protocol) server for Caveman.PrivacyGuard. It exposes PII detection and masking, reversible
session masking, prompt-injection screening and an AI transparency notice as tools for Claude Code, Cursor and any
other MCP client.

Version 1.5.0 targets .NET 10 and uses Caveman.PrivacyGuard 1.5.0.

## Install

    dotnet tool install -g Caveman.PrivacyGuard.Mcp

Register it in your MCP client as a stdio server whose command is caveman-privacyguard-mcp.

## Tools

| Tool | Description |
| :--- | :--- |
| analyze_text | Detects and scores PII and sensitive data in 32 countries; returns compliance flags (GDPR, AI Act, NIS2, PCI-DSS, NIST) |
| mask_text | Masks sensitive data; with a sessionId the placeholders are unique and restorable |
| restore_text | Restores the original values in a model answer, given the sessionId used to mask |
| check_prompt_injection | Screens untrusted text for prompt-injection attempts before it reaches a model |
| get_ai_transparency_notice | Returns a localized disclosure that the user is talking to an AI system |

Use a distinct sessionId for each conversation so that different conversations never share placeholders.

## New in 1.5.0

| Change | Effect on analyze_text and mask_text |
| :--- | :--- |
| Anti-triggers | A number next to invoice, order, article code or protocol is no longer read as a phone number |
| Printed IBAN | Grouped IBANs are masked whole |
| New categories | IP address, URL, monetary amount, date of birth, document protocol number |
| Italian VAT | Corrected checksum: valid numbers are detected |
| .NET 10 | The tool targets net10.0 |

## Disclaimer

analyze_text, check_prompt_injection and get_ai_transparency_notice are technical aids, not a compliance or security
guarantee.

## License

MIT. See the LICENSE file in the package.
