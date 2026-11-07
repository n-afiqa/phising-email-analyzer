# Sample emails

Place saved `.eml` files here for local testing. The analyzer processes one file at a time and runs DNS checks by default. If a VirusTotal API key is configured, URLs and domains are also sent to VirusTotal to look up existing reports. Use `--offline-checks` to disable network lookups, and avoid online checks for sensitive messages unless sharing their domains and URLs is acceptable.

## Guidelines

- Prefer synthetic or redacted messages. Strip personal data before committing samples.
- Include a mix of benign, suspicious, malformed, and incomplete messages when adding fixtures.
- Do not commit live phishing payloads that contain credentials, malware, or victim identifiers.

## Suggested cases

| File idea | What it exercises |
| --- | --- |
| Benign newsletter | Clean headers, matching links, passing auth |
| Brand impersonation | Display-name / lookalike sender domain |
| Link mismatch | Anchor text that does not match `href` |
| IP / shortener URL | Suspicious URL patterns |
| Missing auth headers | Incomplete email; no points for unavailable checks |

This repository ships a few synthetic examples next to this file for CLI smoke tests.
