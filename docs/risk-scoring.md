# Risk scoring

The score adds points for evidence-backed findings from message headers, URLs,
and (when enabled) VirusTotal. Each finding category contributes at most once,
even if multiple examples are found, and the total is capped at 100.

| Finding | Points |
| --- | ---: |
| VirusTotal reports a malicious URL | +35 |
| VirusTotal reports a malicious sender domain | +25 |
| Displayed link text materially misleads about its destination | +20 |
| DMARC authentication failure | +15 |
| Sender domain looks like a known brand | +15 |
| SPF failure | +10 |
| DKIM failure | +10 |
| Suspicious URL pattern (for example, IP host or URL shortener) | +10 |
| From domain differs from Reply-To or Return-Path domain | +10 |

Only explicit SPF, DKIM, or DMARC failures score points. Missing authentication
results, unavailable lookups, and DNS record presence do not. Repeated findings
within a category are counted once.

| Score | Category |
| --- | --- |
| 0–19 | Low |
| 20–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

A low score does not prove an email is safe.
