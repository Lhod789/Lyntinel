# Threat Model: payments-service

> Labelled mock. The AppSec triage checks findings against this threat model.

## Assets
- Customer PII (names, emails, partial card data)
- Payment processing credentials
- Internal admin API

## Trust boundaries
- Public internet -> API gateway
- API gateway -> payments-service
- payments-service -> database (holds PII)

## Threats (STRIDE)
- **T1 Spoofing:** stolen API keys used to impersonate the service. *Mitigation: short-lived tokens, secret rotation.*
- **T2 Tampering:** SQL injection in user lookup alters records. *Mitigation: parameterised queries.*
- **T3 Information disclosure:** dependency vulns expose PII. *Mitigation: keep deps patched, SCA scanning.*
- **T4 Elevation of privilege:** hardcoded cloud credentials grant broad access. *Mitigation: secrets manager, least privilege.*

## Known accepted risks
- axios SSRF (low reachability) accepted until next sprint.
