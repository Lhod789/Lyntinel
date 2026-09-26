# Architecture: payments-service (SIMULATED)

> Labelled mock. The threat-modelling assistant reads this alongside the threat
> model to suggest trust boundaries, threats, and test cases. In production this
> would be a real architecture doc / C4 diagram / OpenAPI spec.

## Components
- **Portal** (public web app) - customer-facing, internet-exposed.
- **Identity Service** - issues JWTs, supports an admin impersonation endpoint.
- **payments-service** - processes payments, holds PII + partial card data.
- **Database** - stores customer PII and payment metadata.

## Data flows
1. Portal -> Identity Service : authentication, token issuance.
2. Portal -> payments-service : authenticated payment requests (Bearer JWT).
3. payments-service -> Database : reads/writes customer + payment records.
4. Admin -> Identity Service `/auth/impersonate` : impersonate a user (privileged).

## API surface (partial)
- `POST /auth/login`
- `POST /auth/impersonate`   (admin-only, impersonation)
- `GET  /payments/{id}`
- `POST /payments`

## Notes
- No rate limiting currently on `/auth/login`.
- Impersonation authorisation is enforced in the controller, not in middleware.
