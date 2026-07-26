# Security model

What this API defends against, how, and what it deliberately does not cover.

## Assumptions

The API is stateless and exposed over HTTPS in production. Clients are
untrusted. The database is trusted but assumed leakable — a dump should not
hand over anything replayable. There is no admin UI: everything goes through
the same authenticated API.

## Threats and controls

### Credential theft from the browser

An XSS on a page holding the credential is the usual way accounts are lost.

The refresh token never reaches JavaScript: it is `HttpOnly`, `Secure`,
`SameSite=Strict`, and scoped to `Path=/api/v1/auth`, so it is not even attached
to ordinary API calls. The access token is reachable by page scripts by
necessity, which is why it lasts 15 minutes and cannot be used to obtain a new
refresh token.

### Replay of a stolen token

Refresh **rotates**: the old row is deleted before the new token is issued, so a
captured token works at most once. Each token is bound to the **User-Agent**
that obtained it and is refused from any other client. Logging in again from the
same client replaces that client's session rather than accumulating sessions.

A changed IP is logged and allowed — mobile networks renumber constantly, and
refusing would lock out real users far more often than attackers.

### A leaked database

Passwords are BCrypt with a `{bcrypt}` prefix through `DelegatingPasswordEncoder`,
so the algorithm can be changed later without invalidating existing hashes.

Refresh tokens are stored as **SHA-256 hex**, never raw. A dump contains no
usable session. Why a fast digest rather than BCrypt is in
[ADR 0001](adr/0001-jwt-access-plus-refresh-cookie.md).

### Forged or confused tokens

Every token is verified against the server key before anything else. A tampered
payload, a signature re-signed with another key, and an `alg=none` header are
all refused, each with its own test.

Tokens also declare a **type**. An access token is refused at `/auth/refresh`
and a refresh token is refused as a bearer credential. Without that check a
refresh token authenticated any request, turning a 15-minute session into a
15-day one and bypassing rotation entirely.

### Privilege escalation

Roles are hierarchical — `SYSTEM` > `ADMIN` > `MANAGER` > `USER` — and a caller
may only grant roles **at or below their own level**. `SYSTEM` is therefore
never assignable through the API, and an `ADMIN` cannot mint an account more
powerful than itself. Denied attempts are recorded in `security.log` as
`AUTHORIZATION_DENIED` with the acting user and IP, not swallowed as an
unexpected error.

Authorisation rules match `/api/v1/users/**`, not `/api/v1/users`. With the
exact path, `/users/{id}` fell through to `anyRequest().authenticated()` and any
signed-in user could read and modify any other, roles included.

### Account enumeration

Every failed login answers the same `401 "Bad credentials"` — wrong password,
unknown username, disabled account and locked account are indistinguishable to
the caller. Since account state is checked before the password, a specific
message would confirm the username exists. The real reason is in `security.log`.

`/auth/login` does not validate username format, for the same reason: rejecting
a malformed username early would tell an attacker it could not exist.

### Brute force and credential stuffing

Token buckets per endpoint and client IP, applied before authentication so a
rejected request costs no BCrypt comparison. `X-Forwarded-For` is honoured only
behind an explicitly trusted proxy; otherwise rotating the header would hand out
a fresh bucket per request. See [ADR 0002](adr/0002-rate-limiting-bucket4j.md).

An exhausted bucket is recorded in `security.log` as `RATE_LIMIT_EXCEEDED` with
the caller IP and a `traceId`. It is the clearest signal this service gets that
someone is guessing credentials, so it is worth more than a `429` the attacker
alone gets to see.

### Account state

`enabled` and `account_non_locked` are real columns, and the JWT filter re-reads
the user on every request. Disabling or locking an account therefore invalidates
its **live** access tokens on the next call, not fifteen minutes later.

### Information disclosure in responses

Controllers return DTOs, never entities. `UserResponse` has no field for the
password hash or the token collection, so there is nothing to leak — the OpenAPI
contract asserts this, and so does a test.

Error bodies carry a status, a safe message, the path and a `traceId`. Never a
stack trace, a class name, or a SQL fragment. The `traceId` is the bridge: a
caller quotes it and the full detail is in the logs.

### Input validation

| Field | Rule |
|---|---|
| Username | 3–50 chars, `[a-zA-Z0-9._-]` |
| Password | 8–72 chars, upper + lower + digit + symbol |

The 72-character cap is not arbitrary: **BCrypt silently ignores everything past
72 bytes**, so a longer password would be accepted and truncated, and the extra
characters would be security theatre. Rejecting it up front is honest.

Validation groups let `password` be required on create and optional on update,
where omitting it keeps the current one.

## Not covered

Stated plainly, because a security document that claims completeness is worse
than one with gaps.

- **CSRF protection is disabled.** Defensible for a bearer-token API, and
  `SameSite=Strict` covers the one cookie. A future cookie-authenticated
  endpoint would need it re-enabled.
- **No account lockout after repeated failures.** The columns exist and are
  enforced; nothing sets them automatically. Rate limiting is the only
  brute-force control.
- **No MFA, no password rotation policy, no breach-list check.**
- **No refresh-token reuse detection.** A rotated token is deleted, so replay
  fails — but the system does not treat the replay as the signal of compromise
  it is, and does not revoke the family.
- **Rate limits are per instance.** See [ADR 0002](adr/0002-rate-limiting-bucket4j.md).
- **Access tokens cannot be revoked** before expiry on endpoints that do not
  re-read the user. The 15-minute lifetime is the mitigation.
- **Secrets come from the environment.** There is no vault integration, and
  `.env` is untracked with `.env.example` as the template.

## Demo posture

This repository is a portfolio project, and a few things are set up for
explorability rather than for a real deployment. All of them are visible, not
hidden:

- **Demo accounts** (`admin` / `manager` / `user`, password `Demo1234!`) are
  seeded in every profile including `prod`, so the stack can be tried without
  someone handing over credentials. `V3__seed_users.sql` says at the top that a
  real deployment drops it or rotates them.
- **Swagger UI and `/v3/api-docs` are public.** Nobody could learn how to obtain
  a token otherwise. One property removes them:
  `springdoc.api-docs.enabled=false`.
- **The `SYSTEM` auditor account** is required by JPA auditing but is created
  disabled with a BCrypt hash of a password nobody knows. It can stamp rows and
  never authenticate.

## Verification

The controls above are not claims; each has a test that fails if it regresses.

```
166 tests · 83.1% instructions · 71.6% branches
```

The security-relevant suites, all running against a real PostgreSQL container:

| Suite | Covers |
|---|---|
| `TokenSecurityIT` | Signature, payload, forged key, `alg=none`, token type confusion |
| `PrivilegeEscalationIT` | The ceiling on grantable roles, `SYSTEM` unreachable |
| `AuthorizationMatrixIT` | Every role against every `/users` endpoint, `401` vs `403` |
| `AccountStateIT` | Disabled and locked accounts, indistinguishable answers |
| `RateLimitingIT` | Bucket capacity, `Retry-After`, `X-Forwarded-For` spoofing |
| `AuditLoggingIT` | Which log each event lands in, and its MDC |
| `ErrorResponseIT` | The error contract, and that no internals leak |
