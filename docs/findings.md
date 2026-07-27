# Findings

Defects found while hardening this project, and how each surfaced. The interest
is less in the bugs than in what caught them: most were invisible to the tests
that existed at the time, and several were only reachable by running the thing
rather than reading it.

Every entry below has a test that fails if it comes back.

---

## Any signed-in user could read and modify any other

`SecurityConfig` matched `"/api/v1/users"` exactly, so `/api/v1/users/{id}` fell
through to `anyRequest().authenticated()`. A `USER` token was enough to read any
account and to `PUT` new roles onto it.

**How it surfaced.** Walking the authorization matrix by hand with three tokens,
one role at a time. The rule looked right in isolation; only the matrix showed
the gap between the two paths.

**Now.** `/api/v1/users/**`, and `AuthorizationMatrixIT` runs every role against
every endpoint, so a rule that covers one path and not its children fails.

---

## Deleting a user destroyed a role for everyone else

`UserEntity` mapped its roles with `CascadeType.ALL`. Roles are a shared
catalogue, so removing a user removed the *role itself*, stripping it from every
other user who had it.

**How it surfaced.** Reproduced live during an end-to-end pass: delete a manager,
then list users, and everyone who had been a `MANAGER` had no role at all.

**Why it matters.** The blast radius is unbounded and the damage is silent —
nothing errors, the catalogue is just smaller than it was.

**Now.** No cascade. The database keeps `ON DELETE CASCADE` on `users_roles`,
which removes the *link* and never the role, and a test deletes a user and then
asserts the role can still be granted.

---

## A refresh token authenticated any request

`JwtAuthenticationFilter` verified the signature and the expiry, but not the
`token_type` claim. A refresh token therefore worked as a bearer credential:
a 15 minute session became a 15 day one, and rotation could be skipped entirely
by never calling `/refresh`.

**How it surfaced.** Asking what the two token types actually differ by, and
finding that the answer was "nothing the filter checks".

**Now.** Both directions are enforced — an access token is refused at `/refresh`
too — and `TokenSecurityIT` covers each.

---

## Failed logins said which usernames existed

Account state is checked before the password, so a disabled account produced a
different message from a wrong password. That is an enumeration oracle: it
confirms a username exists.

**Now.** Every failure answers the same `401 "Bad credentials"`. The real reason
goes to `security.log`. A test strips the timestamp and trace id from two
different failures and asserts the remaining bodies are byte-identical.

---

## Rotating `X-Forwarded-For` walked past the rate limiter

`X-Forwarded-For` is a request header: anyone can send it. Trusting it
unconditionally meant a fresh bucket per request, which is worse than having no
limiter, because the control appears to exist.

**Now.** Honoured only when `app.trust-proxy` is explicitly enabled. The
regression test rotates the header on every attempt and asserts the limit still
bites.

---

## The audit trail filled with normal client behaviour

A duplicate username is a legitimate `409`. It was producing two `ERROR` entries
at `severity=HIGH`. A malformed JWT sent by a client was logged as
`SYSTEM_ERROR`. Meanwhile a privilege escalation attempt — the single most
security-relevant event these endpoints can produce — never reached
`security.log` at all, landing in `error.log` as `UNEXPECTED_ERROR`.

**Why it matters.** A file that fills with routine client mistakes stops being
read, and then a real fault goes unnoticed. Classification is not about
severity, it is about whose fault it is.

**Now.** Business exceptions are classified as such, escalation attempts are
`AUTHORIZATION_DENIED` in `security.log`, and `AuditLoggingIT` asserts *which
file* each event lands in, along with its MDC.

---

## `isTokenExpired` could never return true

```java
return extractExpiration(token).before(Date.from(Instant.now()));
```

Parsing an expired token throws `ExpiredJwtException` instead of returning its
claims, so the method could only return `false` or blow up. It was unused, which
is why nobody had noticed.

**How it surfaced.** Writing a unit test for it. The test was the first caller
that had ever passed it an actually expired token.

---

## Everything outside `/api/` answered 400

`spring.mvc.apiversion.use.path-segment: 1` runs for every request the main
handler mapping sees, not only for the API. Any other path either had no second
segment (`/swagger-ui.html`) or had one that is not a version (`/v3/api-docs`),
and both are rejected.

**How it surfaced.** Adding Swagger. Nothing else had ever requested a path
outside `/api/v1/...`, and actuator has its own handler mapping, so the whole
application looked fine.

**Now.** `ApiVersioningConfig` scopes the rule to `/api/**`. Unknown versions are
still rejected: an authenticated `/api/v9/users` answers `400`.

---

## The filter chain answered outside the error contract

`@ControllerAdvice` only sees what reaches a controller, so everything the
security chain rejected escaped the shared error shape. Three consequences:

- Authentication failures answered `403`, indistinguishable from a missing role.
  A client could not tell "refresh your token and retry" from "you will never be
  allowed to do this".
- Those responses had **no body at all**.
- The rate limiter's `429` had a shape of its own, so a client had to parse two
  kinds of error.

**How it surfaced.** Writing the OpenAPI document. Describing the responses made
it obvious the description and the behaviour disagreed.

**Now.** A `RestAuthenticationEntryPoint`, a `RestAccessDeniedHandler` and the
rate limiter all write through one `ErrorResponseWriter`, using the
application's own `JsonMapper` — so a failure raised in a filter is
indistinguishable from one raised in a controller.

---

## Tripping the rate limiter left no trace

The limiter ran before the filter that establishes the trace id, so a `429`
carried none. Worse, the rejection was not logged anywhere: a brute-force attempt
that actually hit the limit was visible only to the attacker.

**How it surfaced.** An assertion in the Postman collection, checking the `429`
against the error contract the documentation claims.

**Now.** `MdcFilter` runs first, so a trace id exists before anything can reject
a request; `JwtAuthenticationFilter` adds the user once it has authenticated one,
which keeps attribution intact. The limiter writes `RATE_LIMIT_EXCEEDED` to
`security.log`.

---

## A clean clone could not start on Linux

The container runs as a non-root user and compose bind-mounted `./logs`. Docker
creates a missing bind-mount directory owned by root, so on any host without that
directory the application could not open its log files and refused to start.

**How it surfaced.** The first real CI run. It had been simulated locally, but
against a machine where `./logs` already existed — so the simulation never
exercised the condition that fails.

**Why it matters.** It broke the project's own quickstart for everyone who was
not already running it.

**Now.** A named volume, which Docker seeds from the image, ownership included.

---

## Three more that only exist on a Linux host

Found by putting the pipeline together, all of them invisible on Windows:

- **`mvnw` was committed without the executable bit** (`100644`). `./mvnw verify`
  would have failed with `Permission denied` on the first CI run.
- **`openssl rand -base64 64` returns two lines** — openssl wraps at 64
  characters. Pasted into `.env` it is invalid; copying only the first line gives
  48 bytes, which JJWT quietly signs with HS384 instead of HS512.
- **On Git Bash for Windows, openssl ends lines with CRLF**, so `tr -d '\n'`
  leaves a carriage return inside the key and the application refuses to start
  with `Illegal base64 character`. Reproduced against a running stack.

---

## What caught what

| | |
|---|---|
| Running the API by hand, end to end | the authorization gap, the cascade, the enumeration oracle |
| Writing a test for existing code | `isTokenExpired` |
| Writing the OpenAPI contract | versioning outside `/api/`, the `401`/`403` conflation, the empty bodies |
| Writing the Postman collection | the unaudited rate limit |
| Running CI for the first time | the logs volume, the executable bit, the secret generation |

The pattern is that documenting or automating something forces a claim to be
stated precisely, and a precise claim is checkable. Most of these were found by
writing down what the system was supposed to do.
