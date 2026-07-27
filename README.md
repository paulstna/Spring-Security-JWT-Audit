# Spring Security JWT Audit

A stateless REST API built to get the security details right, and to prove it:
JWT authentication with rotating refresh tokens in `HttpOnly` cookies,
hierarchical role authorization, per-IP rate limiting, and an audit trail that
records who did what, from where, and whether it worked.

[![CI](https://github.com/PaulStna/Spring-Security-JWT-Audit/actions/workflows/ci.yml/badge.svg)](https://github.com/PaulStna/Spring-Security-JWT-Audit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/PaulStna/Spring-Security-JWT-Audit/actions/workflows/codeql.yml/badge.svg)](https://github.com/PaulStna/Spring-Security-JWT-Audit/actions/workflows/codeql.yml)
![Java 21](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)
![Spring Boot 4.0](https://img.shields.io/badge/Spring%20Boot-4.0-6DB33F?logo=springboot&logoColor=white)
![PostgreSQL 17](https://img.shields.io/badge/PostgreSQL-17-4169E1?logo=postgresql&logoColor=white)
![Tests](https://img.shields.io/badge/tests-166%20passing-success)
![Coverage](https://img.shields.io/badge/coverage-83%25-success)

---

## Try it in two minutes

```bash
git clone https://github.com/PaulStna/Spring-Security-JWT-Audit.git
cd Spring-Security-JWT-Audit
cp .env.example .env      # generate your own JWT_SECRET_KEY, see below
docker compose up -d
```

Open **<http://localhost:8080/swagger-ui.html>**.

1. `POST /api/v1/auth/login` → **Try it out**. The body is pre-filled with a
   demo account.
2. Copy `authToken` from the response.
3. **Authorize** (top right) → paste it.
4. `GET /api/v1/users` now answers `200`.

| Account | Role | Password |
|---|---|---|
| `admin` | `ADMIN` | `Demo1234!` |
| `manager` | `MANAGER` | `Demo1234!` |
| `user` | `USER` | `Demo1234!` |

Seeded by a Flyway migration in every profile, so the deployed stack is
explorable without anyone handing over credentials. See
[demo posture](docs/SECURITY.md#demo-posture) for what that means and how to
turn it off.

Generate a signing key with:

```bash
openssl rand -base64 64 | tr -d '\r\n'
```

The secret is read as Base64. Two details bite here. Openssl wraps base64 at 64
characters, and on Git Bash for Windows it ends lines with CRLF, so without
stripping both the value spans two lines or hides a carriage return and the
application refuses to start with `Illegal base64 character`. And it needs to be
at least 64 bytes: JJWT picks the strongest algorithm a key supports, so a
shorter one quietly signs with HS384 instead of HS512.

---

## If you have five minutes

Start with **[docs/findings.md](docs/findings.md)** — the defects found while
hardening this, and what caught each one. It is the most honest thing in the
repository: a signed-in user could once read and modify any other account, a
refresh token authenticated any request, and deleting a user destroyed a role
for everyone else. Each has a test that fails if it comes back.

Then, if you want code:

| | |
|---|---|
| [`SecurityConfig`](SpringSecurityApp/src/main/java/com/paulstna/springsecurityapp/security/SecurityConfig.java) | The filter chain and the rules, including the `401`/`403` split |
| [`AuthServiceImpl.refreshToken`](SpringSecurityApp/src/main/java/com/paulstna/springsecurityapp/auth/service/AuthServiceImpl.java) | Rotation, and every reason a token is refused |
| [`AuditLoggingIT`](SpringSecurityApp/src/test/java/com/paulstna/springsecurityapp/audit/AuditLoggingIT.java) | Asserts *which log* each event lands in, not just that it was logged |
| [`OpenApiConventions`](SpringSecurityApp/src/main/java/com/paulstna/springsecurityapp/common/config/OpenApiConventions.java) | `429` is documented only where the limiter is configured, read from the same properties the filter uses |

---

## What is interesting here

**Refresh tokens rotate and are stored hashed.** Every refresh deletes the old
row before issuing the new one, so a stolen token works at most once — and only
from the client that obtained it, since sessions are bound to the User-Agent.
The database holds `SHA-256(token)`, so a dump contains nothing replayable.

**Tokens declare their type.** An access token is refused at `/auth/refresh`,
and a refresh token is refused as a bearer credential. Without that check a
refresh token authenticates any request, turning a 15-minute session into a
15-day one and skipping rotation entirely.

**`401` and `403` mean different things.** One says refresh your token and
retry; the other says you will never be allowed. Both carry the same JSON body
as every other failure, `traceId` included — including the ones produced by
filters, which normally escape `@ControllerAdvice` and come back empty.

**Failed logins are indistinguishable.** Wrong password, unknown user, disabled
account and locked account all answer the same `401`. Account state is checked
before the password, so a specific message would confirm the username exists.
The real reason goes to `security.log`.

**Roles have a ceiling.** A caller may only grant roles at or below their own
level, so an `ADMIN` cannot mint a `SYSTEM` account. Attempts are recorded as
security events, not swallowed as unexpected errors.

**The audit trail is classified, and tested as such.** A duplicate username is a
client mistake and stays out of `error.log`; a privilege escalation attempt
lands in `security.log` with its MDC intact. `AuditLoggingIT` asserts which file
each event reaches — because a log that fills with normal client behaviour stops
being read.

---

## Endpoints

Full contract: [Swagger UI](http://localhost:8080/swagger-ui.html) when running,
or the committed [`docs/openapi.json`](docs/openapi.json).

### Authentication

| | Endpoint | Notes |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Creates a `USER` account and signs it in |
| `POST` | `/api/v1/auth/login` | Returns an access token, sets the refresh cookie |
| `POST` | `/api/v1/auth/refresh` | Rotates the refresh token, returns a new access token |
| `POST` | `/api/v1/auth/logout` | Revokes the session, clears the cookie |

All four are rate limited per client IP and answer `429` with `Retry-After`.

### Users

Every operation needs `Authorization: Bearer <token>`. Roles are hierarchical,
so `ADMIN` satisfies anything `MANAGER` can do.

| | Endpoint | Requires |
|---|---|---|
| `GET` | `/api/v1/users` | `MANAGER` |
| `GET` | `/api/v1/users/{id}` | `MANAGER` |
| `POST` | `/api/v1/users` | `ADMIN` |
| `PUT` | `/api/v1/users/{id}` | `MANAGER` |
| `DELETE` | `/api/v1/users/{id}` | `ADMIN` |

### One error shape

```json
{
  "timestamp": "2026-07-25T23:22:14.883Z",
  "status": 401,
  "message": "Authentication required",
  "path": "/api/v1/users",
  "traceId": "f06d14a1-1dee-454f-9822-6b3d0c18a985"
}
```

`fieldErrors` is added on a validation failure. The `traceId` matches the log
entry, so a caller can quote it and the exact request is one `grep` away.

---

## Postman

Import both files from [`postman/`](postman):

```
postman/Spring-Security-JWT-Audit.postman_collection.json
postman/environment.demo.json
```

Select the environment, run **Auth → Login (admin)**, and every other request is
authenticated: the login test script stores the token, so nothing is copied by
hand. The refresh token is never handled manually either — it arrives in an
`HttpOnly` cookie and Postman's cookie jar sends it back.

It is not a click-through. All 21 requests carry assertions, so running the
whole collection is a live check of the API:

```bash
newman run postman/Spring-Security-JWT-Audit.postman_collection.json \
       -e postman/environment.demo.json
# 22 requests, 57 assertions, 0 failures
```

The **Failure cases** folder is the interesting half: `401` versus `403`, a
refresh token refused as a bearer, an `ADMIN` unable to mint a `SYSTEM` account,
two failed logins proven byte-identical, and a validation error listing its
fields. Each one documents a control that exists for a reason.

**Rate limiting** is last on purpose — it calls itself until the login bucket is
empty, then asserts the `429` and its `Retry-After`. Wait a minute before
signing in again.

---

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | How a request travels, package layout, profiles |
| [Authentication flows](docs/auth-flow.md) | Login, refresh rotation and logout, step by step |
| [Data model](docs/er-diagram.md) | Schema, and why each column is what it is |
| [Security model](docs/SECURITY.md) | Threats, controls, and what is **not** covered |
| [Design decisions](docs/adr/README.md) | ADRs: the alternatives and what each choice costs |
| [Findings](docs/findings.md) | Defects found while hardening this, and what caught each |

---

## Running the tests

```bash
cd SpringSecurityApp
./mvnw test      # unit tests only, no Docker needed
./mvnw verify    # everything, including integration tests
```

`verify` needs Docker running: integration tests start a real **PostgreSQL 17**
container, the same image `compose.yaml` uses. Not H2 — that way the Flyway
migrations, the `ddl-auto=validate` check and Postgres-specific SQL are all
exercised as deployed.

```
166 tests · 83.1% instructions · 71.6% branches · 85.0% lines
```

JaCoCo fails the build below 75% / 65%, in CI as well as locally, so the number
above cannot quietly rot. The report lands in `target/site/jacoco/index.html`.

Every regression found while hardening this project has a test that documents
why it exists: the refresh token refused as a bearer, `/users/{id}` protected,
the role catalogue surviving a user deletion, identical answers for every failed
login, `X-Forwarded-For` not buying extra attempts.

---

## Continuous integration

Two jobs, answering two different questions.

**Build and test** runs `./mvnw verify` — the 166 tests, against a real
PostgreSQL container, with the coverage gate enforced. Coverage lands in the run
summary; on a failure the surefire and failsafe reports are uploaded, because
the console output is too terse to debug from.

**Smoke test the deployable image** builds the Docker image, brings the compose
stack up on the `prod` profile, waits for `/actuator/health`, and runs the
Postman collection against it with newman.

That second job exists because the first one cannot fail for the right reasons.
The tests use `MockMvc`: no servlet container, no socket, no image. A broken
`Dockerfile`, a mistyped compose variable, a profile that never reaches the
container or a datasource that dies on startup would all leave the suite green.
It happened during development — the tests passed while the running container
was three commits behind. The job finishes by printing the `security.log` the
run produced into the summary, so the audit trail is visible from the CI page.

**CodeQL** runs `security-extended` on every push and weekly. The schedule
matters as much as the push trigger: new query packs ship regularly and can flag
code nobody has touched.

**Dependabot** watches Maven, the Dockerfile base images and the workflow
actions. A published CVE in a dependency is the most likely way this becomes
insecure without anyone changing a line of it.

---

## Stack

**Java 21** · **Spring Boot 4.0** · Spring Security · Spring Data JPA ·
**PostgreSQL 17** · Flyway · JJWT · Bucket4j + Caffeine · AspectJ · Logback ·
springdoc-openapi · Testcontainers · JaCoCo · Docker Compose

---

## Configuration

Everything comes from `.env`; `.env.example` is the template.

| Variable | Default | |
|---|---|---|
| `SPRING_PROFILES_ACTIVE` | `prod` | `dev` allows the cookie over plain HTTP and logs at `DEBUG` |
| `JWT_SECRET_KEY` | — | Required, Base64. `openssl rand -base64 64` |
| `JWT_AUTH_EXPIRATION` | `900` | Access token lifetime, seconds |
| `JWT_REFRESH_EXPIRATION` | `1296000` | Refresh token lifetime, seconds |
| `DB_NAME` / `DB_USERNAME` / `DB_PASSWORD` | — | PostgreSQL credentials |

The profile defaults to `prod` on purpose: a missing entry can never silently
downgrade cookie security.

Rate limits and the endpoints they apply to live in `application.yml` under
`bucket`. `app.trust-proxy` (default `false`) controls whether
`X-Forwarded-For` is honoured — leave it off unless a proxy overwrites the
header, or the limiter can be bypassed by rotating it.

---

## Logs

One file per concern, each with the retention its content deserves.

```bash
docker compose exec spring-security-app tail -f /app/logs/security.log
```

They live in a named volume rather than a bind mount to `./logs`: the container
runs as a non-root user, and Docker creates a missing bind-mount directory owned
by root, so on a clean host the application could not open its own log files.
Everything is also on stdout, so `docker compose logs -f` works too.

| | Contains | Kept |
|---|---|---|
| `audit.log` | Successful auth events | 365 days |
| `security.log` | Failed logins, denied authorization, rate limits hit | 180 days |
| `error.log` | Genuine faults only | 90 days |
| `app.log` | Everything | 30 days |

---

## License

MIT.
