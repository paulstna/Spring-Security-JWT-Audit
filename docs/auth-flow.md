# Authentication flows

Two tokens with different jobs. The **access token** is a bearer JWT the client
sends on every call, valid 15 minutes, never stored server side. The **refresh
token** is a JWT the client never touches: it lives in an `HttpOnly` cookie
scoped to `/api/v1/auth`, valid 15 days, and only its SHA-256 hash is kept in
the database.

Why two, and why the cookie, is in [ADR 0001](adr/0001-jwt-access-plus-refresh-cookie.md).

## Login

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RL as RateLimiterFilter
    participant AC as AuthController
    participant AS as AuthService
    participant AM as AuthenticationManager
    participant TS as TokenService
    participant DB as PostgreSQL
    participant LOG as audit.log / security.log

    C->>RL: POST /api/v1/auth/login
    alt bucket empty (5 per minute per IP)
        RL-->>C: 429 + Retry-After
    end
    RL->>AC: pass
    AC->>AS: login(credentials, User-Agent, IP)
    AS->>LOG: LOGIN_ATTEMPT
    AS->>AM: authenticate

    alt wrong password, unknown user, disabled or locked
        AM--xAS: AuthenticationException
        AS->>LOG: LOGIN_FAILED + the real reason
        AS-->>C: 401 "Bad credentials"
        Note over AS,C: The same answer in every case.<br/>The reason exists only in the log.
    end

    AM-->>AS: authenticated
    AS->>TS: delete the token for this User-Agent
    TS->>DB: DELETE FROM tokens
    Note over AS,DB: One live session per device.
    AS->>AS: build access JWT (15 min) + refresh JWT (15 days)
    AS->>TS: store SHA-256(refresh), User-Agent, IP
    TS->>DB: INSERT INTO tokens
    AS->>LOG: LOGIN_SUCCESS
    AS-->>C: 200 { authToken } + Set-Cookie: refreshToken
```

`register` is the same shape: it creates the account with `ROLE_USER`, then
issues the identical pair, so a new user is signed in without a second call.

## Refresh, with rotation

The old token is destroyed before the new one is issued. A stolen refresh token
is therefore usable at most once, and only from the client that obtained it.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AC as AuthController
    participant AS as AuthService
    participant JP as JwtProvider
    participant TS as TokenService
    participant DB as PostgreSQL

    C->>AC: POST /api/v1/auth/refresh<br/>Cookie: refreshToken
    AC->>AS: refreshToken(cookie, User-Agent, IP)

    AS->>JP: signature and expiry valid?
    AS->>JP: token_type == REFRESH_TOKEN?
    Note over AS,JP: An access token is refused here,<br/>and a refresh token is refused as a bearer.

    AS->>TS: find by SHA-256(cookie)
    TS->>DB: SELECT ... WHERE token_hash = ?

    alt not found, revoked, or a different User-Agent
        AS-->>C: 401
    end

    opt IP changed since the token was issued
        AS->>AS: log a warning, allow the request
        Note over AS: Mobile networks change IP constantly.<br/>Refusing would break real users.
    end

    AS->>TS: delete the old row
    TS->>DB: DELETE
    AS->>AS: issue a fresh pair
    AS->>TS: store the new hash
    TS->>DB: INSERT
    AS-->>C: 200 { authToken } + a new Set-Cookie
```

## Logout

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AC as AuthController
    participant AS as AuthService
    participant DB as PostgreSQL

    C->>AC: POST /api/v1/auth/logout<br/>Cookie: refreshToken
    AC->>AS: logout(cookie)
    AS->>DB: DELETE the row matching SHA-256(cookie)
    AC-->>C: 204 + Set-Cookie clearing it (Max-Age=0)
    Note over C,DB: Access tokens already issued stay valid<br/>until they expire. That is the price of<br/>stateless auth, and why they last 15 minutes.
```

Logging out twice is not an error: the second call finds nothing to delete and
still answers `204`. The cookie path is `/api/v1/auth`, which covers both
`/refresh` and `/logout` — it was once `/api/v1/auth/refresh`, so the browser
never sent the cookie to `/logout` and the session could not be revoked at all.

## What a client sees when something fails

| Status | Meaning | Where it comes from |
|---|---|---|
| `400` | The payload broke a validation rule | `MethodArgumentNotValidException`, with `fieldErrors` |
| `401` | No usable credential: absent, malformed, expired, wrong type, or the account is disabled | `RestAuthenticationEntryPoint`, or the handler for a bad login |
| `403` | Authenticated, but the role is not enough | `RestAccessDeniedHandler` |
| `409` | The username is taken | `ResourceAlreadyExistsException` |
| `429` | Rate limit hit, with `Retry-After` | `RateLimiterFilter` |

All five share one body, `traceId` included:

```json
{
  "timestamp": "2026-07-25T23:22:14.883Z",
  "status": 401,
  "message": "Authentication required",
  "path": "/api/v1/users",
  "traceId": "f06d14a1-1dee-454f-9822-6b3d0c18a985"
}
```

The split between `401` and `403` is the useful part: one tells a client to
refresh and retry, the other tells it not to bother.
