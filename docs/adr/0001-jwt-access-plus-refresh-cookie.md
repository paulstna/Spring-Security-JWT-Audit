# 0001 — A short access token plus a refresh token in an HttpOnly cookie

**Status:** Accepted

## Context

The API is stateless: no server session, and it should scale horizontally
without sticky sessions or a shared session store. That leaves the client
holding the credential, which raises two problems that pull in opposite
directions.

A credential the client sends on every request has to be readable by the
client's code, which means readable by any script running on the page. Make it
long-lived and a single XSS becomes permanent account access. Make it
short-lived and the user re-enters their password every fifteen minutes.

## Decision

Two tokens with different jobs and different storage.

**The access token** is a signed JWT (HS512), valid **15 minutes**, sent in the
`Authorization` header. It carries the username and roles, so authorising a
request needs no database round trip. It is never stored server side — there is
nothing to revoke, which is exactly why it is short.

**The refresh token** is a signed JWT valid **15 days**, delivered in a cookie
the client's JavaScript cannot read:

```
Set-Cookie: refreshToken=…; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=1296000
```

Every attribute is load-bearing. `HttpOnly` puts it out of reach of XSS.
`SameSite=Strict` means a foreign site cannot make the browser send it.
`Path=/api/v1/auth` means it is not attached to ordinary API calls, so it is not
in most requests at all. `Secure` is on in `prod` and off in `dev`, which is the
only way to test over `http://localhost`.

Server side, only **`SHA-256(token)` as hex** is stored. Refreshing hashes the
incoming cookie and looks up the digest.

Every refresh **rotates**: the old row is deleted before the new token is
issued. Each token is bound to the **User-Agent** that obtained it, and logging
in again from the same client replaces that client's session rather than adding
one.

## Consequences

**What this buys.** A database dump contains no usable credential. A stolen
refresh token works at most once, and only from the same client. Revoking a
session is a `DELETE`, and it takes effect on the next refresh. Authorising a
normal request touches no table.

**What it costs.** An access token cannot be revoked before it expires: disable
an account and its live token keeps working for up to fifteen minutes on
endpoints that do not re-read the user. This project narrows that window — the
JWT filter loads the user and refuses a disabled or locked one — at the price of
a lookup per request. That trade is deliberate: correctness on account state
matters more here than shaving a query.

**A hash, not BCrypt.** Password hashing is slow on purpose because passwords
are low-entropy and guessable. A refresh token is 256 bits of randomness from a
CSPRNG; there is nothing to brute-force. BCrypt would only add latency to every
refresh, and its 72-byte input cap would silently truncate the JWT.

**A bug this design already caused.** The cookie path was originally
`/api/v1/auth/refresh`, so the browser never sent it to `/logout` and logging
out could not revoke anything. Narrow paths are a real defence and a real
footgun; the flow is now covered by tests.

## Alternatives considered

**Server-side sessions.** Simplest to revoke, but needs shared state and turns
the API into something that cannot scale out without a session store.

**Refresh token in the response body, stored in `localStorage`.** Easier for a
non-browser client, and the standard way to lose everything to one XSS. A
native client can still hold the cookie; the browser is the case that needs
protecting.

**No refresh token, just a long-lived access token.** One credential, no
rotation, no revocation, and the worst of both problems.
