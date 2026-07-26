# 0002 — In-process rate limiting with Bucket4j and Caffeine

**Status:** Accepted

## Context

`/auth/login` is an oracle: it tells anyone who asks whether a password is
correct. Unthrottled, it is a credential-stuffing endpoint. `/auth/register`
lets an anonymous caller create rows in the database. `/auth/refresh` is
cheaper to abuse but still worth bounding.

The limit has to be per client, not global — a global cap turns one attacker
into a denial of service for everyone.

## Decision

Token buckets from **Bucket4j**, held in a **Caffeine** cache keyed by
`endpoint + client IP`, applied by `RateLimiterFilter` before authentication
runs. Limits are configuration, not code:

| Endpoint | Capacity | Refill |
|---|---|---|
| `login` | 5 | 2 tokens per 60s |
| `register` | 3 | 3 tokens per 600s |
| `refresh` | 3 | 3 tokens per 300s |

A token bucket, rather than a fixed window, because it allows a short legitimate
burst — a user mistyping a password twice — while still bounding the sustained
rate. Fixed windows also let an attacker send double the quota across a
boundary.

The filter runs **before** authentication, so a rejected request costs no BCrypt
comparison and no database query. Rejections answer `429` with `Retry-After` and
the same error body as every other failure in the API.

Only endpoints named in `bucket.limited-endpoints` are throttled. An endpoint
listed there but missing its metrics throws at startup rather than running
unlimited — a typo should break the build, not silently remove a control.

## Consequences

**The client IP has to be trustworthy.** `X-Forwarded-For` is a request header:
anyone can send it. Trusting it unconditionally means an attacker rotates the
header and gets a fresh bucket per request, which is worse than having no
limiter, because it looks like one exists. The resolver only honours it when
`app.trust-proxy` is explicitly enabled, and defaults to `getRemoteAddr()`.
There is a regression test that rotates the header and asserts the limit still
bites.

**Buckets do not survive a restart.** They live in memory. A restart resets
every bucket, and an attacker who can trigger restarts can bypass the limit —
but if they can do that, the limiter is not the problem.

**It does not work across instances.** Each replica has its own buckets, so *n*
replicas mean *n* times the limit. Acceptable for a single-instance deployment;
the fix is a shared backend, and Bucket4j supports Redis and Hazelcast behind
the same API, so it is a configuration change rather than a rewrite. That is
much of why Bucket4j was chosen over hand-rolling a counter.

**Behind a load balancer, without `trust-proxy`, everyone shares one IP** and
the limits apply to the whole world at once. Turning `trust-proxy` on is
mandatory in that topology, and safe only when the proxy overwrites the header.

## Alternatives considered

**Spring Cloud Gateway or an API gateway.** The right place for this in a real
deployment, and it belongs to infrastructure the project does not own. Doing it
in-process keeps the control visible in the codebase and testable.

**A `@RateLimit` annotation on controller methods.** Reads nicely, but the
limiter would run after authentication and after the request is mapped, which
is exactly the work an attacker wants to force.

**Redis-backed buckets.** Correct for multiple instances; a second piece of
infrastructure to run for a single-instance demo. The migration path is open.
