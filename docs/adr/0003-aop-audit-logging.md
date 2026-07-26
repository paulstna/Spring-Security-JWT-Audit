# 0003 — The audit trail as an AOP concern with MDC

**Status:** Accepted

## Context

"Who did what, from where, and did it work" is a requirement in its own right —
for incident response, for support, and in regulated environments for
compliance. It is also the kind of requirement that, written inline, buries the
logic it is supposed to observe: a fifteen-line `login` becomes fifty, most of
them logging.

Hand-written logging also drifts. Some paths log the IP, some forget. Some log
the failure reason, some log a generic message. A trail with gaps is worse than
none, because it is trusted.

## Decision

Auditing is a **cross-cutting concern**, implemented as three AspectJ aspects
that advise the service layer, and enriched through **SLF4J's MDC**.

| Aspect | Watches | Writes to |
|---|---|---|
| `AuditAuthAspect` | Auth operations that succeed | `AUDIT` |
| `SecurityAuthAspect` | Auth failures, denied authorisation | `SECURITY` |
| `ErrorLoggingAspect` | Genuine faults | `ERROR` |

`MdcFilter` establishes `traceId`, `user` and `ip` at the start of every
request, **before** the authorization filter, so a rejected request is logged
with the same context as a successful one. Aspects add `eventType`,
`eventAction`, `eventOutcome`, `failureReason` and `severity`. The Logback
patterns render those keys as columns, so the files are greppable without a log
shipper.

Four destinations, each with the retention its content deserves:

| File | Level | Kept |
|---|---|---|
| `audit.log` | `INFO` only | 365 days |
| `security.log` | `WARN` and above | 180 days |
| `error.log` | `ERROR` | 90 days |
| `app.log` | everything | 30 days |

All four write through async appenders, so a slow disk cannot stall a request.

The same `traceId` goes into every error response body, which closes the loop:
a user quotes an id from a failure and the exact request is one `grep` away.

## Consequences

**Classification is the whole game, and it took work to get right.** The
distinction is not severity, it is *whose fault it is*. A duplicate username is
a client mistake and a legitimate `409`; it used to produce two `ERROR` entries
at `severity=HIGH`. A malformed JWT sent by a client was logged as
`SYSTEM_ERROR`. Both were alert fatigue: a file that fills with normal client
behaviour stops being read, and then a real fault goes unnoticed. Business
exceptions are now classified as such, and `AuditLoggingIT` asserts which log
each event lands in — including that a privilege escalation attempt reaches
`security.log` with its MDC intact, rather than `error.log` as
`UNEXPECTED_ERROR`.

**MDC is thread-bound.** Anything dispatched to another thread loses the
context silently. There is no async work here today; adding it means
propagating the MDC explicitly.

**Pointcuts couple the aspects to package structure.** Rename or move a service
and the advice stops firing — with no compile error and no test failure unless
one asserts on the log. That is the real cost of AOP, and why the log
assertions exist.

**Plain text, not JSON.** Easy to read over `docker compose logs` and with
`grep`, which is what a demo needs. Shipping to an aggregator would want
structured output; that is an encoder change, since the MDC keys are already
there.

## Alternatives considered

**Logging inline in the services.** Explicit and greppable, at the price of
drowning the business logic and drifting the moment two people write two
handlers.

**Spring Security's `AuthenticationSuccessEvent` / `AuthenticationFailureEvent`.**
Covers authentication properly and nothing else — not `/users` authorisation,
not token rotation. It would have meant two mechanisms for one trail.

**A `security_events` table.** Queryable and transactional, but it puts audit
writes in the request's transaction, and a rollback would erase the record of
what caused it. Files sidestep that entirely.
