# Architecture decision records

Short notes on the choices that shaped this project: what the alternatives
were, why one was picked, and what it costs. They are written so the reasoning
survives after the reasoning is forgotten.

| | Decision | Status |
|---|---|---|
| [0001](0001-jwt-access-plus-refresh-cookie.md) | A short access token plus a refresh token in an `HttpOnly` cookie | Accepted |
| [0002](0002-rate-limiting-bucket4j.md) | In-process rate limiting with Bucket4j and Caffeine | Accepted |
| [0003](0003-aop-audit-logging.md) | Audit trail as an AOP concern with MDC | Accepted |
| [0004](0004-flyway-migrations.md) | Versioned migrations with Flyway, `ddl-auto=validate` | Accepted |
