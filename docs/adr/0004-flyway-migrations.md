# 0004 — Versioned migrations with Flyway, `ddl-auto=validate`

**Status:** Accepted

## Context

The schema was produced by two mechanisms that did not know about each other:
Hibernate's `ddl-auto=update`, and a `sql/init.sql` mounted into the Postgres
container's entrypoint.

Both are unusable beyond a first run. The init script executes only when the
data directory is empty, so it is a one-shot bootstrap, not a way to evolve
anything. `ddl-auto=update` adds columns and tables but never drops, never
renames, never backfills, and never tells you what it did — the schema becomes
whatever the sequence of deploys happened to produce, and no two environments
are reliably alike.

The hardening work then needed exactly the operations neither can do: adding
`enabled` and `account_non_locked` with sensible defaults for existing rows, and
renaming `tokens.jwt_token` to `token_hash` while purging values that could
never match again.

## Decision

**Flyway** owns the schema. Migrations live in
`src/main/resources/db/migration`, run at startup, and are recorded in
`flyway_schema_history`.

**Hibernate is demoted to `ddl-auto=validate`.** It no longer changes anything;
it compares the entities to the schema at boot and refuses to start if they
disagree. A mapping that drifts from the database is a failed startup, not a
subtly wrong query in production.

The `sql/init.sql` mount is gone from `compose.yaml`. One mechanism, one source
of truth.

Migrations are split by *why they exist*, not by when they were written:

| | |
|---|---|
| `V1__init_schema.sql` | Tables, constraints, indexes |
| `V2__seed_baseline.sql` | Role catalogue and the `SYSTEM` auditor — required everywhere |
| `V3__seed_users.sql` | Demo accounts |
| `V4__hash_refresh_tokens.sql` | `jwt_token` → `token_hash`, incompatible rows purged |

`V2` is not optional data. `SystemAuditorProvider` looks up the `SYSTEM` user to
stamp `created_by` on every save and cannot persist anything without it, so it
belongs to the schema as much as any table does.

`baseline-on-migrate` is enabled so a database created before Flyway existed
accepts the migrations instead of refusing to start.

## Consequences

**Every environment is the same schema, arrived at the same way**, including the
Testcontainers PostgreSQL the integration tests run against. The tests exercise
the real migrations and the real `validate` check, not a dialect that merely
resembles them. A migration that would fail in production fails in CI first.

**Migrations are append-only.** An applied file cannot be edited — Flyway
checksums it and refuses. Fixing a mistake means a new version, which is the
discipline the tool exists to enforce.

**Demo accounts are seeded in every profile, `prod` included.** A deliberate
choice for a portfolio project: the deployed stack has to be explorable without
someone handing over credentials. `V3` says at the top that a real deployment
drops it or rotates the passwords, and the `SYSTEM` account it depends on is
disabled and unusable regardless.

**`V4` deletes every token row.** Those rows held raw JWTs that can never match
a hash, so keeping them would leave dead entries that silently never match.
Active sessions re-authenticate once — the intended effect, and the reason the
migration says so.

**Startup does more work.** Flyway takes a lock and checks history on every
boot. Milliseconds, and worth knowing about when several instances start at
once.

## Alternatives considered

**Liquibase.** Equally capable, with a database-agnostic changelog format. This
project targets PostgreSQL only, so the abstraction buys nothing and costs
readability — plain SQL is reviewable by anyone.

**Keeping `ddl-auto=update` and adding Flyway alongside.** Two things writing to
one schema, racing at startup. Worse than either alone.

**Hand-run SQL scripts.** What `sql/init.sql` already was, with no record of
what ran where.
