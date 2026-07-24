-- ============================================================
-- V1 — Initial schema
-- Mirrors the JPA entities (validated by hibernate ddl-auto=validate).
-- Column names follow Spring's snake_case physical naming strategy.
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY,
    username            VARCHAR(50)  NOT NULL UNIQUE,
    password            VARCHAR(255) NOT NULL,
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    account_non_locked  BOOLEAN      NOT NULL DEFAULT TRUE,

    created_by  UUID,
    updated_by  UUID,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id         SERIAL PRIMARY KEY,
    role_name  VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users_roles (
    user_id  UUID    NOT NULL,
    role_id  INTEGER NOT NULL,

    CONSTRAINT pk_users_roles PRIMARY KEY (user_id, role_id),

    CONSTRAINT fk_users_roles_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    CONSTRAINT fk_users_roles_role
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tokens (
    id          UUID PRIMARY KEY,
    jwt_token   TEXT        NOT NULL UNIQUE,
    token_type  VARCHAR(50) NOT NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,

    user_agent  VARCHAR(255) NOT NULL,
    ip_address  VARCHAR(45)  NOT NULL,

    user_id     UUID NOT NULL,

    created_by  UUID,
    updated_by  UUID,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL,

    CONSTRAINT fk_tokens_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_users_username   ON users(username);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id   ON tokens(user_id);
