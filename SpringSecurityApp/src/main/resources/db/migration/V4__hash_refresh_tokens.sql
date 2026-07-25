-- ============================================================
-- V4 — Store refresh tokens as a SHA-256 hash instead of the raw JWT.
--
-- A database dump no longer contains replayable credentials: the raw token
-- lives only in the client's HttpOnly cookie and is hashed on every lookup.
--
-- Existing rows hold raw JWTs that can never match a hash, so they are purged.
-- Active sessions must re-authenticate once, which is the intended effect.
-- ============================================================

DELETE FROM tokens;

ALTER TABLE tokens RENAME COLUMN jwt_token TO token_hash;

-- SHA-256 rendered as hex is always 64 characters.
ALTER TABLE tokens ALTER COLUMN token_hash TYPE VARCHAR(64);

-- Keep the constraint name aligned with the renamed column.
ALTER TABLE tokens RENAME CONSTRAINT tokens_jwt_token_key TO tokens_token_hash_key;
