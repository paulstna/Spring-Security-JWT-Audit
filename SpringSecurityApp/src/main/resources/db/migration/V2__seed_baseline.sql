-- ============================================================
-- V2 — Baseline seed (required in EVERY environment)
--
-- The roles and the SYSTEM user are NOT demo data: SystemAuditorProvider
-- looks up the "SYSTEM" user to stamp created_by/updated_by on every save,
-- and fails to start persisting entities if it is missing.
--
-- SYSTEM is a non-interactive audit account: it is created disabled and with
-- an unknown (random) BCrypt password, so it cannot be used to authenticate.
-- ============================================================

INSERT INTO roles (id, role_name) VALUES
    (1, 'ROLE_SYSTEM'),
    (2, 'ROLE_ADMIN'),
    (3, 'ROLE_MANAGER'),
    (4, 'ROLE_USER')
ON CONFLICT (role_name) DO NOTHING;

-- Keep the SERIAL sequence ahead of the explicitly-inserted ids
SELECT setval(pg_get_serial_sequence('roles', 'id'), (SELECT MAX(id) FROM roles));

INSERT INTO users (id, username, password, enabled, account_non_locked,
                   created_by, updated_by, created_at, updated_at) VALUES
    ('2f353611-4ced-4c41-87df-771c10dbfec5', 'SYSTEM',
     '{bcrypt}$2a$10$CGadwzhZ0MrX2a/7EfUDhertgudcUWQq8eLH1F8djhIOn9lXmz29S',
     FALSE, TRUE,
     '2f353611-4ced-4c41-87df-771c10dbfec5',
     '2f353611-4ced-4c41-87df-771c10dbfec5',
     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users_roles (user_id, role_id) VALUES
    ('2f353611-4ced-4c41-87df-771c10dbfec5', 1)
ON CONFLICT DO NOTHING;
