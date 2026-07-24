-- ============================================================
-- V3 — Demo users (seeded in EVERY profile so both dev and prod are
-- testable without manual SQL).
--
-- admin / manager / user  -->  password:  Demo1234!
-- Stored as real BCrypt hashes ({bcrypt} prefix for DelegatingPasswordEncoder).
--
-- NOTE: these are demonstration accounts with a known password. For a real
-- production deployment, remove this migration (or rotate the credentials).
-- ============================================================

INSERT INTO users (id, username, password, enabled, account_non_locked,
                   created_by, updated_by, created_at, updated_at) VALUES
    ('50791914-c6ac-4497-85a7-dbf11bd3164a', 'admin',
     '{bcrypt}$2a$10$z3UfzLV.u5MlGm7f22A/AeuBUlaOGDUE79PjLrrcdFtGe/5aZBiNi',
     TRUE, TRUE,
     '2f353611-4ced-4c41-87df-771c10dbfec5', '2f353611-4ced-4c41-87df-771c10dbfec5',
     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('4e8097ad-d353-455f-b3da-29df73f3113f', 'manager',
     '{bcrypt}$2a$10$z3UfzLV.u5MlGm7f22A/AeuBUlaOGDUE79PjLrrcdFtGe/5aZBiNi',
     TRUE, TRUE,
     '2f353611-4ced-4c41-87df-771c10dbfec5', '2f353611-4ced-4c41-87df-771c10dbfec5',
     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('16d6832b-2358-4b42-aaa4-92af86602530', 'user',
     '{bcrypt}$2a$10$z3UfzLV.u5MlGm7f22A/AeuBUlaOGDUE79PjLrrcdFtGe/5aZBiNi',
     TRUE, TRUE,
     '2f353611-4ced-4c41-87df-771c10dbfec5', '2f353611-4ced-4c41-87df-771c10dbfec5',
     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users_roles (user_id, role_id) VALUES
    ('50791914-c6ac-4497-85a7-dbf11bd3164a', 2),  -- admin   -> ROLE_ADMIN
    ('4e8097ad-d353-455f-b3da-29df73f3113f', 3),  -- manager -> ROLE_MANAGER
    ('16d6832b-2358-4b42-aaa4-92af86602530', 4)   -- user    -> ROLE_USER
ON CONFLICT DO NOTHING;
