
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,

    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users_roles (
    user_id UUID NOT NULL,
    role_id INTEGER NOT NULL,

    CONSTRAINT pk_users_roles PRIMARY KEY (user_id, role_id),

    CONSTRAINT fk_users_roles_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_users_roles_role
        FOREIGN KEY (role_id)
        REFERENCES roles(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    jwt_token TEXT NOT NULL UNIQUE,
    token_type VARCHAR(50) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    user_agent VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,

    user_id UUID NOT NULL,

    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT fk_tokens_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_jwt_token ON tokens(jwt_token);

INSERT INTO users (id, username, password, created_by, updated_by, created_at, updated_at) VALUES
('2f353611-4ced-4c41-87df-771c10dbfec5', 'SYSTEM',  '{noop}1234','2f353611-4ced-4c41-87df-771c10dbfec5','2f353611-4ced-4c41-87df-771c10dbfec5' , CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('50791914-c6ac-4497-85a7-dbf11bd3164a', 'admin',   '{noop}1234','2f353611-4ced-4c41-87df-771c10dbfec5','2f353611-4ced-4c41-87df-771c10dbfec5' ,    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('4e8097ad-d353-455f-b3da-29df73f3113f', 'manager', '{noop}1234','2f353611-4ced-4c41-87df-771c10dbfec5','2f353611-4ced-4c41-87df-771c10dbfec5' ,    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('16d6832b-2358-4b42-aaa4-92af86602530', 'user',    '{noop}1234','2f353611-4ced-4c41-87df-771c10dbfec5','2f353611-4ced-4c41-87df-771c10dbfec5' , CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);


INSERT INTO roles(id, role_name ) VALUES
    (1, 'ROLE_SYSTEM'),
    (2, 'ROLE_ADMIN'),
    (3, 'ROLE_MANAGER'),
    (4, 'ROLE_USER');


INSERT INTO users_roles(user_id , role_id) VALUES
    ('2f353611-4ced-4c41-87df-771c10dbfec5', 1),
    ('50791914-c6ac-4497-85a7-dbf11bd3164a', 2),
    ('4e8097ad-d353-455f-b3da-29df73f3113f', 3),
    ('16d6832b-2358-4b42-aaa4-92af86602530', 4);
