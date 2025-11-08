-- +migrate Up
-- +migrate StatementBegin

-- =======================================
-- Timezone Indonesia (WIB)
-- =======================================

-- Aktifkan ekstensi UUID
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone ke Asia/Jakarta (WIB)
SET TIME ZONE 'Asia/Jakarta';

SHOW TIMEZONE;


-- Role untuk user
CREATE TYPE user_role AS ENUM ('admin', 'manager', 'staff');

-- Status task
CREATE TYPE task_status AS ENUM ('todo', 'in-progress', 'done');

-- Status notifikasi
CREATE TYPE notification_status AS ENUM ('pending', 'sent', 'failed');


-- ============================
-- USERS TABLE
-- ============================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(100) NOT NULL,
    email           VARCHAR(150) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            user_role NOT NULL DEFAULT 'staff',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

INSERT INTO users (username, email, password_hash, role)
VALUES
    ('admin_user', 'admin@example.com', crypt('AdminPass123!', gen_salt('bf')), 'admin'),
    ('manager_user', 'manager@example.com', crypt('ManagerPass123!', gen_salt('bf')), 'manager'),
    ('staff_user', 'staff@example.com', crypt('StaffPass123!', gen_salt('bf')), 'staff');

-- ============================
-- PROJECTS TABLE
-- ============================

CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nama            VARCHAR(150) NOT NULL,
    deskripsi       TEXT,
    manager_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_projects_manager_id ON projects(manager_id);


-- ============================
-- PROJECT MEMBERS (Many-to-Many)
-- ============================

CREATE TABLE project_members (
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX idx_project_members_user_id ON project_members(user_id);


-- ============================
-- TASKS TABLE
-- ============================

CREATE TABLE tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title           VARCHAR(200) NOT NULL,
    description     TEXT,
    status          task_status NOT NULL DEFAULT 'todo',
    assignee_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    due_date        DATE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_tasks_project_id ON tasks(project_id);
CREATE INDEX idx_tasks_assignee_id ON tasks(assignee_id);
CREATE INDEX idx_tasks_status ON tasks(status);


-- ============================
-- COMMENTS TABLE
-- ============================

CREATE TABLE comments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content         TEXT NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_comments_task_id ON comments(task_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);


-- ============================
-- ATTACHMENTS TABLE
-- ============================

CREATE TABLE attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id         UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    file_path       TEXT NOT NULL,
    file_name       VARCHAR(255) NOT NULL,
    file_size       BIGINT NOT NULL,
    mime_type       VARCHAR(100),
    uploaded_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_attachments_task_id ON attachments(task_id);
CREATE INDEX idx_attachments_uploaded_by ON attachments(uploaded_by);

-- ============================
-- NOTIFICATIONS TABLE
-- ============================

CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message         TEXT NOT NULL,
    status          notification_status NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);

-- +migrate StatementEnd