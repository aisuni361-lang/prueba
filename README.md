# prueba
prueba de la base 
-- =====================================================================
-- ADISGEA · Script de base de datos unificado (MySQL 8.0.16 o superior)
-- Basado en: ERS v1.0 (25/10/26), ADG-DAT-01 v1.0, ADG-API-01 v1.0 y ADG-PRD-01 v1.1
-- =====================================================================

-- Instalación inicial sobre una base vacía, ejecutada por el administrador de bootstrap.
-- No usa DROP ni desactiva FKs; NO es una migración para una BD existente.
CREATE DATABASE IF NOT EXISTS adisgea
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;
USE adisgea;
SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;
SET SESSION time_zone = '+00:00';
SET SESSION sql_mode = 'STRICT_TRANS_TABLES,STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY';
SET FOREIGN_KEY_CHECKS = 1;
-- Exigir en my.cnf: require_secure_transport=ON, local_infile=OFF,
-- log de consultas generales sin PII, backups + binlogs cifrados, KMS/TDE cuando esté disponible.
-- Configurar event_scheduler=ON en my.cnf (no se eleva privilegio global aquí).
-- Todas las DATETIME se escriben/interpretan en UTC desde el backend.
-- No poner contraseñas, peppers o claves KMS dentro del SQL.


-- ---------------------------------------------------------------------
-- 1. TENANTS (empresas B2B / entidades del Estado B2G)
-- ---------------------------------------------------------------------
CREATE TABLE tenants (
    id          CHAR(36)     NOT NULL DEFAULT (UUID()),
    name        VARCHAR(150) NOT NULL,
    type        VARCHAR(3)   NOT NULL,
    country     CHAR(2)      NOT NULL DEFAULT 'PE',
    status      VARCHAR(10)  NOT NULL DEFAULT 'active',
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT ck_tenants_type   CHECK (type IN ('B2B','B2G')),
    CONSTRAINT ck_tenants_status CHECK (status IN ('active','paused','closed')),
    KEY idx_tenants_status (status),
    CONSTRAINT ck_tenants_country CHECK (REGEXP_LIKE(country, '^[A-Z]{2}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 2. ROLES, USUARIOS Y PERFILES
-- ---------------------------------------------------------------------
CREATE TABLE roles (
    id           SMALLINT    NOT NULL,
    code         VARCHAR(30) NOT NULL,
    name         VARCHAR(60) NOT NULL,
    description  TEXT,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE users (
    id                CHAR(36)     NOT NULL DEFAULT (UUID()),
    tenant_id         CHAR(36)     NULL,                    -- NULL = usuaria B2C
    username          VARCHAR(50)  NOT NULL,
    email             VARCHAR(255) NOT NULL,
    password_hash     VARCHAR(255) NOT NULL,                -- bcrypt cost >= 12, Argon2id PHC
    status            VARCHAR(20)  NOT NULL DEFAULT 'pending',
    email_verified_at DATETIME     NULL,
    last_login_at     DATETIME     NULL,
    password_changed_at DATETIME   NULL,
    failed_login_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until      DATETIME     NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at        DATETIME     NULL,
    deleted_by        CHAR(36)     NULL,
    deletion_reason   VARCHAR(240) NULL,
    email_active      VARCHAR(255) GENERATED ALWAYS AS
        (IF(deleted_at IS NULL, email, NULL)) STORED,
    username_active   VARCHAR(50) GENERATED ALWAYS AS
        (IF(deleted_at IS NULL, username, NULL)) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username_active (username_active),
    UNIQUE KEY uq_users_email_active (email_active),
    KEY idx_users_tenant (tenant_id),
    CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT ck_users_status CHECK (status IN ('pending','active','suspended','deletion_requested','deleted')),
    KEY idx_users_status (status),
    CONSTRAINT fk_users_deleted_by FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT ck_users_email CHECK (
        BINARY email = BINARY LOWER(TRIM(email)) AND
        REGEXP_LIKE(email, '^[a-z0-9][a-z0-9._%+-]*@[a-z0-9][a-z0-9.-]*[.][a-z]{2,63}$', 'c')
    ),
    CONSTRAINT ck_users_hash CHECK (
        REGEXP_LIKE(password_hash, '^[$]2[aby][$](1[2-9]|2[0-9]|3[01])[$][./A-Za-z0-9]{53}$', 'c') OR
        REGEXP_LIKE(password_hash, '^[$]argon2id[$]v=19[$]m=[1-9][0-9]{3,8},t=[1-9][0-9]?,p=[1-9][0-9]?[$][A-Za-z0-9+/]{16,128}[$][A-Za-z0-9+/]{16,128}$', 'c')
    ),
    CONSTRAINT ck_users_active_verified CHECK (status <> 'active' OR email_verified_at IS NOT NULL),
    CONSTRAINT ck_users_deleted CHECK (status <> 'deleted' OR deleted_at IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- Controles de identidad adicionales; PIN/OTP/credenciales no se guardan en claro.
CREATE TABLE user_mfa (
    id                CHAR(36) NOT NULL DEFAULT (UUID()),
    user_id           CHAR(36) NOT NULL,
    method            VARCHAR(10) NOT NULL,
    secret_enc        VARBINARY(512) NULL, -- TOTP: ciphertext AES-GCM
    secret_nonce      BINARY(12) NULL,
    secret_tag        BINARY(16) NULL,
    secret_key_id     VARCHAR(80) NULL,
    credential_id     VARBINARY(1024) NULL, -- WebAuthn: identificador de credencial
    public_key_cose   VARBINARY(2048) NULL, -- WebAuthn: clave pública (no secreta)
    sign_count        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    enabled_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at      DATETIME NULL,
    disabled_at       DATETIME NULL,
    PRIMARY KEY (id),
    KEY idx_mfa_user_active (user_id, disabled_at),
    UNIQUE KEY uq_mfa_credential (credential_id),
    CONSTRAINT fk_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_mfa_method CHECK (method IN ('totp','webauthn')),
    CONSTRAINT ck_mfa_payload CHECK (
      (method='totp' AND secret_enc IS NOT NULL AND secret_nonce IS NOT NULL AND secret_tag IS NOT NULL AND secret_key_id IS NOT NULL AND credential_id IS NULL AND public_key_cose IS NULL)
      OR (method='webauthn' AND secret_enc IS NULL AND secret_nonce IS NULL AND secret_tag IS NULL AND secret_key_id IS NULL AND credential_id IS NOT NULL AND public_key_cose IS NOT NULL)
    ),
    CONSTRAINT ck_mfa_disabled CHECK (disabled_at IS NULL OR disabled_at >= enabled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE mfa_recovery_codes (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    mfa_id        CHAR(36) NOT NULL,
    code_hash     CHAR(64) NOT NULL, -- HMAC-SHA256 con pepper externo
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at       DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_mrc_hash (code_hash),
    KEY idx_mrc_mfa (mfa_id, used_at),
    CONSTRAINT fk_mrc_mfa FOREIGN KEY (mfa_id) REFERENCES user_mfa(id) ON DELETE CASCADE,
    CONSTRAINT ck_mrc_hash CHECK (REGEXP_LIKE(code_hash, '^[a-f0-9]{64}$', 'c')),
    CONSTRAINT ck_mrc_dates CHECK (used_at IS NULL OR used_at >= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Identificador pseudonimizado con HMAC-SHA256, jamás email en claro.
CREATE TABLE login_attempts (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         CHAR(36) NULL,
    identifier_hmac BINARY(32) NOT NULL,
    ip_address      VARCHAR(45) NULL,
    user_agent      VARCHAR(255) NULL,
    success         BOOLEAN NOT NULL,
    failure_code    VARCHAR(30) NULL,
    attempted_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_la_identifier (identifier_hmac, attempted_at DESC),
    KEY idx_la_ip (ip_address, attempted_at DESC),
    KEY idx_la_user (user_id, attempted_at DESC),
    CONSTRAINT fk_la_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT ck_la_success CHECK (success IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE password_history (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id       CHAR(36) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    changed_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_ph_user (user_id, changed_at DESC),
    CONSTRAINT fk_ph_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_ph_hash CHECK (
      REGEXP_LIKE(password_hash, '^[$]2[aby][$](1[2-9]|2[0-9]|3[01])[$][./A-Za-z0-9]{53}$', 'c') OR
      REGEXP_LIKE(password_hash, '^[$]argon2id[$]v=19[$]m=[1-9][0-9]{3,8},t=[1-9][0-9]?,p=[1-9][0-9]?[$][A-Za-z0-9+/]{16,128}[$][A-Za-z0-9+/]{16,128}$', 'c')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Identidad de conexión REAL y dedicada por agente; no usar pool compartido para estas vistas.
-- Solo un administrador concede GRANT de rol + INSERT en este mapa tras validar al operador.
-- USER() refleja el usuario autenticado por MySQL, NO un parámetro del cliente SQL.
CREATE TABLE db_access_principals (
    login_name VARCHAR(32) COLLATE utf8mb4_0900_bin NOT NULL,
    user_id    CHAR(36) NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (login_name),
    UNIQUE KEY uq_dap_user (user_id),
    CONSTRAINT fk_dap_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT ck_dap_login CHECK (REGEXP_LIKE(login_name, '^[a-z][a-z0-9_]{2,31}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Datos regionales y de interfaz (minimización D2: sin fecha de nacimiento exacta)
CREATE TABLE profiles (
    user_id       CHAR(36)     NOT NULL,
    display_name  VARCHAR(100) NULL,
    country_code  CHAR(2)      NOT NULL DEFAULT 'PE',
    locale        VARCHAR(10)  NOT NULL DEFAULT 'es-PE',
    timezone      VARCHAR(64)  NOT NULL DEFAULT 'America/Lima',
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_profiles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_profile_country CHECK (REGEXP_LIKE(country_code, '^[A-Z]{2}$', 'c')),
    CONSTRAINT ck_profile_locale CHECK (REGEXP_LIKE(locale, '^[a-z]{2}-[A-Z]{2}$', 'c')),
    CONSTRAINT ck_profile_tz CHECK (timezone = 'UTC' OR REGEXP_LIKE(timezone, '^[A-Za-z_]+/[A-Za-z0-9_+/-]+$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE user_roles (
    user_id     CHAR(36)  NOT NULL,
    role_id     SMALLINT  NOT NULL,
    granted_by  CHAR(36)  NULL,
    granted_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  DATETIME  NULL,
    revoked_by  CHAR(36)  NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_ur_user    FOREIGN KEY (user_id)    REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT fk_ur_role    FOREIGN KEY (role_id)    REFERENCES roles(id),
    CONSTRAINT fk_ur_granter FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_ur_revoker FOREIGN KEY (revoked_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT ck_ur_revoke CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE auth_tokens (
    id          CHAR(36)     NOT NULL DEFAULT (UUID()),
    user_id     CHAR(36)     NOT NULL,
    token_hash  CHAR(64)     NOT NULL,                   -- SHA-256 en hex de token aleatorio + pepper externo
    purpose     VARCHAR(20)  NOT NULL DEFAULT 'session',
    expires_at  DATETIME     NOT NULL,
    revoked_at  DATETIME     NULL,
    ip_address  VARCHAR(45)  NULL,
    user_agent  VARCHAR(255) NULL,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_tokens_hash (token_hash),
    KEY idx_tokens_user (user_id),
    CONSTRAINT fk_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_tokens_purpose CHECK (purpose IN ('session','refresh','password_reset')),
    KEY idx_tokens_user_revoked (user_id, revoked_at),
    KEY idx_tokens_expires (expires_at),
    CONSTRAINT ck_tokens_exp CHECK (expires_at > created_at),
    CONSTRAINT ck_tokens_hash CHECK (REGEXP_LIKE(token_hash, '^[a-f0-9]{64}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE email_change_requests (
    id           CHAR(36)     NOT NULL DEFAULT (UUID()),
    user_id      CHAR(36)     NOT NULL,
    new_email    VARCHAR(255) NOT NULL,
    code_hash    CHAR(64)     NOT NULL,
    expires_at   DATETIME     NOT NULL,
    confirmed_at DATETIME     NULL,
    attempts     INT UNSIGNED NOT NULL DEFAULT 0,
    ip_address   VARCHAR(45)  NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_ecr_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    KEY idx_ecr_expires (expires_at),
    CONSTRAINT ck_ecr_expires CHECK (expires_at > created_at),
    CONSTRAINT ck_ecr_confirmed CHECK (confirmed_at IS NULL OR confirmed_at >= created_at),
    CONSTRAINT ck_ecr_email CHECK (
        BINARY new_email = BINARY LOWER(TRIM(new_email)) AND
        REGEXP_LIKE(new_email, '^[a-z0-9][a-z0-9._%+-]*@[a-z0-9][a-z0-9.-]*[.][a-z]{2,63}$', 'c')
    ),
    CONSTRAINT ck_ecr_hash CHECK (REGEXP_LIKE(code_hash, '^[a-f0-9]{64}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Solicitudes de eliminación y derechos ARCO (ERS v1.0 / ADG-DAT-01 7.2)
CREATE TABLE account_deletion_requests (
    id           CHAR(36)    NOT NULL DEFAULT (UUID()),
    user_id      CHAR(36)    NOT NULL,
    request_type VARCHAR(15) NOT NULL DEFAULT 'deletion',
    status       VARCHAR(12) NOT NULL DEFAULT 'requested',
    requested_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_at       DATETIME    NULL,
    resolved_at  DATETIME    NULL,
    resolved_by  CHAR(36)    NULL,
    resolution_note VARCHAR(2000) NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_adr_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT ck_adr_type   CHECK (request_type IN ('access','rectification','deletion','opposition')),
    CONSTRAINT ck_adr_status CHECK (status IN ('requested','in_review','completed','cancelled')),
    KEY idx_adr_status (status, due_at),
    CONSTRAINT fk_adr_resolved_by FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT ck_adr_dates CHECK (due_at IS NULL OR due_at > requested_at),
    CONSTRAINT ck_adr_resolved CHECK (resolved_at IS NULL OR resolved_at >= requested_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 3. CONSENTIMIENTOS Y PREFERENCIAS
-- ---------------------------------------------------------------------
CREATE TABLE consent_purposes (
    id           SMALLINT    NOT NULL,
    code         VARCHAR(40) NOT NULL,
    description  TEXT        NOT NULL,
    version      VARCHAR(32) NOT NULL DEFAULT '2026-10-v1',
    is_required  BOOLEAN     NOT NULL DEFAULT FALSE,
    valid_from   DATETIME    NULL,
    valid_to     DATETIME    NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_cp_code (code),
    CONSTRAINT ck_cp_description CHECK (CHAR_LENGTH(description) BETWEEN 10 AND 2000),
    CONSTRAINT ck_cp_validity CHECK (valid_to IS NULL OR (valid_from IS NOT NULL AND valid_to > valid_from))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE user_consents (
    id             CHAR(36)    NOT NULL DEFAULT (UUID()),
    user_id        CHAR(36)    NOT NULL,
    purpose_id     SMALLINT    NOT NULL,
    notice_version VARCHAR(32) NOT NULL DEFAULT '2026-10-v1',
    channel        VARCHAR(10) NOT NULL DEFAULT 'APP',
    granted_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at     DATETIME    NULL,
    revoked_by     CHAR(36)    NULL,
    revocation_reason VARCHAR(250) NULL,
    ip_address     VARCHAR(45) NULL,
    -- Vale 1 si el consentimiento sigue activo, NULL si fue revocado
    active_flag    TINYINT GENERATED ALWAYS AS (IF(revoked_at IS NULL, 1, NULL)) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_consent_active (user_id, purpose_id, active_flag),
    CONSTRAINT fk_uc_user    FOREIGN KEY (user_id)    REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT fk_uc_purpose FOREIGN KEY (purpose_id) REFERENCES consent_purposes(id),
    CONSTRAINT ck_uc_channel CHECK (channel IN ('WEB','APP','SMS','EMAIL','WHATSAPP')),
    CONSTRAINT fk_uc_revoker FOREIGN KEY (revoked_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT ck_uc_revoked CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE notification_preferences (
    user_id                CHAR(36)    NOT NULL,
    email_enabled          BOOLEAN     NOT NULL DEFAULT TRUE,
    push_enabled           BOOLEAN     NOT NULL DEFAULT FALSE,
    reminders_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    alma_enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    alma_memory_opt_in     BOOLEAN     NOT NULL DEFAULT FALSE,
    preferred_window       VARCHAR(50) NULL,
    updated_at             DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_np_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_np_channels CHECK (reminders_enabled = FALSE OR email_enabled = TRUE OR push_enabled = TRUE),
    CONSTRAINT ck_np_window CHECK (
        preferred_window IS NULL OR REGEXP_LIKE(preferred_window, '^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$', 'c')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 4. FEATURE FLAGS, RUTAS Y MÉTODO AMANECER®
-- ---------------------------------------------------------------------
CREATE TABLE feature_flags (
    flag_key     VARCHAR(60) NOT NULL,
    enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    description  TEXT,
    updated_by   CHAR(36)    NULL,
    updated_at   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (flag_key),
    CONSTRAINT fk_ff_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE routes (
    id           SMALLINT    NOT NULL,
    code         VARCHAR(4)  NOT NULL,                      -- R1, R2, R3
    name         VARCHAR(80) NOT NULL,
    description  TEXT,
    flag_key     VARCHAR(60) NULL,
    stage        VARCHAR(15) NOT NULL DEFAULT 'internal',
    PRIMARY KEY (id),
    UNIQUE KEY uq_routes_code (code),
    CONSTRAINT fk_routes_flag FOREIGN KEY (flag_key) REFERENCES feature_flags(flag_key),
    CONSTRAINT ck_routes_stage CHECK (stage IN ('internal','pilot','public','retired'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE method_steps (
    step_order   SMALLINT    NOT NULL,
    name         VARCHAR(40) NOT NULL,
    description  TEXT,
    PRIMARY KEY (step_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 5. TALLERES, CONTENIDOS Y FLUJO DE REVISIÓN EDITORIAL
-- ---------------------------------------------------------------------
CREATE TABLE workshops (
    id            CHAR(36)     NOT NULL DEFAULT (UUID()),
    route_id      SMALLINT     NULL,
    category      VARCHAR(13)  NOT NULL,
    title         VARCHAR(150) NOT NULL,
    summary       TEXT,
    availability  VARCHAR(12)  NOT NULL DEFAULT 'upcoming',
    created_by    CHAR(36)     NULL,
    published_at  DATETIME     NULL,
    archived_at   DATETIME     NULL,
    slug          VARCHAR(160) NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_ws_route FOREIGN KEY (route_id)   REFERENCES routes(id),
    CONSTRAINT fk_ws_user  FOREIGN KEY (created_by) REFERENCES users(id),
    CONSTRAINT ck_ws_category CHECK (category IN ('bienestar','finanzas','empleabilidad')),
    CONSTRAINT ck_ws_avail    CHECK (availability IN ('upcoming','open','paused','closed')),
    UNIQUE KEY uq_workshops_slug (slug),
    KEY idx_ws_route_cat_avail (route_id, category, availability),
    CONSTRAINT ck_ws_published CHECK (published_at IS NULL OR published_at >= created_at),
    CONSTRAINT ck_ws_archived CHECK (archived_at IS NULL OR archived_at >= created_at),
    CONSTRAINT ck_ws_slug CHECK (slug IS NULL OR REGEXP_LIKE(slug, '^[a-z0-9]+(-[a-z0-9]+)*$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE contents (
    id            CHAR(36)     NOT NULL DEFAULT (UUID()),
    workshop_id   CHAR(36)     NOT NULL,
    kind          VARCHAR(8)   NOT NULL,
    title         VARCHAR(150) NOT NULL,
    body          MEDIUMTEXT,
    media_url     TEXT,
    source_ref    VARCHAR(255) NULL,
    sort_order    INT          NOT NULL DEFAULT 0,
    version       INT          NOT NULL DEFAULT 1,
    content_revision INT       NOT NULL DEFAULT 1, -- versión del texto, no de estado
    status        VARCHAR(10)  NOT NULL DEFAULT 'draft',
    author_id     CHAR(36)     NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    published_at  DATETIME     NULL,
    archived_at   DATETIME     NULL,
    PRIMARY KEY (id),
    KEY idx_contents_workshop (workshop_id),
    CONSTRAINT fk_ct_workshop FOREIGN KEY (workshop_id) REFERENCES workshops(id) ON DELETE RESTRICT,
    CONSTRAINT fk_ct_author   FOREIGN KEY (author_id)   REFERENCES users(id),
    CONSTRAINT ck_ct_kind   CHECK (kind IN ('text','audio','video','tip')),
    CONSTRAINT ck_ct_status CHECK (status IN ('draft','in_review','approved','published','archived')),
    KEY idx_contents_status (status),
    CONSTRAINT ck_ct_version CHECK (version >= 1 AND content_revision >= 1),
    CONSTRAINT ck_ct_sort CHECK (sort_order >= 0),
    CONSTRAINT ck_ct_body_len CHECK (body IS NULL OR CHAR_LENGTH(body) <= 100000),
    CONSTRAINT ck_ct_media_https CHECK (media_url IS NULL OR REGEXP_LIKE(media_url, '^https://[^[:space:]]+$', 'c')),
    CONSTRAINT ck_ct_published CHECK (status <> 'published' OR published_at IS NOT NULL),
    CONSTRAINT ck_ct_archived CHECK (archived_at IS NULL OR archived_at >= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE content_reviews (
    id           CHAR(36)    NOT NULL DEFAULT (UUID()),
    content_id   CHAR(36)    NOT NULL,
    reviewer_id  CHAR(36)    NOT NULL,
    decision     VARCHAR(10) NOT NULL,
    comment      TEXT,
    reviewed_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_version INT       NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    CONSTRAINT fk_cr_content  FOREIGN KEY (content_id)  REFERENCES contents(id) ON DELETE RESTRICT,
    CONSTRAINT fk_cr_reviewer FOREIGN KEY (reviewer_id) REFERENCES users(id),
    CONSTRAINT ck_cr_decision CHECK (decision IN ('approved','rejected','changes')),
    KEY idx_cr_content_decision (content_id, decision, review_version),
    CONSTRAINT ck_cr_version CHECK (review_version >= 1),
    CONSTRAINT ck_cr_comment CHECK (comment IS NULL OR CHAR_LENGTH(comment) <= 4000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE landing_slides (
    id         CHAR(36)     NOT NULL DEFAULT (UUID()),
    title      VARCHAR(150) NOT NULL,
    image_url  TEXT         NOT NULL,
    cta_label  VARCHAR(60)  NULL,
    cta_url    TEXT         NULL,
    sort_order INT          NOT NULL DEFAULT 0,
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT ck_ls_image_https CHECK (REGEXP_LIKE(image_url, '^https://[^[:space:]]+$', 'c')),
    CONSTRAINT ck_ls_cta_https CHECK (cta_url IS NULL OR REGEXP_LIKE(cta_url, '^https://[^[:space:]]+$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 6. COHORTES E INSCRIPCIONES
-- ---------------------------------------------------------------------
CREATE TABLE cohorts (
    id              CHAR(36)     NOT NULL DEFAULT (UUID()),
    workshop_id     CHAR(36)     NOT NULL,
    tenant_id       CHAR(36)     NULL,
    name            VARCHAR(100) NOT NULL,
    facilitator_id  CHAR(36)     NULL,
    starts_on       DATE         NULL,
    ends_on         DATE         NULL,
    status          VARCHAR(10)  NOT NULL DEFAULT 'planned',
    capacity        INT UNSIGNED NULL,
    active_enrollments INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT fk_co_workshop    FOREIGN KEY (workshop_id)    REFERENCES workshops(id),
    CONSTRAINT fk_co_tenant      FOREIGN KEY (tenant_id)      REFERENCES tenants(id),
    CONSTRAINT fk_co_facilitator FOREIGN KEY (facilitator_id) REFERENCES users(id),
    CONSTRAINT ck_co_status CHECK (status IN ('planned','active','finished','paused')),
    UNIQUE KEY uq_co_id_workshop (id, workshop_id),
    KEY idx_co_tenant_status (tenant_id, status),
    CONSTRAINT ck_co_dates CHECK (starts_on IS NULL OR ends_on IS NULL OR ends_on >= starts_on),
    CONSTRAINT ck_co_capacity CHECK (capacity IS NULL OR (capacity > 0 AND active_enrollments <= capacity))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE enrollments (
    id            CHAR(36)     NOT NULL DEFAULT (UUID()),
    user_id       CHAR(36)     NOT NULL,
    workshop_id   CHAR(36)     NOT NULL,
    cohort_id     CHAR(36)     NULL,
    public_code   VARCHAR(64)  NULL,                        -- Pseudónimo en programas B2B/B2G
    status        VARCHAR(10)  NOT NULL DEFAULT 'active',
    progress_pct  DECIMAL(5,2) NOT NULL DEFAULT 0,
    enrolled_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at  DATETIME     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_enroll_user_workshop (user_id, workshop_id),
    KEY idx_enroll_cohort (cohort_id),
    CONSTRAINT fk_en_user     FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_en_workshop FOREIGN KEY (workshop_id) REFERENCES workshops(id),
    CONSTRAINT fk_en_cohort   FOREIGN KEY (cohort_id, workshop_id) REFERENCES cohorts(id, workshop_id),
    CONSTRAINT ck_en_status   CHECK (status IN ('active','paused','completed','withdrawn')),
    CONSTRAINT ck_en_progress CHECK (progress_pct BETWEEN 0 AND 100),
    UNIQUE KEY uq_enroll_public_code (public_code),
    KEY idx_enroll_user_status (user_id, status),
    KEY idx_enroll_cohort_progress (cohort_id, progress_pct),
    CONSTRAINT ck_en_100 CHECK (progress_pct < 100 OR status = 'completed'),
    CONSTRAINT ck_en_completed CHECK (status <> 'completed' OR (progress_pct = 100 AND completed_at IS NOT NULL)),
    CONSTRAINT ck_en_completion_date CHECK (completed_at IS NULL OR completed_at >= enrolled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 7. PLAN SEMANAL, ACTIVIDADES Y REVISIONES (R1 Core)
-- ---------------------------------------------------------------------
CREATE TABLE weekly_plans (
    id          CHAR(36)  NOT NULL DEFAULT (UUID()),
    user_id     CHAR(36)  NOT NULL,
    route_id    SMALLINT  NOT NULL,
    week_start  DATE      NOT NULL,
    goal        TEXT,
    revision    INT       NOT NULL DEFAULT 1,               -- Control de concurrencia (ADG-API-01)
    updated_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    archived_at DATETIME  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_plan_week (user_id, route_id, week_start),
    CONSTRAINT fk_wp_user  FOREIGN KEY (user_id)  REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_wp_route FOREIGN KEY (route_id) REFERENCES routes(id),
    CONSTRAINT ck_wp_monday CHECK (DAYOFWEEK(week_start) = 2),
    CONSTRAINT ck_wp_rev CHECK (revision >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE activities (
    id             CHAR(36)     NOT NULL DEFAULT (UUID()),
    plan_id        CHAR(36)     NOT NULL,
    title          VARCHAR(150) NOT NULL,
    dimension      VARCHAR(25)  NULL,
    scheduled_for  DATETIME     NULL,
    status         VARCHAR(12)  NOT NULL DEFAULT 'pending',
    version        INT          NOT NULL DEFAULT 1,         -- Validación If-Match en PATCH
    updated_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    completed_at   DATETIME     NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_ac_plan FOREIGN KEY (plan_id) REFERENCES weekly_plans(id) ON DELETE CASCADE,
    CONSTRAINT ck_ac_status CHECK (status IN ('pending','planned','completed','postponed','rescheduled','paused')),
    KEY idx_act_plan_status (plan_id, status),
    CONSTRAINT ck_ac_dimension CHECK (dimension IS NULL OR dimension IN ('movimiento','descanso','alimentacion','conexion_social','proposito','aprendizaje')),
    CONSTRAINT ck_ac_version CHECK (version >= 1),
    CONSTRAINT ck_ac_completed CHECK (status <> 'completed' OR completed_at IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Revisión voluntaria de fin de semana (API-015 / ADG-DAT-01)
CREATE TABLE weekly_reviews (
    id               CHAR(36)     NOT NULL DEFAULT (UUID()),
    plan_id          CHAR(36)     NOT NULL,
    user_id          CHAR(36)     NOT NULL,
    useful           BOOLEAN      NULL,
    next_adjustment  VARCHAR(200) NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_review_plan (plan_id),
    CONSTRAINT fk_wr_plan FOREIGN KEY (plan_id) REFERENCES weekly_plans(id) ON DELETE CASCADE,
    CONSTRAINT fk_wr_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Check-ins y notas: datos PRIVADOS D3 (restringidos al personal)
CREATE TABLE checkins (
    id          CHAR(36)  NOT NULL DEFAULT (UUID()),
    user_id     CHAR(36)  NOT NULL,
    mood        SMALLINT  NULL,
    note_enc     VARBINARY(8192) NULL, -- AES-256-GCM ciphertext (cifrar en backend)
    note_nonce   BINARY(12)  NULL,
    note_tag     BINARY(16)  NULL,
    note_key_id  VARCHAR(80) NULL,
    created_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_chk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_chk_mood CHECK (mood BETWEEN 1 AND 5),
    KEY idx_chk_user_date (user_id, created_at DESC),
    CONSTRAINT ck_chk_payload CHECK (
        (note_enc IS NULL AND note_nonce IS NULL AND note_tag IS NULL AND note_key_id IS NULL AND mood IS NOT NULL)
        OR (note_enc IS NOT NULL AND note_nonce IS NOT NULL AND note_tag IS NOT NULL AND note_key_id IS NOT NULL AND OCTET_LENGTH(note_enc) BETWEEN 1 AND 8192)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 8. MÓDULOS EN DESARROLLO PARALELO: R2 (FINANZAS) Y R3 (CARRERA)
-- ---------------------------------------------------------------------
CREATE TABLE educational_budgets (
    id                    CHAR(36) NOT NULL DEFAULT (UUID()),
    user_id               CHAR(36) NOT NULL,
    period_month          CHAR(7)  NOT NULL,                -- Formato YYYY-MM
    currency              CHAR(3)  NOT NULL DEFAULT 'PEN',
    monthly_amount_minor  BIGINT   NOT NULL DEFAULT 0,      -- En céntimos (sin float)
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    planned_total_minor   BIGINT   NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uq_budget_period (user_id, period_month),
    CONSTRAINT fk_eb_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_eb_amount CHECK (monthly_amount_minor BETWEEN 0 AND 999999999),
    CONSTRAINT ck_eb_planned CHECK (planned_total_minor BETWEEN 0 AND monthly_amount_minor),
    CONSTRAINT ck_eb_month CHECK (REGEXP_LIKE(period_month, '^[0-9]{4}-(0[1-9]|1[0-2])$', 'c')),
    CONSTRAINT ck_eb_ccy CHECK (REGEXP_LIKE(currency, '^[A-Z]{3}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE budget_categories (
    id                    CHAR(36)     NOT NULL DEFAULT (UUID()),
    budget_id             CHAR(36)     NOT NULL,
    label                 VARCHAR(100) NOT NULL,
    planned_amount_minor  BIGINT       NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT fk_bc_budget FOREIGN KEY (budget_id) REFERENCES educational_budgets(id) ON DELETE CASCADE,
    CONSTRAINT ck_bc_amount CHECK (planned_amount_minor BETWEEN 0 AND 999999999),
    KEY idx_bc_budget (budget_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE financial_goals (
    id                   CHAR(36)     NOT NULL DEFAULT (UUID()),
    user_id              CHAR(36)     NOT NULL,
    title                VARCHAR(160) NOT NULL,
    currency             CHAR(3)      NOT NULL DEFAULT 'PEN',
    target_amount_minor  BIGINT       NULL,
    due_date             DATE         NULL,
    status               VARCHAR(12)  NOT NULL DEFAULT 'active',
    created_at           DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at         DATETIME     NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_fg_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_fg_status CHECK (status IN ('active','paused','completed')),
    CONSTRAINT ck_fg_amount CHECK (target_amount_minor IS NOT NULL OR status = 'paused'),
    CONSTRAINT ck_fg_amount_range CHECK (target_amount_minor IS NULL OR target_amount_minor BETWEEN 0 AND 999999999999),
    CONSTRAINT ck_fg_due CHECK (due_date IS NULL OR due_date >= DATE(created_at)),
    CONSTRAINT ck_fg_ccy CHECK (REGEXP_LIKE(currency, '^[A-Z]{3}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE learning_plans (
    id          CHAR(36)     NOT NULL DEFAULT (UUID()),
    user_id     CHAR(36)     NOT NULL,
    goal        VARCHAR(160) NOT NULL,
    status      VARCHAR(12)  NOT NULL DEFAULT 'active',
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME    NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_lp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_lp_status CHECK (status IN ('active','paused','completed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE skill_goals (
    id                CHAR(36)    NOT NULL DEFAULT (UUID()),
    learning_plan_id  CHAR(36)    NOT NULL,
    skill_code        VARCHAR(64) NOT NULL,
    progress_state    VARCHAR(15) NOT NULL DEFAULT 'pending',
    completed_at      DATETIME    NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_sg_plan FOREIGN KEY (learning_plan_id) REFERENCES learning_plans(id) ON DELETE CASCADE,
    CONSTRAINT ck_sg_state CHECK (progress_state IN ('pending','in_progress','completed')),
    UNIQUE KEY uq_skill_plan_code (learning_plan_id, skill_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE opportunities (
    id           CHAR(36)     NOT NULL DEFAULT (UUID()),
    title        VARCHAR(200) NOT NULL,
    issuer       VARCHAR(150) NOT NULL,
    url          VARCHAR(500) NOT NULL,
    country      CHAR(2)      NOT NULL DEFAULT 'PE',
    verified_at  DATETIME     NOT NULL,
    expires_at   DATETIME     NOT NULL,
    deleted_at   DATETIME     NULL,
    PRIMARY KEY (id),
    KEY idx_opp_expires (expires_at),
    CONSTRAINT ck_opp_https CHECK (REGEXP_LIKE(url, '^https://[^[:space:]]+$', 'c')),
    CONSTRAINT ck_opp_dates CHECK (verified_at <= expires_at),
    CONSTRAINT ck_opp_country CHECK (REGEXP_LIKE(country, '^[A-Z]{2}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE saved_opportunities (
    user_id         CHAR(36) NOT NULL,
    opportunity_id  CHAR(36) NOT NULL,
    saved_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, opportunity_id),
    CONSTRAINT fk_so_user FOREIGN KEY (user_id)        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_so_opp  FOREIGN KEY (opportunity_id) REFERENCES opportunities(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 9. ALMA (chat persistente, sugerencias y recordatorios confirmados)
-- ---------------------------------------------------------------------
CREATE TABLE alma_conversations (
    id          CHAR(36)  NOT NULL DEFAULT (UUID()),
    user_id     CHAR(36)  NOT NULL,
    created_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at   DATETIME  NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_alc_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE alma_messages (
    id               CHAR(36)   NOT NULL DEFAULT (UUID()),
    conversation_id  CHAR(36)   NOT NULL,
    sender           VARCHAR(5) NOT NULL,
    body_enc         VARBINARY(8192) NOT NULL,
    body_nonce       BINARY(12)  NOT NULL,
    body_tag         BINARY(16)  NOT NULL,
    body_key_id      VARCHAR(80) NOT NULL,
    redacted_at      DATETIME   NULL,
    created_at       DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_alma_msg_conv (conversation_id, created_at),
    CONSTRAINT fk_alm_conv FOREIGN KEY (conversation_id) REFERENCES alma_conversations(id) ON DELETE CASCADE,
    CONSTRAINT ck_alm_sender CHECK (sender IN ('user','alma')),
    CONSTRAINT ck_alm_bodylen CHECK (OCTET_LENGTH(body_enc) BETWEEN 1 AND 8192)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE alma_reminders (
    id                CHAR(36)    NOT NULL DEFAULT (UUID()),
    user_id           CHAR(36)    NOT NULL,
    activity_id       CHAR(36)    NULL,
    remind_at         DATETIME    NOT NULL,
    confirmed_by_user BOOLEAN     NOT NULL DEFAULT FALSE,   -- Requiere confirmación explícita
    status            VARCHAR(10) NOT NULL DEFAULT 'draft',
    sent_at           DATETIME    NULL,
    cancelled_at      DATETIME    NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_rem_user     FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_rem_activity FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE SET NULL,
    CONSTRAINT ck_rem_status CHECK (status IN ('draft','scheduled','sent','cancelled','failed')),
    KEY idx_rem_pending (remind_at, status),
    CONSTRAINT ck_rem_confirmed CHECK (status <> 'scheduled' OR confirmed_by_user = TRUE)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 10. SOPORTE TÉCNICO Y FACILITACIÓN
-- ---------------------------------------------------------------------
CREATE TABLE support_tickets (
    id           CHAR(36)     NOT NULL DEFAULT (UUID()),
    user_id      CHAR(36)     NOT NULL,
    subject      VARCHAR(150) NOT NULL,
    category     VARCHAR(20)  NOT NULL DEFAULT 'technical',
    status       VARCHAR(12)  NOT NULL DEFAULT 'open',
    priority     VARCHAR(10)  NOT NULL DEFAULT 'medium',
    assigned_to  CHAR(36)     NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at    DATETIME     NULL,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_st_user     FOREIGN KEY (user_id)     REFERENCES users(id),
    CONSTRAINT fk_st_assigned FOREIGN KEY (assigned_to) REFERENCES users(id),
    CONSTRAINT ck_st_category CHECK (category IN ('technical','access_reset','facilitation','other')),
    CONSTRAINT ck_st_status   CHECK (status IN ('open','in_progress','resolved','closed')),
    KEY idx_tickets_user_status (user_id, status),
    KEY idx_tickets_assignee_status (assigned_to, status),
    CONSTRAINT ck_st_priority CHECK (priority IN ('low','medium','high','urgent'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE ticket_messages (
    id         CHAR(36)  NOT NULL DEFAULT (UUID()),
    ticket_id  CHAR(36)  NOT NULL,
    author_id  CHAR(36)  NOT NULL,
    body       TEXT      NOT NULL,
    created_at DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_tm_ticket FOREIGN KEY (ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE,
    CONSTRAINT fk_tm_author FOREIGN KEY (author_id) REFERENCES users(id),
    KEY idx_tm_ticket_date (ticket_id, created_at),
    CONSTRAINT ck_tm_length CHECK (CHAR_LENGTH(body) BETWEEN 1 AND 8000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 11. FEEDBACK Y FORMULARIOS PÚBLICOS (Captación y Alianzas)
-- ---------------------------------------------------------------------
CREATE TABLE content_feedback (
    id          CHAR(36)  NOT NULL DEFAULT (UUID()),
    user_id     CHAR(36)  NOT NULL,
    workshop_id CHAR(36)  NULL,
    content_id  CHAR(36)  NULL,
    rating      SMALLINT  NULL,
    comment     TEXT,
    created_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_cf_user     FOREIGN KEY (user_id)     REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_cf_workshop FOREIGN KEY (workshop_id) REFERENCES workshops(id),
    CONSTRAINT fk_cf_content  FOREIGN KEY (content_id)  REFERENCES contents(id),
    CONSTRAINT ck_cf_rating   CHECK (rating BETWEEN 1 AND 5),
    CONSTRAINT ck_cf_target   CHECK (workshop_id IS NOT NULL OR content_id IS NOT NULL),
    CONSTRAINT ck_cf_comment CHECK (comment IS NULL OR CHAR_LENGTH(comment) <= 4000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE pilot_applications (
    id                       CHAR(36)     NOT NULL DEFAULT (UUID()),
    contact_email            VARCHAR(255) NULL,
    contact_phone            VARCHAR(20)  NULL,
    source_ip                VARCHAR(45)  NULL,
    privacy_notice_accepted  BOOLEAN      NOT NULL DEFAULT FALSE,
    status                   VARCHAR(15)  NOT NULL DEFAULT 'received',
    created_at               DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT ck_pa_privacy CHECK (privacy_notice_accepted = TRUE),
    CONSTRAINT ck_pa_status  CHECK (status IN ('received','under_review','invited','rejected')),
    KEY idx_pa_status (status),
    CONSTRAINT ck_pa_contact CHECK (contact_email IS NOT NULL OR contact_phone IS NOT NULL),
    CONSTRAINT ck_pa_email CHECK (contact_email IS NULL OR (
        BINARY contact_email = BINARY LOWER(TRIM(contact_email)) AND
        REGEXP_LIKE(contact_email, '^[a-z0-9][a-z0-9._%+-]*@[a-z0-9][a-z0-9.-]*[.][a-z]{2,63}$', 'c')
    )),
    CONSTRAINT ck_pa_phone CHECK (contact_phone IS NULL OR REGEXP_LIKE(contact_phone, '^[+][1-9][0-9]{7,14}$', 'c'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE partnership_requests (
    id            CHAR(36)     NOT NULL DEFAULT (UUID()),
    org_name      VARCHAR(150) NOT NULL,
    org_type      VARCHAR(3)   NOT NULL,
    contact_name  VARCHAR(100) NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    message       TEXT,
    status        VARCHAR(12)  NOT NULL DEFAULT 'new',
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    assigned_to   CHAR(36)     NULL,
    source_ip     VARCHAR(45)  NULL,
    PRIMARY KEY (id),
    CONSTRAINT ck_pr_type   CHECK (org_type IN ('B2B','B2G')),
    CONSTRAINT ck_pr_status CHECK (status IN ('new','contacted','accepted','discarded')),
    KEY idx_pr_status (status),
    CONSTRAINT fk_pr_assigned FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT ck_pr_email CHECK (
        BINARY contact_email = BINARY LOWER(TRIM(contact_email)) AND
        REGEXP_LIKE(contact_email, '^[a-z0-9][a-z0-9._%+-]*@[a-z0-9][a-z0-9.-]*[.][a-z]{2,63}$', 'c')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE contact_messages (
    id         CHAR(36)     NOT NULL DEFAULT (UUID()),
    name       VARCHAR(100) NULL,
    email      VARCHAR(255) NOT NULL,
    message    TEXT         NOT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip  VARCHAR(45)  NULL,
    status     VARCHAR(12)  NOT NULL DEFAULT 'new',
    PRIMARY KEY (id),
    CONSTRAINT ck_cm_status CHECK (status IN ('new','read','replied')),
    CONSTRAINT ck_cm_email CHECK (
        BINARY email = BINARY LOWER(TRIM(email)) AND
        REGEXP_LIKE(email, '^[a-z0-9][a-z0-9._%+-]*@[a-z0-9][a-z0-9.-]*[.][a-z]{2,63}$', 'c')
    ),
    CONSTRAINT ck_cm_length CHECK (CHAR_LENGTH(message) BETWEEN 1 AND 5000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- 12. AUDITORÍA INALTERABLE E IDEMPOTENCIA API
-- ---------------------------------------------------------------------
CREATE TABLE admin_access_log (
    id         BIGINT      NOT NULL AUTO_INCREMENT,
    user_id    CHAR(36)    NOT NULL,
    role_id    SMALLINT    NOT NULL,
    event      VARCHAR(6)  NOT NULL,
    ip_address VARCHAR(45) NULL,
    event_at   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent VARCHAR(255) NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_aal_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT fk_aal_role FOREIGN KEY (role_id) REFERENCES roles(id),
    CONSTRAINT ck_aal_event CHECK (event IN ('login','logout')),
    KEY idx_aal_user_date (user_id, event_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE audit_log (
    id          BIGINT       NOT NULL AUTO_INCREMENT,
    actor_id    CHAR(36)     NULL,
    action      VARCHAR(60)  NOT NULL,
    entity      VARCHAR(60)  NULL,
    entity_id   VARCHAR(64)  NULL,
    detail      JSON         NULL,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    request_id  CHAR(36)     NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_al_actor FOREIGN KEY (actor_id) REFERENCES users(id),
    KEY idx_audit_entity (entity, entity_id),
    KEY idx_audit_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Control de claves Idempotency-Key para peticiones POST seguras (ADG-API-01)
CREATE TABLE idempotency_keys (
    idempotency_key VARCHAR(128) NOT NULL,
    user_id         CHAR(36)     NOT NULL,
    endpoint_path   VARCHAR(150) NOT NULL,
    response_status SMALLINT     NOT NULL,
    response_body_enc VARBINARY(8192) NULL, -- nunca persistir respuesta con PII sin cifrar
    response_nonce BINARY(12) NULL,
    response_tag BINARY(16) NULL,
    response_key_id VARCHAR(80) NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME     NOT NULL,
    PRIMARY KEY (idempotency_key, user_id, endpoint_path),
    CONSTRAINT fk_ik_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    KEY idx_ik_expires (expires_at),
    CONSTRAINT ck_ik_exp CHECK (expires_at > created_at),
    CONSTRAINT ck_ik_status CHECK (response_status BETWEEN 100 AND 599),
    CONSTRAINT ck_ik_payload CHECK (
        (response_body_enc IS NULL AND response_nonce IS NULL AND response_tag IS NULL AND response_key_id IS NULL) OR
        (response_body_enc IS NOT NULL AND response_nonce IS NOT NULL AND response_tag IS NOT NULL AND response_key_id IS NOT NULL AND OCTET_LENGTH(response_body_enc) BETWEEN 1 AND 8192)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- =====================================================================
-- 13. CUENTAS DE SERVICIO / DEFINER BLOQUEADO (bootstrap DBA/root)
-- =====================================================================
-- ACCOUNT LOCK = sin credenciales activas al instalar. El orquestador debe
-- establecer secretos con un gestor, limitar host/IP y desbloquear SOLO
-- las cuentas necesarias fuera de esta migración. NUNCA poner passwords aquí.
-- Un login distinto por agente de soporte/facilitador/gestor. No compartir el
-- login entre tenants. La inserción en db_access_principals es administrativa.
CREATE USER IF NOT EXISTS 'adisgea_definer'@'%' ACCOUNT LOCK;
CREATE USER IF NOT EXISTS 'adisgea_app'@'%' ACCOUNT LOCK;
CREATE USER IF NOT EXISTS 'adisgea_logger'@'%' ACCOUNT LOCK;
CREATE USER IF NOT EXISTS 'adisgea_migrator'@'%' ACCOUNT LOCK;
CREATE ROLE IF NOT EXISTS 'adisgea_support', 'adisgea_facilitator', 'adisgea_institution';

-- El DEFINER está bloqueado; solo se usa en vistas, triggers, eventos y rutinas.
GRANT SELECT, TRIGGER ON adisgea.* TO 'adisgea_definer'@'%';
GRANT INSERT ON adisgea.audit_log TO 'adisgea_definer'@'%';
GRANT UPDATE ON adisgea.cohorts TO 'adisgea_definer'@'%';
GRANT UPDATE ON adisgea.educational_budgets TO 'adisgea_definer'@'%';
GRANT UPDATE ON adisgea.contents TO 'adisgea_definer'@'%';
GRANT UPDATE ON adisgea.weekly_plans TO 'adisgea_definer'@'%';
GRANT UPDATE ON adisgea.activities TO 'adisgea_definer'@'%';
GRANT DELETE ON adisgea.auth_tokens TO 'adisgea_definer'@'%';
GRANT DELETE ON adisgea.email_change_requests TO 'adisgea_definer'@'%';
GRANT DELETE ON adisgea.idempotency_keys TO 'adisgea_definer'@'%';
GRANT DELETE ON adisgea.login_attempts TO 'adisgea_definer'@'%';
GRANT EVENT ON adisgea.* TO 'adisgea_definer'@'%';

-- =====================================================================
-- 14. TRIGGERS Y RUTINAS DE INTEGRIDAD Y AUDITORÍA
-- =====================================================================
DELIMITER $$

CREATE DEFINER = 'adisgea_definer'@'%' PROCEDURE sp_log_audit(
    IN p_actor CHAR(36), IN p_action VARCHAR(60),
    IN p_entity VARCHAR(60), IN p_entity_id VARCHAR(64), IN p_detail JSON
)
SQL SECURITY DEFINER
MODIFIES SQL DATA
BEGIN
    -- La invocación no se concede a cuentas de usuarios finales.
    -- Los triggers solo envían identificadores, estados y metadatos inocuos.
    INSERT INTO audit_log (actor_id, action, entity, entity_id, detail)
    VALUES (p_actor, p_action, p_entity, p_entity_id, p_detail);
END$$

-- Historial de passwords: no sobrescribir ni borrar sin proceso ARCO DBA.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_password_history_no_update
BEFORE UPDATE ON password_history FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='password_history es append-only';
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_password_history_no_delete
BEFORE DELETE ON password_history FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='password_history es append-only';
END$$

-- Inmutabilidad lógica: no concede DROP/ALTER/TRUNCATE sobre logs a la app.
-- TRUNCATE no dispara triggers, y root/DDL siempre puede borrar: réplica WORM.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_audit_no_update
BEFORE UPDATE ON audit_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit_log es inmutable';
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_audit_no_delete
BEFORE DELETE ON audit_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit_log es inmutable';
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_access_no_update
BEFORE UPDATE ON admin_access_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='admin_access_log es inmutable';
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_access_no_delete
BEFORE DELETE ON admin_access_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='admin_access_log es inmutable';
END$$

-- No se puede retirar el último factor activo mientras exista un rol crítico.
-- Para rotar un factor: registrar el sustituto, revocar el rol, desactivar
-- el factor anterior, y volver a asignar rol; la app también debe controlarlo.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_mfa_protect_update
BEFORE UPDATE ON user_mfa FOR EACH ROW
BEGIN
    IF OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL AND EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
       WHERE ur.user_id=OLD.user_id AND ur.revoked_at IS NULL
       AND r.code IN ('administrador','direccion','gestor_institucional','soporte')
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Revocar rol privilegiado antes de desactivar MFA';
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_mfa_protect_delete
BEFORE DELETE ON user_mfa FOR EACH ROW
BEGIN
    IF OLD.disabled_at IS NULL AND EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
       WHERE ur.user_id=OLD.user_id AND ur.revoked_at IS NULL
       AND r.code IN ('administrador','direccion','gestor_institucional','soporte')
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Revocar rol privilegiado antes de borrar MFA';
    END IF;
END$$

-- MFA antes de otorgar un rol privilegiado. La verificación del segundo factor
-- DURANTE CADA LOGIN se hace en backend; la existencia de un registro NO prueba
-- autenticación. Se bloquean también activaciones de roles previamente revocados.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_user_roles_mfa_insert
BEFORE INSERT ON user_roles FOR EACH ROW
BEGIN
    IF NEW.revoked_at IS NULL AND EXISTS (
        SELECT 1 FROM roles WHERE id=NEW.role_id AND code IN
        ('administrador','direccion','gestor_institucional','soporte')
    ) AND NOT EXISTS (
        SELECT 1 FROM user_mfa WHERE user_id=NEW.user_id AND disabled_at IS NULL
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='El rol privilegiado requiere MFA activo';
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_user_roles_mfa_update
BEFORE UPDATE ON user_roles FOR EACH ROW
BEGIN
    IF NEW.revoked_at IS NULL AND EXISTS (
        SELECT 1 FROM roles WHERE id=NEW.role_id AND code IN
        ('administrador','direccion','gestor_institucional','soporte')
    ) AND NOT EXISTS (
        SELECT 1 FROM user_mfa WHERE user_id=NEW.user_id AND disabled_at IS NULL
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='El rol privilegiado requiere MFA activo';
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_roles_audit_insert
AFTER INSERT ON user_roles FOR EACH ROW
BEGIN
    CALL sp_log_audit(NEW.granted_by, 'role_granted','user_roles',
        CONCAT(NEW.user_id,':',NEW.role_id), JSON_OBJECT('role_id',NEW.role_id,'revoked',NEW.revoked_at IS NOT NULL));
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_roles_audit_update
AFTER UPDATE ON user_roles FOR EACH ROW
BEGIN
    CALL sp_log_audit(NEW.revoked_by, 'role_updated','user_roles',
        CONCAT(NEW.user_id,':',NEW.role_id), JSON_OBJECT('role_id',NEW.role_id,
        'was_revoked', OLD.revoked_at IS NOT NULL,'is_revoked',NEW.revoked_at IS NOT NULL));
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_roles_audit_delete
AFTER DELETE ON user_roles FOR EACH ROW
BEGIN
    CALL sp_log_audit(NULL, 'role_deleted','user_roles',
        CONCAT(OLD.user_id,':',OLD.role_id),JSON_OBJECT('role_id',OLD.role_id));
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_consents_audit_insert
AFTER INSERT ON user_consents FOR EACH ROW
BEGIN
    CALL sp_log_audit(NULL,'consent_granted','user_consents',NEW.id,
      JSON_OBJECT('purpose_id',NEW.purpose_id,'notice_version',NEW.notice_version,'channel',NEW.channel));
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_consents_audit_update
AFTER UPDATE ON user_consents FOR EACH ROW
BEGIN
    CALL sp_log_audit(NEW.revoked_by,'consent_updated','user_consents',NEW.id,
      JSON_OBJECT('purpose_id',NEW.purpose_id,
       'was_revoked',OLD.revoked_at IS NOT NULL,'is_revoked',NEW.revoked_at IS NOT NULL));
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_consents_audit_delete
AFTER DELETE ON user_consents FOR EACH ROW
BEGIN
    CALL sp_log_audit(NULL,'consent_deleted','user_consents',OLD.id,
      JSON_OBJECT('purpose_id',OLD.purpose_id));
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_feature_flags_audit
AFTER UPDATE ON feature_flags FOR EACH ROW
BEGIN
    IF NOT (OLD.enabled <=> NEW.enabled) THEN
      CALL sp_log_audit(NEW.updated_by,'feature_flag_updated','feature_flags',NEW.flag_key,
           JSON_OBJECT('old_enabled',OLD.enabled,'new_enabled',NEW.enabled));
    END IF;
END$$

-- Conteo de versión incondicional. Un cliente debe hacer:
-- UPDATE contents SET ... WHERE id=? AND version=?; comprobar ROW_COUNT()=1.
-- No establecer version desde el cliente: lo controla solo el trigger.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_contents_before_insert
BEFORE INSERT ON contents FOR EACH ROW
BEGIN
    IF NEW.status='published' OR NEW.published_at IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='No publicar contenido desde INSERT';
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_contents_version
BEFORE UPDATE ON contents FOR EACH ROW
BEGIN
    IF NEW.version <> OLD.version OR OLD.version >= 2147483647 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='version de contenido manipulada o desbordada';
    END IF;
    SET NEW.version=OLD.version+1;
    IF NOT (NEW.title <=> OLD.title) OR NOT (NEW.body <=> OLD.body)
       OR NOT (NEW.media_url <=> OLD.media_url) OR NOT (NEW.source_ref <=> OLD.source_ref)
       OR NOT (NEW.kind <=> OLD.kind) OR NOT (NEW.workshop_id <=> OLD.workshop_id)
       OR NOT (NEW.author_id <=> OLD.author_id) THEN
       SET NEW.content_revision=OLD.content_revision+1;
    ELSE
       IF NEW.content_revision<>OLD.content_revision THEN
           SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='content_revision no puede modificarse';
       END IF;
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_contents_publish_guard
BEFORE UPDATE ON contents FOR EACH ROW FOLLOWS trg_contents_version
BEGIN
    DECLARE v_approved INT DEFAULT 0;
    -- Cambiar un contenido publicado invalida aprobación: retirar primero a borrador.
    IF NEW.status='published' THEN
      IF NOT (NEW.title <=> OLD.title)
          OR NOT (NEW.body <=> OLD.body)
          OR NOT (NEW.media_url <=> OLD.media_url)
          OR NOT (NEW.source_ref <=> OLD.source_ref)
          OR NOT (NEW.kind <=> OLD.kind)
          OR NOT (NEW.workshop_id <=> OLD.workshop_id)
          OR NOT (NEW.author_id <=> OLD.author_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Contenido publicado no puede cambiar sin nueva revisión';
      END IF;
      IF OLD.status <> 'published' THEN
        IF OLD.status NOT IN ('in_review','approved') THEN
          SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='La publicación exige estado revisado';
        END IF;
        SELECT COUNT(*) INTO v_approved FROM content_reviews
         WHERE content_id=OLD.id AND decision='approved' AND review_version=OLD.content_revision;
        IF v_approved=0 THEN
          SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='No se puede publicar sin revisión aprobada para la versión vigente';
        END IF;
        IF NEW.published_at IS NULL THEN SET NEW.published_at=UTC_TIMESTAMP(); END IF;
      END IF;
    END IF;
    IF NEW.status='archived' AND NEW.archived_at IS NULL THEN
       SET NEW.archived_at=UTC_TIMESTAMP();
    END IF;
END$$

-- Las revisiones apuntan a content_revision exacta y solo especialistas/dirección
-- distintos del autor pueden aprobar. Append-only: no UPDATE/DELETE.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_content_reviews_valid
BEFORE INSERT ON content_reviews FOR EACH ROW
BEGIN
    DECLARE v_ver INT DEFAULT NULL;
    DECLARE v_status VARCHAR(10);
    DECLARE v_author CHAR(36);
    SELECT content_revision,status,author_id INTO v_ver,v_status,v_author
      FROM contents WHERE id=NEW.content_id;
    IF v_ver IS NULL OR NEW.review_version<>v_ver OR v_status NOT IN ('in_review','approved') THEN
       SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Revisión de versión o estado inválidos';
    END IF;
    IF NEW.reviewer_id=v_author OR NOT EXISTS (
        SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
        JOIN users u ON u.id=ur.user_id
        WHERE ur.user_id=NEW.reviewer_id AND ur.revoked_at IS NULL
          AND u.status='active' AND r.code IN ('direccion','editora_especialista')
    ) THEN
       SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='El revisor debe ser un especialista autorizado distinto al autor';
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_content_reviews_no_update
BEFORE UPDATE ON content_reviews FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='content_reviews es append-only';
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_content_reviews_no_delete
BEFORE DELETE ON content_reviews FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='content_reviews es append-only';
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_contents_audit_status
AFTER UPDATE ON contents FOR EACH ROW
BEGIN
    IF NOT (OLD.status <=> NEW.status) THEN
      CALL sp_log_audit(NULL,'content_status_changed','contents',NEW.id,
         JSON_OBJECT('old_status',OLD.status,'new_status',NEW.status,
                     'reviewed_content_version',OLD.content_revision));
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_weekly_plans_revision
BEFORE UPDATE ON weekly_plans FOR EACH ROW
BEGIN
    IF NEW.revision<>OLD.revision OR OLD.revision>=2147483647 THEN
       SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='revision semanal manipulada o desbordada';
    END IF;
    SET NEW.revision=OLD.revision+1;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_activities_version
BEFORE UPDATE ON activities FOR EACH ROW
BEGIN
    IF NEW.version<>OLD.version OR OLD.version>=2147483647 THEN
       SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='version actividad manipulada o desbordada';
    END IF;
    SET NEW.version=OLD.version+1;
END$$

-- Consentimiento de seguimiento: registros de progreso > 0 solo si consentimiento vigente.
-- Población de cohortes: contabilidad transaccional mediante UPDATE atómico del padre.
-- Capacidad reservada para estados active/paused; completed/withdrawn liberan cupo.
-- Las actualizaciones concurrentes sobre una misma cohorte se serializan con InnoDB.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_enrollments_before_insert
BEFORE INSERT ON enrollments FOR EACH ROW
BEGIN
    DECLARE v_membership INT DEFAULT 0;
    DECLARE v_consent INT DEFAULT 0;
    IF NEW.cohort_id IS NOT NULL THEN
      SELECT COUNT(*) INTO v_membership FROM cohorts c JOIN users u ON u.id=NEW.user_id
       WHERE c.id=NEW.cohort_id AND c.workshop_id=NEW.workshop_id
         AND (c.tenant_id <=> u.tenant_id);
      IF v_membership<>1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Cohorte, taller y tenant no coinciden';
      END IF;
    END IF;
    IF NEW.progress_pct>0 THEN
      SELECT COUNT(*) INTO v_consent FROM user_consents uc
      JOIN consent_purposes cp ON cp.id=uc.purpose_id
       WHERE uc.user_id=NEW.user_id AND uc.revoked_at IS NULL
         AND cp.code='progress_tracking'
         AND (cp.valid_to IS NULL OR cp.valid_to>UTC_TIMESTAMP());
      IF v_consent=0 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Falta consentimiento para seguimiento'; END IF;
    END IF;
    IF NEW.cohort_id IS NOT NULL AND NEW.status IN ('active','paused') THEN
      UPDATE cohorts SET active_enrollments=active_enrollments+1
       WHERE id=NEW.cohort_id AND (capacity IS NULL OR active_enrollments<capacity);
      IF ROW_COUNT()<>1 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Cohorte sin cupos disponibles';
      END IF;
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_enrollments_before_update
BEFORE UPDATE ON enrollments FOR EACH ROW
BEGIN
    DECLARE v_membership INT DEFAULT 0;
    DECLARE v_consent INT DEFAULT 0;
    IF NEW.cohort_id IS NOT NULL THEN
      SELECT COUNT(*) INTO v_membership FROM cohorts c JOIN users u ON u.id=NEW.user_id
       WHERE c.id=NEW.cohort_id AND c.workshop_id=NEW.workshop_id
         AND (c.tenant_id <=> u.tenant_id);
      IF v_membership<>1 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Cohorte, taller y tenant no coinciden'; END IF;
    END IF;
    IF NEW.progress_pct>0 AND (OLD.progress_pct<>NEW.progress_pct OR OLD.user_id<>NEW.user_id) THEN
      SELECT COUNT(*) INTO v_consent FROM user_consents uc
      JOIN consent_purposes cp ON cp.id=uc.purpose_id
       WHERE uc.user_id=NEW.user_id AND uc.revoked_at IS NULL
         AND cp.code='progress_tracking'
         AND (cp.valid_to IS NULL OR cp.valid_to>UTC_TIMESTAMP());
      IF v_consent=0 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Falta consentimiento para seguimiento'; END IF;
    END IF;
    -- Orden fijo de decremento/incremento; deadlocks multi-cohorte deben reintentarse.
    IF OLD.cohort_id IS NOT NULL AND OLD.status IN ('active','paused')
       AND (NOT (OLD.cohort_id <=> NEW.cohort_id) OR NEW.status NOT IN ('active','paused')) THEN
      UPDATE cohorts SET active_enrollments=active_enrollments-1
       WHERE id=OLD.cohort_id AND active_enrollments>0;
      IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Conteo de cohorte inconsistente'; END IF;
    END IF;
    IF NEW.cohort_id IS NOT NULL AND NEW.status IN ('active','paused')
       AND (NOT (OLD.cohort_id <=> NEW.cohort_id) OR OLD.status NOT IN ('active','paused')) THEN
      UPDATE cohorts SET active_enrollments=active_enrollments+1
       WHERE id=NEW.cohort_id AND (capacity IS NULL OR active_enrollments<capacity);
      IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Cohorte sin cupos disponibles'; END IF;
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_enrollments_before_delete
BEFORE DELETE ON enrollments FOR EACH ROW
BEGIN
    IF OLD.cohort_id IS NOT NULL AND OLD.status IN ('active','paused') THEN
      UPDATE cohorts SET active_enrollments=active_enrollments-1
       WHERE id=OLD.cohort_id AND active_enrollments>0;
      IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Conteo de cohorte inconsistente'; END IF;
    END IF;
END$$

-- Presupuesto: suma de categorías controlada por columna de acumulación del padre;
-- el UPDATE es atómico y el CHECK del presupuesto impide reducir el límite.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_budget_cat_insert
BEFORE INSERT ON budget_categories FOR EACH ROW
BEGIN
    IF NEW.planned_amount_minor>0 THEN
      UPDATE educational_budgets
         SET planned_total_minor=planned_total_minor+NEW.planned_amount_minor
       WHERE id=NEW.budget_id
         AND planned_total_minor+NEW.planned_amount_minor<=monthly_amount_minor;
      IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
         SET MESSAGE_TEXT='La suma de categorías supera el presupuesto'; END IF;
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_budget_cat_update
BEFORE UPDATE ON budget_categories FOR EACH ROW
BEGIN
    IF OLD.budget_id=NEW.budget_id THEN
      -- UPDATE que no altera el importe no requiere escribir contador.
      IF OLD.planned_amount_minor<>NEW.planned_amount_minor THEN
        UPDATE educational_budgets
           SET planned_total_minor=planned_total_minor-OLD.planned_amount_minor+NEW.planned_amount_minor
         WHERE id=NEW.budget_id
           AND planned_total_minor>=OLD.planned_amount_minor
           AND planned_total_minor-OLD.planned_amount_minor+NEW.planned_amount_minor<=monthly_amount_minor;
        IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
           SET MESSAGE_TEXT='Límite presupuesto o contador inconsistente'; END IF;
      END IF;
    ELSE
      IF OLD.planned_amount_minor>0 THEN
        UPDATE educational_budgets SET planned_total_minor=planned_total_minor-OLD.planned_amount_minor
         WHERE id=OLD.budget_id AND planned_total_minor>=OLD.planned_amount_minor;
        IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT='Contador presupuesto anterior inconsistente'; END IF;
      END IF;
      IF NEW.planned_amount_minor>0 THEN
        UPDATE educational_budgets SET planned_total_minor=planned_total_minor+NEW.planned_amount_minor
         WHERE id=NEW.budget_id AND planned_total_minor+NEW.planned_amount_minor<=monthly_amount_minor;
        IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT='Presupuesto destino sin saldo'; END IF;
      END IF;
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_budget_cat_delete
BEFORE DELETE ON budget_categories FOR EACH ROW
BEGIN
    IF OLD.planned_amount_minor>0 THEN
      UPDATE educational_budgets SET planned_total_minor=planned_total_minor-OLD.planned_amount_minor
       WHERE id=OLD.budget_id AND planned_total_minor>=OLD.planned_amount_minor;
      IF ROW_COUNT()<>1 THEN SIGNAL SQLSTATE '45000'
          SET MESSAGE_TEXT='Contador presupuesto inconsistente'; END IF;
    END IF;
END$$

-- ALMA: solo usuarias con consentimiento vigente pueden abrir conversaciones.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_alma_consent_guard
BEFORE INSERT ON alma_conversations FOR EACH ROW
BEGIN
    IF NOT EXISTS (
       SELECT 1 FROM user_consents uc JOIN consent_purposes cp ON cp.id=uc.purpose_id
        WHERE uc.user_id=NEW.user_id AND uc.revoked_at IS NULL AND cp.code='alma_chat'
          AND (cp.valid_to IS NULL OR cp.valid_to>UTC_TIMESTAMP())
    ) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Se requiere consentimiento ALMA';
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_alma_reminder_owner_insert
BEFORE INSERT ON alma_reminders FOR EACH ROW
BEGIN
    IF NEW.activity_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM activities a JOIN weekly_plans p ON p.id=a.plan_id
      WHERE a.id=NEW.activity_id AND p.user_id=NEW.user_id
    ) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Actividad de recordatorio ajena'; END IF;
    IF NEW.status='scheduled' AND NOT EXISTS (
      SELECT 1 FROM notification_preferences np WHERE np.user_id=NEW.user_id
        AND np.reminders_enabled=TRUE AND (np.email_enabled=TRUE OR np.push_enabled=TRUE)
    ) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Canal de recordatorios desactivado'; END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_alma_reminder_owner_update
BEFORE UPDATE ON alma_reminders FOR EACH ROW
BEGIN
    IF NEW.activity_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM activities a JOIN weekly_plans p ON p.id=a.plan_id
      WHERE a.id=NEW.activity_id AND p.user_id=NEW.user_id
    ) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Actividad de recordatorio ajena'; END IF;
    IF NEW.status='scheduled' AND NOT EXISTS (
      SELECT 1 FROM notification_preferences np WHERE np.user_id=NEW.user_id
        AND np.reminders_enabled=TRUE AND (np.email_enabled=TRUE OR np.push_enabled=TRUE)
    ) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Canal de recordatorios desactivado'; END IF;
END$$

-- No se atribuye un acceso administrativo a un rol revocado/ajeno.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_admin_access_role_guard
BEFORE INSERT ON admin_access_log FOR EACH ROW
BEGIN
    IF NOT EXISTS (
       SELECT 1 FROM user_roles ur JOIN users u ON u.id=ur.user_id
        WHERE ur.user_id=NEW.user_id AND ur.role_id=NEW.role_id
          AND ur.revoked_at IS NULL AND u.status='active'
    ) THEN SIGNAL SQLSTATE '45000'
       SET MESSAGE_TEXT='No se puede registrar acceso con rol inactivo o ajeno'; END IF;
END$$

-- La asignación de tickets requiere soporte activo del MISMO tenant.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_support_assign_insert
BEFORE INSERT ON support_tickets FOR EACH ROW
BEGIN
    IF NEW.assigned_to IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM users subject JOIN users agent ON agent.id=NEW.assigned_to
       JOIN user_roles ur ON ur.user_id=agent.id AND ur.revoked_at IS NULL
       JOIN roles r ON r.id=ur.role_id AND r.code='soporte'
       WHERE subject.id=NEW.user_id AND agent.status='active'
         AND (subject.tenant_id <=> agent.tenant_id)
    ) THEN SIGNAL SQLSTATE '45000'
       SET MESSAGE_TEXT='Soporte no autorizado para el tenant del ticket'; END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_support_assign_update
BEFORE UPDATE ON support_tickets FOR EACH ROW
BEGIN
    IF NEW.assigned_to IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM users subject JOIN users agent ON agent.id=NEW.assigned_to
       JOIN user_roles ur ON ur.user_id=agent.id AND ur.revoked_at IS NULL
       JOIN roles r ON r.id=ur.role_id AND r.code='soporte'
       WHERE subject.id=NEW.user_id AND agent.status='active'
         AND (subject.tenant_id <=> agent.tenant_id)
    ) THEN SIGNAL SQLSTATE '45000'
       SET MESSAGE_TEXT='Soporte no autorizado para el tenant del ticket'; END IF;
END$$

-- No trasladar usuarios/cohortes con inscripciones vigentes a otro tenant.
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_user_tenant_guard
BEFORE UPDATE ON users FOR EACH ROW
BEGIN
    IF NOT (OLD.tenant_id <=> NEW.tenant_id)
      AND EXISTS (SELECT 1 FROM enrollments WHERE user_id=OLD.id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='No cambiar el tenant de usuarios inscritos';
    END IF;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_cohort_tenant_guard
BEFORE UPDATE ON cohorts FOR EACH ROW
BEGIN
    IF (NOT (OLD.tenant_id <=> NEW.tenant_id) OR OLD.workshop_id<>NEW.workshop_id)
      AND EXISTS (SELECT 1 FROM enrollments WHERE cohort_id=OLD.id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='No cambiar tenant/taller de una cohorte inscrita';
    END IF;
END$$

CREATE DEFINER = 'adisgea_definer'@'%' TRIGGER trg_support_tickets_audit
AFTER UPDATE ON support_tickets FOR EACH ROW
BEGIN
    IF NOT (OLD.status <=> NEW.status) OR NOT (OLD.assigned_to <=> NEW.assigned_to) THEN
      CALL sp_log_audit(NULL,'ticket_changed','support_tickets',NEW.id,
        JSON_OBJECT('old_status',OLD.status,'new_status',NEW.status,
        'assignment_changed',NOT(OLD.assigned_to <=> NEW.assigned_to)));
    END IF;
END$$

-- La base de datos no puede hacer CAPTCHA ni verificar Argon2/bcrypt/TOTP:
-- middleware aplica de forma atómica LOCKOUT (5 fallos / 15 min),
-- verifica MFA real y registra cada intento. Procedure para consulta de umbral.
CREATE DEFINER = 'adisgea_definer'@'%' PROCEDURE sp_login_rate_status(
    IN p_identifier_hmac BINARY(32), IN p_ip_address VARCHAR(45)
)
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
    DECLARE v_identifier_count INT DEFAULT 0;
    DECLARE v_ip_count INT DEFAULT 0;
    SELECT COUNT(*) INTO v_identifier_count FROM login_attempts
    WHERE identifier_hmac=p_identifier_hmac AND success=FALSE
      AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 15 MINUTE;
    IF p_ip_address IS NOT NULL THEN
       SELECT COUNT(*) INTO v_ip_count FROM login_attempts
       WHERE ip_address=p_ip_address AND success=FALSE
       AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 15 MINUTE;
    END IF;
    SELECT v_identifier_count AS failures_identifier_15m,
           v_ip_count AS failures_ip_15m,
           IF(v_identifier_count>=5 OR v_ip_count>=20,1,0) AS should_throttle;
END$$

-- Consultas cerradas: los parámetros no conceden identidad ni autorizan tenant.
-- USER() identifica el login MySQL; cuenta dedicada mapeada por un DBA.
-- Se valida el rol aplicativo activo y que el recurso tenga el mismo tenant.
CREATE DEFINER = 'adisgea_definer'@'%' PROCEDURE sp_support_user_basic(IN p_ticket_id CHAR(36))
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
    SELECT v.id, v.username, v.email, v.status, v.created_at
    FROM v_support_user_basic v
    JOIN support_tickets t ON t.user_id=v.id
    JOIN db_access_principals p ON p.login_name=SUBSTRING_INDEX(USER(), '@', 1)
    WHERE t.id=p_ticket_id AND t.status IN ('open','in_progress')
      AND t.assigned_to=p.user_id AND p.enabled=TRUE;
END$$
CREATE DEFINER = 'adisgea_definer'@'%' PROCEDURE sp_cohort_progress(IN p_tenant_id CHAR(36))
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
    SELECT cohort_id, name, tenant_id, participants, avg_progress_pct
      FROM v_cohort_progress WHERE tenant_id=p_tenant_id;
END$$

DELIMITER ;

-- =====================================================================
-- 15. VISTAS DE SOLO LECTURA (SQL SECURITY DEFINER + TEMPTABLE)
-- =====================================================================
-- Sin filas para conexiones no identificadas en db_access_principals.
-- Los objetos nunca deben recibir GRANT UPDATE/DELETE/INSERT.
CREATE OR REPLACE ALGORITHM=TEMPTABLE DEFINER='adisgea_definer'@'%'
SQL SECURITY DEFINER VIEW v_support_user_basic AS
SELECT DISTINCT u.id, u.username, u.email, u.status, u.created_at
FROM support_tickets st
JOIN users u ON u.id=st.user_id
JOIN db_access_principals p ON p.login_name=SUBSTRING_INDEX(USER(), '@', 1) AND p.enabled=TRUE
JOIN users agent ON agent.id=p.user_id
WHERE st.assigned_to=agent.id AND st.status IN ('open','in_progress')
  AND agent.status='active' AND agent.deleted_at IS NULL
  AND (agent.tenant_id <=> u.tenant_id)
  AND EXISTS (
    SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
     WHERE ur.user_id=agent.id AND ur.revoked_at IS NULL AND r.code='soporte'
  );

CREATE OR REPLACE ALGORITHM=TEMPTABLE DEFINER='adisgea_definer'@'%'
SQL SECURITY DEFINER VIEW v_cohort_progress AS
SELECT c.id AS cohort_id, c.name, c.tenant_id,
       COUNT(DISTINCT e.id) AS participants,
       ROUND(AVG(e.progress_pct),1) AS avg_progress_pct
FROM cohorts c
JOIN enrollments e ON e.cohort_id=c.id AND e.status<>'withdrawn'
JOIN users participant ON participant.id=e.user_id AND participant.tenant_id=c.tenant_id
JOIN db_access_principals p ON p.login_name=SUBSTRING_INDEX(USER(), '@', 1) AND p.enabled=TRUE
JOIN users agent ON agent.id=p.user_id
WHERE c.tenant_id IS NOT NULL AND c.tenant_id=agent.tenant_id
  AND agent.status='active' AND agent.deleted_at IS NULL
  AND EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
       WHERE ur.user_id=agent.id AND ur.revoked_at IS NULL
         AND (r.code IN ('gestor_institucional','direccion')
              OR (r.code='facilitadora' AND c.facilitator_id=agent.id))
  )
GROUP BY c.id,c.name,c.tenant_id
HAVING COUNT(DISTINCT e.id)>=10;

CREATE OR REPLACE ALGORITHM=TEMPTABLE DEFINER='adisgea_definer'@'%'
SQL SECURITY DEFINER VIEW v_workshop_feedback AS
SELECT w.id AS workshop_id, w.title,
       COUNT(DISTINCT f.id) AS responses,
       ROUND(AVG(f.rating),2) AS avg_rating
FROM workshops w
JOIN content_feedback f ON f.workshop_id=w.id
JOIN users participant ON participant.id=f.user_id
JOIN db_access_principals p ON p.login_name=SUBSTRING_INDEX(USER(), '@', 1) AND p.enabled=TRUE
JOIN users agent ON agent.id=p.user_id
WHERE agent.status='active' AND agent.deleted_at IS NULL
  AND agent.tenant_id IS NOT NULL AND participant.tenant_id=agent.tenant_id
  AND EXISTS (
    SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
    WHERE ur.user_id=agent.id AND ur.revoked_at IS NULL
      AND r.code IN ('direccion','gestor_institucional')
  )
GROUP BY w.id,w.title
HAVING COUNT(DISTINCT f.id)>=5;

CREATE OR REPLACE ALGORITHM=TEMPTABLE DEFINER='adisgea_definer'@'%'
SQL SECURITY DEFINER VIEW v_facilitator_contents AS
SELECT ct.id, ct.workshop_id, ct.kind, ct.title, ct.version, ct.status,
       ct.updated_at
FROM contents ct
JOIN db_access_principals p ON p.login_name=SUBSTRING_INDEX(USER(),'@',1) AND p.enabled=TRUE
JOIN users agent ON agent.id=p.user_id
WHERE ct.author_id=agent.id AND agent.status='active' AND agent.deleted_at IS NULL
  AND ct.status IN ('draft','in_review','approved')
  AND EXISTS (
      SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
      WHERE ur.user_id=agent.id AND ur.revoked_at IS NULL
        AND r.code IN ('facilitadora','editora_especialista')
  );

-- =====================================================================
-- 16. PERMISOS: NO SE CONCEDEN TABLAS CON PII A ROLES DE CONSULTA
-- =====================================================================
GRANT SELECT ON adisgea.v_support_user_basic TO 'adisgea_support';
GRANT EXECUTE ON PROCEDURE adisgea.sp_support_user_basic TO 'adisgea_support';
GRANT SELECT ON adisgea.v_cohort_progress TO 'adisgea_facilitator', 'adisgea_institution';
GRANT EXECUTE ON PROCEDURE adisgea.sp_cohort_progress TO 'adisgea_facilitator', 'adisgea_institution';
GRANT SELECT ON adisgea.v_facilitator_contents TO 'adisgea_facilitator';
GRANT SELECT ON adisgea.v_workshop_feedback TO 'adisgea_institution';
-- NO dar SELECT/UPDATE de users, checkins, alma_messages ni contents base a estos roles.
-- Se concede el rol únicamente a operadores con cuentas MySQL individuales
-- y registro db_access_principals aprobado por DBA.

-- Cuenta backend privada, nunca conectada desde cliente público ni compartida
-- entre tenants de consulta. API DEBE validar identidad y tenant por operación,
-- e incluir autorizaciones y protección CSRF, sin asumir RLS nativo de MySQL.
-- El DBA puede conceder permisos DML granulares al backend según endpoints.
GRANT SELECT ON adisgea.roles TO 'adisgea_app'@'%';
GRANT SELECT ON adisgea.routes TO 'adisgea_app'@'%';
GRANT SELECT ON adisgea.method_steps TO 'adisgea_app'@'%';
GRANT SELECT ON adisgea.consent_purposes TO 'adisgea_app'@'%';
GRANT SELECT ON adisgea.feature_flags TO 'adisgea_app'@'%';
GRANT EXECUTE ON PROCEDURE adisgea.sp_login_rate_status TO 'adisgea_app'@'%';
GRANT INSERT ON adisgea.audit_log TO 'adisgea_logger'@'%';
GRANT INSERT ON adisgea.admin_access_log TO 'adisgea_logger'@'%';
-- Migrador NO obtiene DROP (que permitiría TRUNCATE auditable). Para una
-- migración destructiva se requiere aprobación y rol DBA separado.
GRANT CREATE, ALTER, INDEX, REFERENCES, TRIGGER, CREATE ROUTINE, ALTER ROUTINE,
      CREATE VIEW, SHOW VIEW, EVENT, SELECT, INSERT, UPDATE, DELETE
 ON adisgea.* TO 'adisgea_migrator'@'%';

-- =====================================================================
-- 17. RETENCIÓN AUTOMÁTICA (event_scheduler debe habilitarse en my.cnf)
-- =====================================================================
DELIMITER $$
CREATE DEFINER = 'adisgea_definer'@'%' EVENT IF NOT EXISTS ev_purge_expired_credentials
ON SCHEDULE EVERY 1 DAY
STARTS CURRENT_TIMESTAMP + INTERVAL 1 DAY
DO
BEGIN
    DELETE FROM auth_tokens WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 90 DAY;
    DELETE FROM idempotency_keys WHERE expires_at < UTC_TIMESTAMP();
    DELETE FROM email_change_requests WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 30 DAY;
    DELETE FROM login_attempts WHERE attempted_at < UTC_TIMESTAMP() - INTERVAL 30 DAY;
END$$
DELIMITER ;

-- =====================================================================
-- 18. SEMILLAS DEL SISTEMA CON FKs ACTIVAS
-- =====================================================================
SET FOREIGN_KEY_CHECKS = 1;
INSERT INTO roles (id, code, name, description) VALUES
 (1,'usuaria_registrada','Usuaria registrada','Gestiona perfil y consentimientos; sin acceso a contenidos de talleres'),
 (2,'usuaria_inscrita','Usuaria inscrita','Accede a los recursos del programa en el que está inscrita'),
 (3,'facilitadora','Facilitadora','Gestiona grupos y borradores; sin acceso a datos íntimos'),
 (4,'soporte','Soporte','Tickets y datos mínimos de cuenta'),
 (5,'administrador','Administrador','Catálogos, usuarios y reportes operativos; con auditoría'),
 (6,'gestor_institucional','Gestor institucional','Solo reportes agregados con umbral'),
 (7,'direccion','Dirección','Valida y publica contenidos; ve consolidados globales'),
 (8,'editora_especialista','Editora / Especialista','Redacta y revisa contenidos educativos');

INSERT INTO consent_purposes (id, code, description, version, is_required) VALUES
 (1,'terms_privacy','Aceptación de términos y política de privacidad','2026-10-v1',TRUE),
 (2,'progress_tracking','Registro voluntario de progreso y check-ins','2026-10-v1',FALSE),
 (3,'alma_chat','Conversaciones y acompañamiento con ALMA','2026-10-v1',FALSE),
 (4,'communications','Recibir comunicaciones y recordatorios','2026-10-v1',FALSE);

INSERT INTO feature_flags (flag_key, enabled, description) VALUES
 ('route_r1_wellbeing', TRUE,  'Piloto R1 Bienestar cotidiano'),
 ('route_r2_economy',   FALSE, 'R2 Autonomía económica (solo interno)'),
 ('route_r3_career',    FALSE, 'R3 Desarrollo profesional (solo interno)'),
 ('alma_enabled',       TRUE,  'Asistente ALMA 1.0');

INSERT INTO routes (id, code, name, description, flag_key, stage) VALUES
 (1,'R1','Bienestar','28 días + ALMA + rutinas + seguimiento','route_r1_wellbeing','pilot'),
 (2,'R2','Autonomía económica','Presupuesto educativo, metas y recursos','route_r2_economy','internal'),
 (3,'R3','Desarrollo profesional','Objetivos, aprendizaje y oportunidades','route_r3_career','internal');

INSERT INTO method_steps (step_order, name) VALUES
 (1,'Reconocer'),(2,'Comprender'),(3,'Reconectar'),(4,'Elegir'),
 (5,'Reconstruir'),(6,'Crecer'),(7,'Conectar');

