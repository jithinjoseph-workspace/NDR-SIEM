CREATE DATABASE IF NOT EXISTS ndr;

CREATE TABLE IF NOT EXISTS ndr.ndr_events (
    timestamp    DateTime,
    source       String,
    src_ip       String,
    dst_ip       String,
    src_port     UInt16,
    dst_port     UInt16,
    proto        String,
    event_type   String,
    community_id String,
    raw          String,
    tenant_id    String DEFAULT 'default'
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ndr.ndr_hits (
    timestamp    DateTime,
    community_id String,
    src_ip       String,
    dst_ip       String,
    score        Float32,
    severity     String,
    tags         Array(String),
    sigma_hits   Array(String),
    threat_intel UInt8,
    src_country  String,
    dst_country  String,
    tenant_id    String DEFAULT 'default'
) ENGINE = MergeTree()
ORDER BY (timestamp, severity, score)
TTL timestamp + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.ndr_stats (
    timestamp      DateTime,
    events_per_min UInt32,
    hits_per_min   UInt32,
    top_src_ip     String,
    top_dst_ip     String
) ENGINE = MergeTree()
ORDER BY timestamp
TTL timestamp + INTERVAL 7 DAY;


CREATE TABLE IF NOT EXISTS ndr.rules_state (
    id      String,
    enabled UInt8    DEFAULT 1,
    updated DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated)
ORDER BY id;

-- Settings table for configurable thresholds
CREATE TABLE IF NOT EXISTS ndr.settings
(
    key        String,
    value      String,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key;

-- Default thresholds
INSERT INTO ndr.settings (key, value) VALUES
    ('store_threshold',    '10'),
    ('alert_threshold',    '75'),
    ('critical_threshold', '90'),
    ('soar_threshold',     '75');

-- SOAR configuration table
CREATE TABLE IF NOT EXISTS ndr.soar_config
(
    key        String,
    value      String,
    tenant_id  String DEFAULT 'default',
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key;

-- SOAR playbooks table
CREATE TABLE IF NOT EXISTS ndr.soar_playbooks
(
    id          String,
    name        String,
    description String,
    trigger     String,
    action_type String,
    config      String,
    enabled     UInt8 DEFAULT 1,
    runs        UInt64 DEFAULT 0,
    tenant_id   String DEFAULT 'default',
    created_at  DateTime DEFAULT now(),
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;



-- SOAR integrations table
CREATE TABLE IF NOT EXISTS ndr.soar_integrations
(
    id          String,
    name        String,
    type        String,
    config      String,
    enabled     UInt8 DEFAULT 1,
    tenant_id   String DEFAULT 'default',
    created_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY id;

-- Users table
CREATE TABLE IF NOT EXISTS ndr.users
(
    id            String DEFAULT toString(generateUUIDv4()),
    username      String,
    password_hash  String,
    role          String DEFAULT 'analyst',
    tenant_id     String DEFAULT 'default',
    permissions   String DEFAULT 'dashboard,alerts',
    created_at    DateTime DEFAULT now(),
    last_login    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY username;

-- Insert default admin user
-- Password: ndr@admin123 (bcrypt hash)
INSERT INTO ndr.users (username, password_hash, role)
VALUES ('admin', '$2b$12$qB5uFqakHidExby4EbdH6.tFvW34sj7CAQFZdUCzk5YSi/kV3S09.', 'super_admin');

CREATE TABLE IF NOT EXISTS ndr.tenants
(
    id         String,
    name       String,
    active     UInt8 DEFAULT 1,
    created_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY id;

INSERT INTO ndr.tenants (id, name, active)
VALUES ('default', 'Default Organization', 1);

CREATE TABLE IF NOT EXISTS ndr.sigma_rules
(
    id          String,
    name        String,
    content     String,
    enabled     UInt8 DEFAULT 1,
    tenant_id   String DEFAULT 'default',
    created_at  DateTime DEFAULT now(),
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.sensor_keys
(
    id          String DEFAULT toString(generateUUIDv4()),
    key_hash    String,
    key_prefix  String,
    tenant_id   String,
    name        String,
    hostname    String DEFAULT '',
    active      UInt8 DEFAULT 1,
    created_at  DateTime DEFAULT now(),
    last_seen   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.sensor_commands
(
    id          String DEFAULT toString(generateUUIDv4()),
    tenant_id   String,
    command     String,
    status      String DEFAULT 'pending',
    created_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (tenant_id, created_at);