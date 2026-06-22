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
INSERT INTO ndr.settings (key, value)
SELECT 'store_threshold', '10'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'store_threshold'
);

INSERT INTO ndr.settings (key, value)
SELECT 'alert_threshold', '75'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'alert_threshold'
);

INSERT INTO ndr.settings (key, value)
SELECT 'critical_threshold', '90'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'critical_threshold'
);

INSERT INTO ndr.settings (key, value)
SELECT 'soar_threshold', '75'
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.settings FINAL WHERE key = 'soar_threshold'
);

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
    active        UInt8 DEFAULT 1,
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
    updated_at DateTime DEFAULT now(),
    created_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

INSERT INTO ndr.tenants (id, name, active)
SELECT 'default', 'Default Organization', 1
WHERE NOT EXISTS (
    SELECT 1 FROM ndr.tenants FINAL WHERE id = 'default'
);

CREATE TABLE IF NOT EXISTS ndr.announcements
(
    id             String,
    title          String,
    message        String,
    announcement_type String DEFAULT 'info',
    audience       String DEFAULT 'all',
    status         String DEFAULT 'draft',
    target_roles   Array(String),
    target_tenants Array(String),
    start_at       DateTime DEFAULT now(),
    end_at         Nullable(DateTime),
    created_by     String,
    created_at     DateTime DEFAULT now(),
    updated_at     DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.announcement_reads
(
    announcement_id String,
    username        String,
    read_at         DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(read_at)
ORDER BY (announcement_id, username);

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
    interface_name String DEFAULT '',
    os_name     String DEFAULT '',
    zeek_status String DEFAULT 'unknown',
    suricata_status String DEFAULT 'unknown',
    vector_status String DEFAULT 'unknown',
    arkime_status String DEFAULT 'unknown',
    arkime_url  String DEFAULT '',
    arkime_pass String DEFAULT '',
    active      UInt8 DEFAULT 1,
    created_at  DateTime DEFAULT now(),
    last_seen   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY id;

CREATE TABLE IF NOT EXISTS ndr.pcap_sessions
(
    session_id   String,
    community_id String,
    src_ip       String,
    dst_ip       String,
    src_port     UInt16,
    dst_port     UInt16,
    proto        String,
    start_time   DateTime DEFAULT now(),
    end_time     DateTime DEFAULT now(),
    bytes        UInt64 DEFAULT 0,
    packets      UInt64 DEFAULT 0,
    arkime_url   String DEFAULT '',
    tenant_id    String DEFAULT 'default',
    sensor_host  String DEFAULT '',
    file_path    String DEFAULT ''
)
ENGINE = ReplacingMergeTree(start_time)
ORDER BY (tenant_id, session_id)
TTL start_time + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS ndr.pcap_pending
(
    community_id      String,
    tenant_id         String   DEFAULT 'default',
    requested_at      DateTime DEFAULT now(),
    fulfilled         UInt8    DEFAULT 0,
    fulfilled_at      DateTime DEFAULT toDateTime(0),
    retry_count       UInt8    DEFAULT 0,
    last_retry        DateTime DEFAULT toDateTime(0),
    error_message     String   DEFAULT '',
    upload_size_bytes UInt64   DEFAULT 0,
    severity          String   DEFAULT 'MEDIUM'
)
ENGINE = ReplacingMergeTree(requested_at)
ORDER BY (tenant_id, community_id)
TTL requested_at + INTERVAL 2 DAY;

CREATE TABLE IF NOT EXISTS ndr.ai_suppressions
(
    id             String   DEFAULT toString(generateUUIDv4()),
    tenant_id      String   DEFAULT 'default',
    signature_id   UInt64   DEFAULT 0,
    signature_name String   DEFAULT '',
    suppress_type  String   DEFAULT 'by_dst',
    suppress_ip    String   DEFAULT '',
    src_ip         String   DEFAULT '',
    dst_ip         String   DEFAULT '',
    community_id   String   DEFAULT '',
    ai_reason      String   DEFAULT '',
    ai_confidence  UInt8    DEFAULT 0,
    sensor_id      String   DEFAULT '',
    active         UInt8    DEFAULT 1,
    created_at     DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (tenant_id, signature_id, suppress_type, suppress_ip)
TTL created_at + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS ndr.sensor_commands
(
    id          String DEFAULT toString(generateUUIDv4()),
    tenant_id   String,
    sensor_id   String DEFAULT '',
    command     String,
    status      String DEFAULT 'pending',
    created_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (tenant_id, sensor_id, created_at);

CREATE TABLE IF NOT EXISTS ndr.support_messages
(
    id              String DEFAULT toString(generateUUIDv4()),
    tenant_id       String,
    sender_username String,
    sender_role     String,
    subject         String,
    category        String DEFAULT 'General',
    message         String,
    status          String DEFAULT 'open',
    admin_reply     String DEFAULT '',
    replied_by      String DEFAULT '',
    forwarded       UInt8 DEFAULT 0,
    forwarded_by    String DEFAULT '',
    deleted         UInt8 DEFAULT 0,
    created_at      DateTime DEFAULT now(),
    updated_at      DateTime DEFAULT now(),
    replied_at      Nullable(DateTime),
    forwarded_at    Nullable(DateTime)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

-- Native SOAR Tables
CREATE TABLE IF NOT EXISTS ndr.soar_cases
(
    id           String DEFAULT toString(generateUUIDv4()),
    title        String,
    description  String DEFAULT '',
    severity     String DEFAULT 'MEDIUM',
    status       String DEFAULT 'New',  -- New, Investigating, Resolved, False Positive
    assigned_to  String DEFAULT '',
    src_ip       String DEFAULT '',
    dst_ip       String DEFAULT '',
    community_id String DEFAULT '',
    hit_ids      Array(String) DEFAULT [],
    tags         Array(String) DEFAULT [],
    created_at   DateTime DEFAULT now(),
    updated_at   DateTime DEFAULT now(),
    closed_at    Nullable(DateTime),
    tenant_id    String DEFAULT 'default'
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS ndr.soar_case_comments
(
    id         String DEFAULT toString(generateUUIDv4()),
    case_id    String,
    author     String,
    comment    String,
    created_at DateTime DEFAULT now(),
    tenant_id  String DEFAULT 'default'
)
ENGINE = MergeTree()
ORDER BY (tenant_id, case_id, created_at);

CREATE TABLE IF NOT EXISTS ndr.soar_native_playbooks
(
    id           String DEFAULT toString(generateUUIDv4()),
    name         String,
    description  String DEFAULT '',
    enabled      UInt8 DEFAULT 1,
    -- condition fields
    cond_field   String,   -- 'score','severity','threat_intel','src_country','sigma_tag'
    cond_op      String,   -- '>','>=','==','contains'
    cond_value   String,
    -- action
    action_type  String,   -- 'slack','teams','discord','telegram','pagerduty','jira','webhook','email','create_case','block_ip'
    action_config String,  -- JSON config
    run_count    UInt64 DEFAULT 0,
    last_run     Nullable(DateTime),
    created_at   DateTime DEFAULT now(),
    updated_at   DateTime DEFAULT now(),
    tenant_id    String DEFAULT 'default'
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, id);

CREATE TABLE IF NOT EXISTS ndr.soar_playbook_runs
(
    id            String DEFAULT toString(generateUUIDv4()),
    playbook_id   String,
    playbook_name String,
    hit_id        String,
    status        String,
    detail        String,
    created_at    DateTime DEFAULT now(),
    tenant_id     String DEFAULT 'default'
)
ENGINE = MergeTree()
ORDER BY (tenant_id, created_at);

-- Evidence chain of custody log (per-tenant)
CREATE TABLE IF NOT EXISTS ndr.evidence_log
(
    id              String DEFAULT generateUUIDv4(),
    community_id    String,
    bundle_id       String DEFAULT '',
    action          String,
    performed_by    String,
    performed_at    DateTime DEFAULT now(),
    severity        String DEFAULT '',
    src_ip          String DEFAULT '',
    dst_ip          String DEFAULT '',
    case_id         String DEFAULT '',
    notes           String DEFAULT '',
    ip_address      String DEFAULT ''
)
ENGINE = MergeTree
ORDER BY (community_id, performed_at);

-- Evidence bundles (auto-captured or manual)
CREATE TABLE IF NOT EXISTS ndr.evidence_bundles
(
    id              String DEFAULT generateUUIDv4(),
    community_id    String,
    file_path       String,
    sha256          String,
    size_bytes      UInt64 DEFAULT 0,
    auto_captured   UInt8 DEFAULT 0,
    captured_at     DateTime DEFAULT now(),
    expires_at      DateTime DEFAULT now() + INTERVAL 90 DAY,
    status          String DEFAULT 'ready',
    legal_hold      UInt8 DEFAULT 0,
    hold_reason     String DEFAULT '',
    hold_set_by     String DEFAULT '',
    src_ip          String DEFAULT '',
    dst_ip          String DEFAULT '',
    severity        String DEFAULT '',
    alert_id        String DEFAULT ''
)
ENGINE = ReplacingMergeTree(captured_at)
ORDER BY (community_id, id)
TTL expires_at WHERE legal_hold = 0;

-- Evidence annotations (analyst notes per evidence bundle)
CREATE TABLE IF NOT EXISTS ndr.evidence_annotations
(
    id              String DEFAULT generateUUIDv4(),
    bundle_id       String,
    community_id    String,
    author          String,
    note            String,
    tag             String DEFAULT '',
    created_at      DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (bundle_id, created_at);

-- Permanent immutable IOC hit log — per-tenant, written at detection time, never deleted or updated.
-- create_tenant() replaces ndr. → ndr_<tenant>. so each tenant gets their own isolated table.
CREATE TABLE IF NOT EXISTS ndr.ioc_hits
(
    timestamp    DateTime DEFAULT now(),
    community_id String,
    src_ip       String,
    dst_ip       String,
    matched_ip   String,
    ioc_type     String   DEFAULT 'ip',
    feed_source  String   DEFAULT 'feodo'
)
ENGINE = MergeTree()
ORDER BY (timestamp, community_id, matched_ip)
SETTINGS non_replicated_deduplication_window = 0
COMMENT 'Immutable IOC hit log — never delete or update these records';

-- Global shared IOC table (not per-tenant)
CREATE TABLE IF NOT EXISTS ndr.shared_iocs
(
    id                  String DEFAULT generateUUIDv4(),
    ioc_value           String,
    ioc_type            String,
    confidence          UInt8 DEFAULT 50,
    first_seen          DateTime DEFAULT now(),
    last_seen           DateTime DEFAULT now(),
    tenant_hash         String DEFAULT '',
    tags                String DEFAULT '',
    description         String DEFAULT ''
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (ioc_type, ioc_value);
