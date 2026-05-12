-- TunnelDeck schema v1.
--
-- Singleton table is enforced by CHECK(id = 1). Timestamps are unix seconds
-- stored as INTEGER; conversion to time.Time happens in Go.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    public_ip            TEXT    NOT NULL DEFAULT '',
    wan_if               TEXT    NOT NULL DEFAULT '',
    wg_if                TEXT    NOT NULL DEFAULT 'wg0',
    wg_ip                TEXT    NOT NULL DEFAULT '',
    wg_port              INTEGER NOT NULL DEFAULT 51820,
    wg_subnet            TEXT    NOT NULL DEFAULT '10.66.66.0/24',
    wg_public_key        TEXT    NOT NULL DEFAULT '',
    ui_bind              TEXT    NOT NULL DEFAULT '127.0.0.1',
    ui_port              INTEGER NOT NULL DEFAULT 9443,
    managed_nft_table    TEXT    NOT NULL DEFAULT 'tunneldeck_nat',
    -- adopt_mode: 'fresh' | 'monitor-only' | 'adopted'
    adopt_mode           TEXT    NOT NULL DEFAULT 'fresh',
    adopt_confirmed_at   INTEGER,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    wg_ip          TEXT    NOT NULL UNIQUE,
    public_key     TEXT    NOT NULL DEFAULT '',
    endpoint_hint  TEXT    NOT NULL DEFAULT '',
    keepalive      INTEGER NOT NULL DEFAULT 25,
    adopted        INTEGER NOT NULL DEFAULT 0,
    last_seen_at   INTEGER,
    created_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nodes_public_key ON nodes(public_key);

CREATE TABLE IF NOT EXISTS forwards (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    proto         TEXT    NOT NULL CHECK (proto IN ('tcp','udp')),
    public_port   INTEGER NOT NULL CHECK (public_port BETWEEN 1 AND 65535),
    node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    target_port   INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    description   TEXT    NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    log_mode      TEXT    NOT NULL DEFAULT 'counter' CHECK (log_mode IN ('counter','connlog','debug')),
    created_at    INTEGER NOT NULL,
    UNIQUE (proto, public_port)
);

CREATE INDEX IF NOT EXISTS idx_forwards_node ON forwards(node_id);

CREATE TABLE IF NOT EXISTS join_tokens (
    token       TEXT    PRIMARY KEY,
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    NOT NULL UNIQUE,
    pwhash              TEXT    NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL,
    last_login          INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    actor   TEXT    NOT NULL DEFAULT 'system',
    action  TEXT    NOT NULL,
    target  TEXT    NOT NULL DEFAULT '',
    detail  TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS snapshots (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    kind    TEXT    NOT NULL,
    path    TEXT    NOT NULL,
    sha256  TEXT    NOT NULL,
    note    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    ip          TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    success     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(ip, ts DESC);
