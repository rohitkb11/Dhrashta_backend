CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    threat_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence JSONB,
    visibility JSONB,
    model_version TEXT,
    event_id TEXT UNIQUE,
    flow_id TEXT,
    input_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_class ON alerts (threat_class);
