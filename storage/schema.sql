CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',

    FOREIGN KEY (event_id)
        REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key
ON alerts(dedup_key);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events(timestamp_utc);
