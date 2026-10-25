CREATE TABLE IF NOT EXISTS threats (
    md5 text PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255 AND name ~ '[^[:space:]]'),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 4096),
    severity text NOT NULL DEFAULT 'unknown'
        CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    type text NOT NULL DEFAULT 'unknown'
        CHECK (type IN ('unknown', 'virus', 'worm', 'trojan', 'ransomware', 'spyware', 'adware', 'rootkit', 'other')),
    tags text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
