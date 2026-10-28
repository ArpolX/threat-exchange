-- +goose Up
CREATE TABLE threats (
    md5 TEXT PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 255),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 4096),
    severity TEXT NOT NULL DEFAULT 'unknown'
        CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    category TEXT NOT NULL DEFAULT 'unknown'
        CHECK (category IN ('unknown', 'trojan', 'ransomware', 'spyware', 'adware', 'worm', 'virus', 'rootkit', 'other')),
    source TEXT NOT NULL DEFAULT '' CHECK (char_length(source) <= 255),
    sha256 TEXT CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE threats;
