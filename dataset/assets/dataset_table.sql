CREATE TABLE if not exists domains (
    url TEXT NOT NULL PRIMARY KEY UNIQUE,
    whois_info TEXT NOT NULL,
    ip TEXT,
    -- Category can be null depending on source
    category TEXT
);

CREATE TABLE if not exists pending_domains (
    url TEXT NOT NULL PRIMARY KEY,
    phishing BOOLEAN NOT NULL,
    source TEXT NOT NULL
);
