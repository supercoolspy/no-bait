CREATE TABLE if not exists domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root TEXT NOT NULL,
    subdomain TEXT,
    whois_info TEXT NOT NULL,
    ip TEXT,
    -- Category can be null depending on source
    category TEXT
);
