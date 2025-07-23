CREATE TABLE if not exists domains (
    url TEXT NOT NULL PRIMARY KEY UNIQUE,
    whois_info TEXT NOT NULL,
    cert_info TEXT DEFAULT NULL,
    -- Enum so source can be determined from the enum type
    collector_info TEXT NOT NULL
);

CREATE TABLE if not exists pending_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    collector_data TEXT NOT NULL
);
