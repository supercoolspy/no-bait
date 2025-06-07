CREATE TABLE if not exists domains (
    url TEXT NOT NULL PRIMARY KEY UNIQUE,
    whois_info TEXT NOT NULL,
    -- Enum so source can be determined from the enum type
    collector_info TEXT NOT NULL
);

CREATE TABLE if not exists pending_domains (
    url TEXT NOT NULL PRIMARY KEY,
    collector_data TEXT NOT NULL
);
