CREATE TABLE members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key TEXT UNIQUE,
    nick TEXT UNIQUE
);
CREATE TABLE ips (
    member_id INTEGER,
    ip TEXT,
    FOREIGN KEY(member_id) REFERENCES members(id)
);
CREATE INDEX public_key ON members (public_key);
