.open members.db
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
CREATE INDEX nick ON members (nick);
CREATE INDEX member_id ON ips (member_id);
.exit