.open members.db
CREATE TABLE members (
    nick TEXT UNIQUE PRIMARY KEY,
    public_key TEXT UNIQUE
);
CREATE TABLE ips (
    member_nick TEXT,
    ip TEXT,
    FOREIGN KEY(member_nick) REFERENCES members(nick)
);
CREATE INDEX public_key ON members (public_key);
.exit