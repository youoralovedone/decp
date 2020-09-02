.open members.db
DELETE FROM members WHERE nick = "troof";
DELETE FROM ips WHERE member_nick = "troof";
.close