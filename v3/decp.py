import socket
import json
import sqlite3
import rsa
from v3.load_keys import load_keys
from v3.load_db import sqlite3_wrapper


class decp_node():
    def __init__(self):
        self.db = sqlite3_wrapper()
        self.keys = load_keys()

        with open("config.json") as config_file:
            config = json.loads(config_file.read())
        self.nick = config["nick"]
        self.ips = config["ips"]

        # check if members.db is initialized, init it if not
        if len(self.db.execute("SELECT * FROM members WHERE public_key = ?", self.keys["pub_key_s"])) == 0:
            self.db.execute("INSERT INTO members (public_key, nick) VALUES (?, ?)", self.keys["pub_key_s"], self.nick)
            self.id = self.db.execute("SELECT id FROM members WHERE public_key = ?", self.keys["pub_key_s"])[0]["id"]
            for ip in self.ips:
                self.db.execute("INSERT INTO ips (member_id, ip) VALUES (?, ?)", self.id, ip)

        self.id = self.db.execute("SELECT id FROM members WHERE public_key = ?", self.keys["pub_key_s"])


node = decp_node()