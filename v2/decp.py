import sqlite3
import rsa
import json
from v2.gen_keys import gen_keys


class decp_node():
    def __init__(self, config_path):
        # connect to members db
        with open(config_path) as config_file:
            config = json.loads(config_file.read())
        self.conn = sqlite3.connect(config["db_path"])
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()

        # load/generate keys
        try:
            self.keys = gen_keys(config["keys_path"])
        except Exception as er:
            # exit("[ERR] key loading/generation failed")
            quit("[ERR] key loading/generation failed")

        # initialize members.db if not already
        # maybe move this to a seperate file?
        self.c.execute("SELECT * FROM members WHERE public_key = ?", (self.keys["pub_key"], ))
        self.me = self.select_result()
        if len(self.me) == 0:
            self.c.execute("INSERT INTO members (public_key, nick) VALUES (?, ?)", (self.keys["pub_key"], config["nick"]))
            self.conn.commit()

            self.c.execute("SELECT id FROM members WHERE public_key = ?", (self.keys["pub_key"], ))
            self.id = self.select_result()[0]["id"]

            for ip in config["ips"]:
                self.c.execute("INSERT INTO ips (member_id, ip) VALUES (?, ?)", (self.id, ip))
                self.conn.commit()

            self.c.execute("SELECT * FROM members WHERE public_key = ?", (self.keys["pub_key"], ))
            self.me = self.select_result()[0]

    def select_result(self):
        return [dict(row) for row in self.c.fetchall()]

    def exit(self):
        self.conn.close()


decp_node_instance = decp_node("config.json")