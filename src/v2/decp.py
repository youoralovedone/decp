import sqlite3
import rsa
import json
import socket
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
        self.keys = gen_keys(config["keys_path"])
        if not self.keys:
            quit("[ERR] key loading/generation failed")

        # initialize members.db if not already
        # maybe move this to a seperate module?
        self.c.execute("SELECT * FROM members WHERE public_key = ?", (self.keys["pub_key"], ))
        # not running on key regeneration
        if len(self.select_result()) == 0:
            self.c.execute("INSERT INTO members (public_key, nick) VALUES (?, ?)", (self.keys["pub_key"], config["nick"]))
            self.conn.commit()

            self.c.execute("SELECT id FROM members WHERE public_key = ?", (self.keys["pub_key"], ))
            self.id = self.select_result()[0]["id"]

            for ip in config["ips"]:
                self.c.execute("INSERT INTO ips (member_id, ip) VALUES (?, ?)", (self.id, ip))
                self.conn.commit()

        self.c.execute("SELECT * FROM members")
        self.members = self.select_result()

    def select_result(self):
        return [dict(row) for row in self.c.fetchall()]

    def send_message(self, message):
        for member in self.members:
            c_pub_key = member["public_key"]
            # write socket wrapper
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.c.execute("SELECT ip FROM ips WHERE member_id = ?", (member["id"], ))
            ips = self.select_result()
            dump = json.dumps(
                {
                    "request": "MSG",
                    "message": f"{message}",
                    "member_id": f"{member['id']}",
                }
            )
            enc_message = rsa.encrypt(dump.encode("utf-8"), rsa.PublicKey.load_pkcs1(c_pub_key))

            # not matching?
            # print(c_pub_key)
            # print(self.keys["pub_key"])

            # https://stackoverflow.com/questions/49677614/overflow-exception-when-encrypting-message-with-python-rsa
            # https://stackoverflow.com/questions/33884538/double-encrypting-2048-rsa
            # crlf fucking with the key? NOPE
            # need to encrypt with sub value of private key, weird API?
            enc_message = rsa.encrypt(enc_message, self.keys["priv_key_b"])

            # enc_message = rsa.encrypt(message.encode("utf-8"), self.keys["priv_key_b"])


            for ip in ips:
                s.connect((ip["ip"], 3623))
                s.send(enc_message)
                s.send(message.encode("utf-8"))
                s.close()

    def exit(self):
        self.conn.close()


decp_node_instance = decp_node("config.json")
decp_node_instance.send_message("testing")