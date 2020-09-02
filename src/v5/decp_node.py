import socket
import json
from base64 import b64encode, b64decode
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from src.v5.helpers import sqlite3_wrapper, load_keys, recv_all


class decp_node():
    def __init__(self):
        self.db = sqlite3_wrapper()
        self.keys = load_keys()

        # load config
        with open("config.json") as config_file:
            config = json.loads(config_file.read())
        self.nick = config["nick"]
        self.self_ips = config["ips"]

        self.init_db()

        # initialize requests handler dict
        self.handler_dict = {
            "MSG": self.handle_msg,
            "JOIN": self.handle_join
        }

        self.connection_threads = []

        self.server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # stop OS from preventing same connection twice in a row
        self.server_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_s.bind((socket.gethostname(), 3623))
        self.server_s.listen(5)

        # start listening thread
        self.server_stopped = False
        self.server_thread = threading.Thread(target=self.start_server_thread)
        self.server_thread.daemon = True
        # self.threads.append(self.server_thread)
        self.server_thread.start()

    def send_message(self, message):
        member_threads = []
        members = self.db.execute("SELECT * FROM members")
        for member in members:
            thread = threading.Thread(target=self.start_message_thread, args=(member, message, ))
            member_threads.append(thread)
            thread.start()

        for thread in member_threads:
            thread.join()

    def join(self):
        pass

    def handle_request(self, request):
        request_json = json.loads(request)
        self.handler_dict[request_json.pop("request")](request_json)

    def handle_msg(self, request_json):
        key_enc = b64decode(request_json["key"].encode("utf-8"))
        key = rsa.decrypt(key_enc, self.keys["priv_key"])

        message_enc = b64decode(request_json["message"])
        iv = b64decode(request_json["iv"].encode("utf-8"))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        message = unpad(cipher.decrypt(message_enc), AES.block_size).decode("utf-8")

        sender_row = self.db.execute("SELECT * FROM members WHERE nick = ?", request_json["sender_nick"])[0]
        signature = b64decode(request_json["signature"])
        signed = rsa.verify(message.encode("utf-8"), signature, rsa.PublicKey.load_pkcs1(sender_row["public_key"]))
        status = "[signature matches]" if signed else "[WARNING SIGNATURE DOES NOT MATCH]"
        sender_nick = sender_row["nick"]
        # move this to messages queue
        print(status, sender_nick, ":", message)

    def handle_join(self, request_json):
        pass

    def start_server_thread(self):
        while not self.server_stopped:
            # dispatch client_s in thread
            client_s, address = self.server_s.accept()
            connection_thread = threading.Thread(target=self.start_connection_thread, args=(client_s, ))
            # working?
            self.connection_threads.append(connection_thread)
            connection_thread.start()

    def start_connection_thread(self, client_s):
        data = recv_all(client_s)
        self.handle_request(data)
        client_s.close()

    def stop(self):
        self.server_s.close()
        self.server_stopped = True

        self.server_thread.join()
        for thread in self.connection_threads:
            thread.join()

    def start_message_thread(self, member, message):
        # encrypt message
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CBC)
        e_message = b64encode(cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))).decode('utf-8')
        # initialization vector must be included in message
        iv = b64encode(cipher.iv).decode('utf-8')

        # encrypt key
        key_e = b64encode(rsa.encrypt(key, rsa.PublicKey.load_pkcs1(member["public_key"]))).decode("utf-8")
        # generate message signature
        signature = b64encode(rsa.sign(message.encode("utf-8"), self.keys["priv_key"], "SHA-224")).decode("utf-8")

        dump = json.dumps(
            {
                "request": "MSG",
                "message": f"{e_message}",
                "sender_nick": f"{self.nick}",
                "key": f"{key_e}",
                "iv": f"{iv}",
                "signature": f"{signature}"
            }
        )

        reciepient_ips = self.db.execute("SELECT * FROM ips WHERE member_nick = ?", member["nick"])
        for ip in reciepient_ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((ip["ip"], 3623))
                s.send(dump.encode("utf-8"))
                s.close()
            except (ConnectionRefusedError, socket.timeout) as e:
                print(f"target machine at {ip['ip']} refused connection, check if port 3623 is forwarded")

    def is_ready(self):
        pass

    def init_db(self):
        # check if members.db is initialized, init it if not
        self_row = self.db.execute("SELECT * FROM members WHERE nick = ?", self.nick)
        if len(self_row) == 0:
            self.db.execute("INSERT INTO members (nick, public_key) VALUES (?, ?)", self.nick, self.keys["pub_key_s"])

            for ip in self.self_ips:
                self.db.execute("INSERT INTO ips (member_nick, ip) VALUES (?, ?)", self.nick, ip)
        elif self_row[0]["public_key"] != self.keys["pub_key_s"]:
            self.db.execute("UPDATE members SET public_key = ? WHERE nick = ?", self.keys["pub_key_s"], self.nick)
