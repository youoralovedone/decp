import socket
import os
import json
from base64 import b64encode, b64decode
import threading
import sqlite3
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class decp_node():
    def __init__(self):
        self.db = sqlite3_wrapper()
        self.keys = self.load_keys()

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
        self.request_queue = []
        self.message_queue = []

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

        # start handler thread
        self.request_handler_thread = threading.Thread(target=self.start_request_handler_thread)
        self.request_handler_thread.daemon = True
        self.request_handler_thread.start()

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
        self.request_queue.append(request_json)
        # self.handler_dict[request_json.pop("request")](request_json)

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
        # status = "[signature matches]" if signed else "[WARNING SIGNATURE DOES NOT MATCH]"
        sender_nick = sender_row["nick"]
        # move this to messages queue
        self.message_queue.append(
            {
                "signed": signed,
                "sender_nick": sender_nick,
                "message": message
            }
        )
        # print(status, sender_nick, ":", message)

    # def get_message_queue(self):
    #     return self.message_queue

    def handle_join(self, request_json):
        pass

    def start_server_thread(self):
        while True:
            # dispatch client_s in thread
            if self.server_stopped:
                break
            client_s, address = self.server_s.accept()
            connection_thread = threading.Thread(target=self.start_connection_thread, args=(client_s, ))
            # working?
            self.connection_threads.append(connection_thread)
            connection_thread.start()

    def start_request_handler_thread(self):
        while True:
            if self.server_stopped:
                break
            try:
                request_json = self.request_queue.pop(0)
                self.handler_dict[request_json.pop("request")](request_json)
            except IndexError as e:
                continue

    def stop(self):
        self.server_stopped = True
        self.server_s.close()

        for thread in self.connection_threads:
            thread.join()

    def start_connection_thread(self, client_s):
        data = self.recv_all(client_s)
        self.handle_request(data)
        client_s.close()

    def recv_all(self, sock):
        buffer_size = 4096
        data = b""
        while True:
            part = sock.recv(buffer_size)
            data += part
            if not part:
                break
        return data

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

    def load_keys(self):
        # keys stored as PEM in keys directory
        cwd = os.getcwd()
        priv_path = os.path.join(cwd, "keys", "private.pem")
        pub_path = os.path.join(cwd, "keys", "public.pem")

        # generate keys if keys directory does not exist
        # to regenerate keys: delete keys dir and then delete or update entry in members.db associated with self
        #   - via nick maybe?
        if not os.path.exists(os.path.join(cwd, "keys")):
            os.mkdir("keys")

            print("generating keys, this may take a while...")
            (pub_key, priv_key) = rsa.newkeys(2048)

            with open(pub_path, "w") as pub_file:
                pub_file.write(pub_key.save_pkcs1("PEM").decode("utf-8"))
            with open(priv_path, "w") as priv_file:
                priv_file.write(priv_key.save_pkcs1("PEM").decode("utf-8"))

        # load keys as python-rsa types
        with open(pub_path, mode="rb") as pub_file:
            pub_key_s = pub_file.read()
            pub_key = rsa.PublicKey.load_pkcs1(pub_key_s)
        with open(priv_path, mode="rb") as priv_file:
            priv_key_s = priv_file.read()
            priv_key = rsa.PrivateKey.load_pkcs1(priv_key_s)

        # key_s are keys encoded as strings
        return {
            "pub_key_s": pub_key_s,
            "priv_key_s": priv_key_s,
            "pub_key": pub_key,
            "priv_key": priv_key
        }


# member db must be named members.db and located in the same directory as decp.py
class sqlite3_wrapper():
    def __init__(self):
        # connect to members.db
        self.conn = sqlite3.connect("members.db", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()
        self.lock = threading.Lock()

    def execute(self, query, *argv):
        self.lock.acquire(True)
        self.c.execute(query, argv)
        self.lock.release()
        self.conn.commit()
        self.lock.acquire(True)
        result = self.c.fetchall()
        self.lock.release()
        return [dict(row) for row in result]

    def close(self):
        # close connection to database
        self.conn.close()
