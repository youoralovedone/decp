import socket
import json
from base64 import b64encode, b64decode
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from src.v4.load_keys import load_keys
from src.v4.load_db import sqlite3_wrapper


class decp_node():
    def __init__(self):
        self.db = sqlite3_wrapper()
        self.keys = load_keys()

        with open("config.json") as config_file:
            config = json.loads(config_file.read())
        self.nick = config["nick"]
        self.self_ips = config["ips"]

        # check if members.db is initialized, init it if not
        if len(self.db.execute("SELECT * FROM members WHERE nick = ?", self.nick)) == 0:
            self.db.execute("INSERT INTO members (nick, public_key) VALUES (?, ?)", self.nick, self.keys["pub_key_s"])

            for ip in self.self_ips:
                self.db.execute("INSERT INTO ips (member_nick, ip) VALUES (?, ?)", self.nick, ip)

        self.members = self.db.execute("SELECT * FROM members")
        self.ips = self.db.execute("SELECT * FROM ips")

        # initialize requests handler dict
        self.handler_dict = {
            "MSG": self.handle_msg,
            "JOIN": self.handle_join
        }

        # start listening thread
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_stopped = False
        self.server_thread.start()

    def send_message(self, message):
        threads = []
        for member in self.members:
            thread = threading.Thread(target=self.msg_thread, args=(member, message, ))
            threads.append(thread)
            thread.start()

        for thread in threads:
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

        sender_row = self.server_thread_db.execute("SELECT * FROM members WHERE nick = ?", request_json["sender_nick"])[0]
        signature = b64decode(request_json["signature"])
        signed = rsa.verify(message.encode("utf-8"), signature, rsa.PublicKey.load_pkcs1(sender_row["public_key"]))
        status = "[signature matches]" if signed else "[WARNING SIGNATURE DOES NOT MATCH]"
        sender_nick = sender_row["nick"]
        print(status, sender_nick, ":", message)

    def handle_join(self, request_json):
        pass

    def start_server(self):
        self.server_thread_db = sqlite3_wrapper()

        print("starting listening server in separate thread...")
        self.server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_s.bind((socket.gethostname(), 3623))
        # queue up to 5 connections before dropping
        self.server_s.listen(5)
        print("done! listening on port 3623")

        while not self.server_stopped:
            client_s, address = self.server_s.accept()
            data = self.recv_all(client_s)
            self.handle_request(data)
            client_s.close()

    def stop_server(self):
        # not closing the socket on forced exit?
        self.server_s.close()
        self.server_stopped = True

    def msg_thread(self, member, message):
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

        for ip in self.ips:
            if ip["member_nick"] != member["nick"]:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # https://stackoverflow.com/questions/7214553/python-socket-hangs-on-connect
                s.connect((ip["ip"], 3623))
                s.send(dump.encode("utf-8"))
                s.setblocking(0)
                s.close()
            except (ConnectionRefusedError, TimeoutError) as e:
                print(f"target machine at {ip['ip']} refused connection, check if port 3623 is forwarded")

    def recv_all(self, sock):
        buffer_size = 4096
        data = b""
        while True:
            part = sock.recv(buffer_size)
            data += part
            if len(part) < buffer_size:
                break
        return data
