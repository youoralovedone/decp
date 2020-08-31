import socket
import json
import base64
import threading
import multiprocessing
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from v3.load_keys import load_keys
from v3.load_db import sqlite3_wrapper


class decp_node():
    def __init__(self):
        self.db = sqlite3_wrapper()
        self.keys = load_keys()

        with open("../../v3/config.json") as config_file:
            config = json.loads(config_file.read())
        self.nick = config["nick"]
        self.ips = config["ips"]

        # check if members.db is initialized, init it if not
        if len(self.db.execute("SELECT * FROM members WHERE public_key = ?", self.keys["pub_key_s"])) == 0:
            self.db.execute("INSERT INTO members (public_key, nick) VALUES (?, ?)", self.keys["pub_key_s"], self.nick)
            self.id = self.db.execute("SELECT id FROM members WHERE public_key = ?", self.keys["pub_key_s"])[0]["id"]
            for ip in self.ips:
                self.db.execute("INSERT INTO ips (member_id, ip) VALUES (?, ?)", self.id, ip)

        self.id = self.db.execute("SELECT id FROM members WHERE public_key = ?", self.keys["pub_key_s"])[0]["id"]
        self.members = self.db.execute("SELECT * FROM members")

        # start listening server on port 3623
        self.server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_s.bind((socket.gethostname(), 3623))
        self.server_s.listen(5)
        self.start_server()
        # self.server_thread = multiprocessing.Process(target=self.start_server)

    def send_message(self, message):
        for member in self.members:
            # encrypt messagge
            key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_CBC)
            e_message = base64.b64encode(cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))).decode('utf-8')
            # initialization vector must be included in message
            iv = base64.b64encode(cipher.iv).decode('utf-8')

            # encrypt key
            key_e = base64.b64encode(rsa.encrypt(key, rsa.PublicKey.load_pkcs1(member["public_key"])))
            # generate message signature
            signature = base64.b64encode(rsa.sign(message.encode("utf-8"), self.keys["priv_key"], "SHA-224"))

            dump = json.dumps(
                {
                    "request": "MSG",
                    "message": f"{e_message}",
                    "member_id": f"{self.id}",
                    "key": f"{key_e}",
                    "iv": f"{iv}",
                    "signature": f"{signature}"
                }
            )

            threads = []
            ips = self.db.execute("SELECT ip FROM ips WHERE member_id = ?", member["id"])
            for ip in ips:
                thread = threading.Thread(target=self.send_thread, args=(ip, dump, ))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

    def start_server(self):
        while True:
            (client_s, address) = self.server_s.accept()
            data = self.recv_all(client_s)
            print(data)

    # def stop_server(self):
    #     self.server_s.close()
    #     self.server_thread.join()

    def recv_all(self, sock):
        buffer_size = 4096
        data = b''
        while True:
            part = sock.recv(buffer_size)
            data += part
            if len(part) < buffer_size:
                break
        return data

    # run sockets in threads to prevent blocking
    def send_thread(self, ip, dump):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip["ip"], 3623))
            s.send(dump.encode("utf-8"))
            s.close()
        except (ConnectionRefusedError, TimeoutError):
            print("target machine refused connection or connection timed out, check if port 3623 is forwarded")


node = decp_node()
node.send_message("testing")