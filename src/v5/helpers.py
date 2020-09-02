import os
import rsa
import sqlite3


# member db must be named members.db and located in the same directory as decp.py
class sqlite3_wrapper():
    def __init__(self):
        # connect to members.db
        self.conn = sqlite3.connect("members.db", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()

    def execute(self, query, *argv):
        self.c.execute(query, argv)
        self.conn.commit()
        return [dict(row) for row in self.c.fetchall()]

    def close(self):
        # close connection to database
        self.conn.close()


def load_keys():
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


def recv_all(sock):
    buffer_size = 4096
    data = b""
    while True:
        part = sock.recv(buffer_size)
        data += part
        if not part:
            break
    return data
