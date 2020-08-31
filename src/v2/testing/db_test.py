import sqlite3
import rsa

## gen_keys function in decp class

# set_db function in decp class
# connect to members db
conn = sqlite3.connect("members.db")
conn.row_factory = sqlite3.Row
c = conn.cursor()

c.execute("SELECT * FROM members")
members = [dict(row) for row in c.fetchall()]

# send_message function in decp class
for member in members:
    c_pubkey = rsa.PublicKey.load_pkcs1(member["public_key"].encode("utf-8"), "PEM")
    # print(rsa.encrypt("testing".encode("utf-8"), c_pubkey))
