import os
import rsa


def load_keys():
    # keys stored as PEM in keys directory
    cwd = os.getcwd()
    priv_path = os.path.join(cwd, "keys", "private.pem")
    pub_path = os.path.join(cwd, "keys", "public.pem")

    # generate keys if keys directory does not exist, delete keys dir to regenerate keys
    if not os.path.exists(os.path.join(cwd, "keys")):
        os.mkdir("keys")

        (pub_key, priv_key) = rsa.newkeys(2048)

        with open(pub_path, "w") as pub_file:
            pub_file.write(pub_key.save_pkcs1("PEM").decode("utf-8"))
        with open(priv_path, "w") as priv_file:
            priv_file.write(priv_key.save_pkcs1("PEM").decode("utf-8"))

    # load keys as python-rsa types
    with open(pub_path, mode="rb") as pub_file:
        pub_key = rsa.PrivateKey.load_pkcs1(pub_file.read())
    with open(priv_path, mode="rb") as priv_file:
        priv_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

    return pub_key, priv_key
