import os
import rsa


def gen_keys(keys_path):
    # load/generate keys
    # can probably be cleaned up a little
    keys_path_f = os.path.join(os.getcwd(), keys_path)
    priv_path = os.path.join(keys_path_f, "private.pem")
    pub_path = os.path.join(keys_path_f, "public.pem")

    if not os.path.exists(keys_path):
        # delete keys to regenerate
        if input(f"no key directory detected, generate keys at {os.getcwd()}/keys? (y/n)\n").lower() == "y":
            print("[OK] generating keys... this may take a while")
            (pub_key, priv_key) = rsa.newkeys(2048)

            os.mkdir(keys_path)

            with open(priv_path, "w") as private_pem:
                # _r REM format
                private_pem.write(priv_key.save_pkcs1("PEM").decode("utf-8"))
            with open(pub_path, "w") as public_pem:
                public_pem.write(pub_key.save_pkcs1("PEM").decode("utf-8"))
        else:
            print("[ERR] key generation aborted")
            return

    with open(priv_path, mode="rb") as private_pem:
        priv_key_r = private_pem.read()
        priv_key = rsa.PrivateKey.load_pkcs1(priv_key_r)
    with open(pub_path, mode="rb") as public_pem:
        pub_key_r = public_pem.read()
        pub_key = rsa.PublicKey.load_pkcs1(pub_key_r)

    # _b are the rsa custom types
    return {
        "pub_key_b": pub_key,
        "priv_key_b": priv_key,
        "pub_key": pub_key_r,
        "priv_key": priv_key_r
    }
