import rsa
(pub_key, priv_key) = rsa.newkeys(2048)

with open("public.pem", "w") as file:
    file.write(rsa.PublicKey.save_pkcs1(pub_key).decode("utf-8"))