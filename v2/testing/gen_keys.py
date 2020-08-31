import rsa


def main():
    (pubkey, privkey) = rsa.newkeys(2048)

    with open("private.pem", "w") as private:
        private.write(privkey.save_pkcs1("PEM").decode("utf-8"))

    with open("public.pem", "w") as public:
        public.write(pubkey.save_pkcs1("PEM").decode("utf-8"))



if __name__ == "__main__":
    main()
