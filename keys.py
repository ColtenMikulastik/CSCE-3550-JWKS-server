
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# key exponent (usually 65537), and key_size above 1024 (breakable): https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048

class Key_Ring:
    """ class to store jwt keys and operate on them """
    def __init__(self):
        self.key_list = list()
    
    def create_new_key(self, kid):
        """add key to keyring with kid"""



def generate_rsa_key():
    """ returns RSA private key, with which the public can be generated"""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    ) # generate with defaults

    # print out information about key
    # using PEM encoding of binary keys, pretty standard 
    encrypted_pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    print(encrypted_pem_private_key.splitlines())

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(pem_public_key.splitlines()[0])