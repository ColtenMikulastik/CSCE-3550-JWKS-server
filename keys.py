from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime as dt
import uuid
import base64
import jwt

# key exponent (usually 65537), and key_size above 1024 (breakable): https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048

class Key_Ring:
    """ class to store jwt keys and operate on them """
    # structure: list of JWKs(dict)
    def __init__(self):
        # store as ADT, decode when read, print pretty, but also comparisons will be easier
        self.key_list = list()
        self.private_key_list = dict()

    def create_new_jwk(self, kid=None, expiry=24):
        """add key to keyring with kid"""
        # if no kid passed to member function, generate random using uuid func
        if not kid:
            kid = str(uuid.uuid1())

        # TODO: check if kid already exist
        
        # generate keys
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE
        ) # generate with defaults
        
        # converting our ints to b64 url safe encoded values
        modu_exp_b64 = util_get_modu_and_exp_base64(private_key.public_key())
        

        # init timestamp data, used twice...
        init_at = dt.datetime.now()
        exp_at = dt.datetime.now() + dt.timedelta(hours=expiry)

        jwk = {
            "kty": "RSA", # always gonna be rsa
            "use": "sig", # assuming signature for now
            "kid": kid,
            "n" : modu_exp_b64[0], # public key modulo 
            "e": modu_exp_b64[1], # public key ex
            "alg": "RS256",
            "iat": int(init_at.timestamp()),
            "exp": int(exp_at.timestamp())
        }
        self.private_key_list[kid] = private_key
        self.key_list.append(jwk)
    
    def get_keys(self, expired=False):
        """ look through keys find ones that aren't expired yet """
        # grab current dt
        cur_time = dt.datetime.now()

        # create output key list and loop comparing the exp values
        out_key_list = list()
        for key_entry in self.key_list:
            if key_entry["exp"] > int(cur_time.timestamp()) != expired: # compair, and flip if we are looking for expired
                out_key_list.append(key_entry)
            else:
                # if its expired then pass and continue looking
                continue
        return out_key_list


def util_get_modu_and_exp_base64(public_key) -> tuple(2):
    modul_int = public_key.public_numbers().n
    # calculate byte length of modulus
    modul_byte_length = (modul_int.bit_length() + 7) // 8 # should be 256
    modul_bytes = modul_int.to_bytes(modul_byte_length)
    modul_b64 = base64.urlsafe_b64encode(modul_bytes).decode('utf-8')

    exp_int = public_key.public_numbers().e
    # calculate byte length of exponent
    exp_byte_length = (exp_int.bit_length() + 7 ) // 8
    exp_bytes = exp_int.to_bytes(exp_byte_length)
    exp_b64 = base64.urlsafe_b64encode(exp_bytes).decode('utf-8')

    # return both decoded/encoded numbers
    return (modul_b64, exp_b64)
