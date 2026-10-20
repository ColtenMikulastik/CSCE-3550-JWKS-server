import base64
import copy
import datetime as dt
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# key exponent (usually 65537), and key_size above 1024 (breakable): https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
DB_FILE = "totally_not_my_privateKeys.db"
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048

class KeyRing:
    """ class to store jwt keys and operate on them """
    # structure: list of JWKs(dict)
    def __init__(self, db_path=DB_FILE):
        # store as ADT, decode when read, print pretty, but also comparisons will be easier
        self.key_list = []
        self.private_key_list = {}
        # get connection to database
        self.db_con = sqlite3.connect(db_path)
        cur = self.db_con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
                )
        """)
        # load every stored key into memory first
        res = cur.execute("SELECT kid, key, exp FROM keys")
        for extracted_key in res.fetchall():
            self.generate_key(*extracted_key)

        # make sure at least 1 expired and 1 valid key exist (for POST:/auth)
        cur_time = int(dt.datetime.now(dt.UTC).timestamp())
        if not any(k["exp"] <= cur_time for k in self.key_list):
            self.create_new_jwk(expiry=0, expired=True)
        if not any(k["exp"] > cur_time for k in self.key_list):
            self.create_new_jwk(expiry=24)

        # so the keys in database should track the live keys exactly at run time

    def generate_key(self, kid, private_bytes, exp):
        """ generates and adds key to keyring from database info """
        # generate public key
        private_key = serialization.load_pem_private_key(
            private_bytes,
            password=None
        )

        modu_exp_b64 = util_get_modu_and_exp_base64(private_key.public_key())

        # generate timestamp and exp timestamp
        init_at = dt.datetime.now(dt.UTC)

        # encode our data in dictionary 
        jwk = {
            "kty": "RSA", # always gonna be rsa
            "use": "sig", # assuming signature for now
            "kid": kid,
            "n" : modu_exp_b64[0], # public key modulo 
            "e": modu_exp_b64[1], # public key ex
            "alg": "RS256",
            "iat": int(init_at.timestamp()),
            "exp": exp
        }
        # add key to key ring
        self.private_key_list[kid] = private_key
        self.key_list.append(jwk)


    def is_unique_kid(self, kid) -> bool:
        """Check if kid is unique in the keyring"""
        for key_entry in self.key_list:
            if key_entry["kid"] == kid:
                return False
        return True

    def create_new_jwk(self, kid=None, expiry=24, expired=False):
        """add key to keyring with kid"""
        # only honor a caller supplied kid if it is an unused int,
        # otherwise let sqlite assign one (guarantees uniqueness vs the db)
        if not isinstance(kid, int) or isinstance(kid, bool) or not self.is_unique_kid(kid):
            kid = None

        # generate keys
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE
        ) # generate with defaults
        
        # converting our ints to b64 url safe encoded values
        modu_exp_b64 = util_get_modu_and_exp_base64(private_key.public_key())
        
        # init timestamp data, used twice...
        init_at = dt.datetime.now(dt.UTC)
        if expired:
            exp_at = dt.datetime.now(dt.UTC) - dt.timedelta(1)
        else:
            exp_at = dt.datetime.now(dt.UTC) + dt.timedelta(hours=expiry)

        # put our key in the database (parameterized, never string built)
        db_ready_key = util_serialize_private_key(private_key)
        cur = self.db_con.cursor()
        cur.execute(
            "INSERT INTO keys(kid, key, exp) VALUES(?, ?, ?)",
            (kid, db_ready_key, int(exp_at.timestamp()))
        )
        kid = cur.lastrowid
        self.db_con.commit()

        # set up our jwk structure
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

        # hold on to our private key, and append the public to the keyring
        self.private_key_list[kid] = private_key
        self.key_list.append(jwk)
    
    def get_keys(self, expired=False) -> list:
        """ return list of keys, expired if you want that """
        # grab current dt
        cur_time = dt.datetime.now(dt.UTC)
        # create output key list and loop comparing the exp values
        out_key_list = []
        for key_entry in self.key_list:
            if (key_entry["exp"] > int(cur_time.timestamp())) != expired: # compair, and flip if we are looking for expired
                # interesting evil bug of pain
                key_copy = copy.deepcopy(key_entry)
                key_copy["kid"] = str(key_entry["kid"])
                out_key_list.append(key_copy)
            else:
                # if its expired then pass and continue looking
                continue
        if out_key_list == []:
            raise LookupError("No Keys Bozo")
        return out_key_list
    
    def __del__(self):
        self.db_con.close()

def util_get_modu_and_exp_base64(public_key) -> tuple:
    """ returns the modulus and exponent of a given public key in tuple"""
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


def util_serialize_private_key(private_key):
    """ takes a private key """
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_private_key