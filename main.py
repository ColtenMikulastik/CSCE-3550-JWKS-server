
from fastapi import FastAPI
import keys
import uvicorn 
import datetime as dt
import jwt


app = FastAPI()
key_ring = keys.Key_Ring()
key_ring.create_new_jwk()
key_ring.create_new_jwk(expiry=0)


def create_jwt(expiry=24, expired=False):
    """ creates a jwt, can make it expired if you want """
    init_at = dt.datetime.now()
    exp_at = dt.datetime.now() + dt.timedelta(hours=expiry)

    # pull our jwk to sign here either expired or not
    # grab the first key
    jwk = key_ring.get_keys()[0]
    
    # create the jwt
    jwt_wrapper = {
        "iat": init_at,
        "exp": exp_at,
        "cnf": {
            "jwk": jwk
        }
    }
    # get our private key out
    private_key = key_ring.private_key_list[jwk["kid"]]

    # generate the jwt using the jwk
    private_key_pem = private_key
    complete_jwt = jwt.encode(jwt_wrapper, private_key_pem, algorithm="RS256")
    # I'm gonna store the Jwt as a key in the JWK dictionary entry 
    return complete_jwt

@app.post("/auth")
async def auth_handler():
    """ return new JWT, unless expired param """
    jwt = create_jwt(expiry=24)
    return { "new jtk created": jwt }


@app.get("/")
async def root():
    """ index, let them know whats up """
    return { "message" : "JWKS service running..." }
    

@app.get("/.well-known/jwks.json")
async def get_jwks():
    """ reply with keys """
    # init keyring
    key_ring.create_new_jwk()
    key_ring.create_new_jwk(expiry=0)
    return {"keys": key_ring.get_keys()}

if __name__ == "__main__":
    """ run unicorn web server using app on 8080 """
    uvicorn.run(app, host="127.0.0.1", port=8080)