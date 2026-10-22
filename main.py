
import datetime as dt

import jwt
import uvicorn
from fastapi import FastAPI, Query

import keys

app = FastAPI()
key_ring = keys.KeyRing()

def create_jwt(expiry=24, expired=False):
    """ creates a jwt, can make it expired if you want that """
    # get the time
    init_at = dt.datetime.now(dt.UTC)
    exp_at = dt.datetime.now(dt.UTC) + dt.timedelta(hours=expiry)

    # pull our jwk to sign here either expired or not
    # grab the first key
    try:
        jwk = key_ring.get_keys(expired=expired)[0]
    except LookupError as e:
        print(f"create jwt called before jwk: {e}")
        # create a jwk
        key_ring.create_new_jwk(expiry=expiry, expired=expired)
        jwk = key_ring.get_keys(expired=expired)[0]
    
    kid_int = int(jwk["kid"])

    # an "expired" token must actually be expired, so use the key's own expiry
    if expired:
        exp_at = dt.datetime.fromtimestamp(jwk["exp"], dt.UTC)
    
    # pair our jwk with our jwt
    jwt_wrapper = {
        "iat": int(init_at.timestamp()),
        "exp": int(exp_at.timestamp()),
        "cnf": {
            "jwk": jwk
        }
    }

    # get our private key out
    private_key = key_ring.private_key_list[kid_int]

    # generate the jwt using the jwk
    private_key_pem = private_key
    complete_jwt = jwt.encode(
        jwt_wrapper,
        private_key_pem,
        algorithm="RS256",
        headers={"kid": str(jwk["kid"])}
    )
    # I'm gonna store the Jwt as a key in the JWK dictionary entry 
    return complete_jwt

@app.post("/auth")
async def auth_handler(expired: str | None = Query(None)):
    """ return new JWT, unless expired param """
    if expired is not None:
        # create expired jwt
        encoded_jwt = create_jwt(expiry=0, expired=True)
    else:
        encoded_jwt = create_jwt(expiry=24)
    return { "token": encoded_jwt }


@app.get("/")
async def root():
    """ index, let them know whats up """
    return { "message" : "JWKS service running..." }
    

@app.get("/.well-known/jwks.json")
async def get_jwks():
    """ reply with keys """
    # init keyring
    return {"keys": key_ring.get_keys()}

if __name__ == "__main__":
    """ run unicorn web server using app on 8080 """
    uvicorn.run(app, host="127.0.0.1", port=8080)