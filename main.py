
from fastapi import FastAPI
import datetime as dt
import uvicorn
import keys
import jwt

app = FastAPI()
key_ring = keys.KeyRing()
key_ring.create_new_jwk()
key_ring.create_new_jwk(expiry=0, expired=True)

def create_jwt(expiry=24, expired=False):
    """ creates a jwt, can make it expired if you want that """
    # get the time
    init_at = dt.datetime.now(dt.UTC)
    exp_at = dt.datetime.now(dt.UTC) + dt.timedelta(expiry)


    # pull our jwk to sign here either expired or not
    # grab the first key
    try:
        jwk = key_ring.get_keys(expired=expired)[0]
    except LookupError as e:
        print(f"create jwt called before jwk: {e}")
        # create a jwk
        key_ring.create_new_jwk(expiry=expiry, expired=expired)
        jwk = key_ring.get_keys(expired=expired)[0]
    
    # pair our jwk with our jwt
    jwt_wrapper = {
        "iat": int(init_at.timestamp()),
        "exp": int(exp_at.timestamp()),
        "cnf": {
            "jwk": jwk
        }
    }

    # get our private key out
    private_key = key_ring.private_key_list[jwk["kid"]]

    # generate the jwt using the jwk
    private_key_pem = private_key
    complete_jwt = jwt.encode(
        jwt_wrapper,
        private_key_pem,
        algorithm="RS256",
        headers={"kid": jwk["kid"]}
    )
    # I'm gonna store the Jwt as a key in the JWK dictionary entry 
    return complete_jwt

@app.post("/auth")
async def auth_handler(expired: str | None = None):
    """ return new JWT, unless expired param """
    if expired is not None:
        # create expired jwt
        jwt = create_jwt(expiry=0, expired=True)
    else:
        jwt = create_jwt(expiry=24)
    return { "token": jwt }


@app.get("/")
async def root():
    """ index, let them know whats up """
    return { "message" : "JWKS service running..." }
    

@app.get("/.well-known/jwks.json")
async def get_jwks():
    """ reply with keys """
    # init keyring
    key_ring.create_new_jwk()
    key_ring.create_new_jwk(expiry=0, expired=True)
    key_ring.create_new_jwk(kid="cat")
    key_ring.create_new_jwk(kid="cat")
    return {"keys": key_ring.get_keys()}

if __name__ == "__main__":
    """ run unicorn web server using app on 8080 """
    uvicorn.run(app, host="127.0.0.1", port=8080)