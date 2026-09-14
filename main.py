
from fastapi import FastAPI
import keys
import uvicorn 

app = FastAPI()

@app.get("/")
async def root():
    """ index, let them know whats up """
    return { "message" : "JWKS service running..." }
    

@app.get("/jwks")
async def get_jwks():
    """ reply with keys """
    # init keyring
    key_ring = keys.Key_Ring()
    key_ring.create_new_jwk()
    key_ring.create_new_jwk()
    key_ring.create_new_jwk()
    key_ring.create_new_jwk()
    key_ring.create_new_jwk()
    key_ring.create_new_jwk()
    return {"keys": key_ring}

if __name__ == "__main__":
    """ run unicorn web server using app on 8080 """
    uvicorn.run(app, host="127.0.0.1", port=8080)