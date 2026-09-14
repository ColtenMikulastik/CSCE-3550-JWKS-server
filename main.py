
from fastapi import FastAPI
import keys
import uvicorn 

app = FastAPI()
key_ring = keys.Key_Ring()

@app.get("/")
async def root():
    """ index, let them know whats up """
    return { "message" : "JWKS service running..." }
    

@app.get("/jwks")
async def get_jwks():
    """ reply with keys """
    # init keyring
    key_ring.create_new_jwt()
    key_ring.create_new_jwt(expiry=0)
    return {"valid_keys": key_ring.get_unexpired_keys()}

if __name__ == "__main__":
    """ run unicorn web server using app on 8080 """
    uvicorn.run(app, host="127.0.0.1", port=8080)