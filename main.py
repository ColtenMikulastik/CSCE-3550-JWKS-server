
from fastapi import FastAPI

app = FastAPI()

keys = {
    "message": "Hey here are all the keys",
    "number_of_keys": 2,
    "key_1": "abcedfg",
    "key_2": "abcedfg",
}


@app.get("/")
async def root():
    return keys
    

