
# JWKS Server 
- run through `uv run fastapi dev`
- this server attempts to serve JWT (jots) which are self signed packets of json info, which verify integrity through asymetric keys 

## Testing
- run through pytest
- can run pytest with: `uv run pytest`


## Production Path:
- [x] 0.1.0: Basic FastAPI Server Setup
    - configured FastAPI
    - connect to uvicorn
- [x] 0.2.0: Generate RSA Keys
    - complete RSA generation
    - basic JWT creation
- [x] 0.3.0: Add Key Expiry Logic
    - key ring holds JWK and JWT
    - key ring holds init time, and expiry
- [x] 0.4.0: Authentication Endpoint
    - creates JWT using JWK to sign,
    - when expired is present, signs expired JWT with an expired JWK
- [x] 0.5.0: Complete Implementation & Testing
