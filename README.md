
# JWKS Server 
- run through `uv run fastapi dev`

- this server attempts to serve JWT (jots) which are self signed packets of json info, which verify integrity through asymetric keys 

## Production Path:
- [x] 0.1.0: Basic FastAPI Server Setup
    - configured FastAPI
    - connect to uvicorn
- [ ] 0.2.0: Generate RSA Keys
- [ ] 0.3.0: Add Key Expiry Logic
- [ ] 0.4.0: Authentication Endpoint
- [ ] 0.5.0: Complete Implementation & Testing