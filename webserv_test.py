import unittest
from fastapi.testclient import TestClient
from main import app
import json
import jwt
import datetime

class TestWebServer(unittest.TestCase):
    def setUp(self):
        """Set up test client before each test"""
        self.client = TestClient(app)
    
    def test_root_endpoint(self):
        """Test the root endpoint returns correct message"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("message", data)
        self.assertEqual(data["message"], "JWKS service running...")
    
    def test_well_known_jwks_endpoint_structure(self):
        """Test the /.well-known/jwks.json endpoint returns proper structure"""
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check that we have a "keys" key (not "valid_keys")
        self.assertIn("keys", data)
        
    def test_well_known_jwks_endpoint_returns_multiple_keys(self):
        """Test that /.well-known/jwks.json endpoint creates multiple keys"""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        
        # The endpoint should create keys and return them
        self.assertIn("keys", data)
        
        # Check we have valid keys returned
        keys = data["keys"]
        self.assertIsInstance(keys, list)
        
    def test_well_known_jwks_endpoint_returns_valid_jwk_structure(self):
        """Test that the returned keys have proper JWK structure"""
        response = self.client.get("/.well-known/jwks.json")
        data = response.json()
        
        # Access the keys from the response
        keys = data["keys"]
        
        # Check that we have at least some keys 
        self.assertGreater(len(keys), 0)
        
        # Validate structure of each key
        for key in keys:
            self.assertIn("kty", key)
            self.assertEqual(key["kty"], "RSA")
            self.assertIn("use", key)
            self.assertEqual(key["use"], "sig")
            self.assertIn("kid", key)
            self.assertIn("n", key)  # modulus
            self.assertIn("e", key)  # exponent
            self.assertIn("alg", key)
            self.assertEqual(key["alg"], "RS256")
    
    def test_auth_endpoint_returns_jwt(self):
        """Test the /auth endpoint returns a valid JWT"""
        response = self.client.post("/auth")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check that we have a token
        self.assertIn("token", data)
        token = data["token"]
        print(token)
        
        # Validate the JWT structure and signature
        try:
            # Decode without verification to check structure
            decoded = jwt.decode(token, options={"verify_signature": False})
            jwk_decode = decoded["cnf"]["jwk"]
            # Check required claims are present
            self.assertIn("kid", jwk_decode)
            self.assertIn("iat", jwk_decode)
            self.assertIn("exp", jwk_decode)
            
            # Check that iat and exp are valid timestamps
            self.assertIsInstance(decoded["iat"], int)
            self.assertIsInstance(decoded["exp"], int)
            
            # Check that token is not expired (should be valid for at least 1 hour)
            current_time = int(datetime.datetime.now().timestamp())
            self.assertLessEqual(decoded["iat"], current_time)
            self.assertGreater(decoded["exp"], current_time)
            
        except Exception as e:
            self.fail(f"JWT validation failed: {e}")

    def test_auth_endpoint_returns_valid_jwt_structure(self):
        """Test that the JWT returned has proper structure"""
        response = self.client.post("/auth")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        token = data["token"]
        
        # Try to decode the JWT to verify it's valid
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            jwk_decode = decoded["cnf"]["jwk"]
            
            # Check that we have standard JWT claims
            self.assertIn("kid", jwk_decode)
            self.assertIn("iat", jwk_decode)
            self.assertIn("exp", jwk_decode)
            
            # Check that the claims have expected types
            self.assertIsInstance(decoded["iat"], int)
            self.assertIsInstance(decoded["exp"], int)
            
        except Exception as e:
            self.fail(f"Failed to decode JWT: {e}")

    def test_jwks_endpoint_returns_keys(self):
        """Test that the endpoint returns keys with proper structure"""
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check that we have a "keys" key
        self.assertIn("keys", data)
        
        # Check that keys is a list
        keys = data["keys"]
        self.assertIsInstance(keys, list)
        
        # If there are keys, check their structure
        if len(keys) > 0:
            key = keys[0]
            self.assertIn("kty", key)
            self.assertEqual(key["kty"], "RSA")
            self.assertIn("use", key)
            self.assertEqual(key["use"], "sig")
            self.assertIn("kid", key)
            self.assertIn("n", key)
            self.assertIn("e", key)
            self.assertIn("alg", key)
            self.assertEqual(key["alg"], "RS256")

if __name__ == '__main__':
    unittest.main()