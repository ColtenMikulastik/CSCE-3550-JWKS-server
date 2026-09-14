import unittest
from fastapi.testclient import TestClient
from main import app
import json

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
    
    def test_jwks_endpoint_structure(self):
        """Test the /jwks endpoint returns proper structure"""
        response = self.client.get("/jwks")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Check that we have a "valid_keys" key
        self.assertIn("valid_keys", data)
        
    def test_jwks_endpoint_returns_multiple_keys(self):
        """Test that /jwks endpoint creates multiple keys"""
        response = self.client.get("/jwks")
        data = response.json()
        
        # The endpoint should create keys and return them
        self.assertIn("valid_keys", data)
        
        # Check we have valid keys returned
        valid_keys = data["valid_keys"]
        self.assertIsInstance(valid_keys, list)
        
    def test_jwks_endpoint_returns_valid_jwk_structure(self):
        """Test that the returned keys have proper JWK structure"""
        response = self.client.get("/jwks")
        data = response.json()
        
        # Access the valid_keys from the response
        valid_keys = data["valid_keys"]
        
        # Check that we have at least some keys 
        self.assertGreater(len(valid_keys), 0)
        
        # Validate structure of each key
        for key in valid_keys:
            self.assertIn("kty", key)
            self.assertEqual(key["kty"], "RSA")
            self.assertIn("use", key)
            self.assertEqual(key["use"], "sig")
            self.assertIn("kid", key)
            self.assertIn("n", key)  # modulus
            self.assertIn("e", key)  # exponent
            self.assertIn("alg", key)
            self.assertEqual(key["alg"], "RS256")

if __name__ == '__main__':
    unittest.main()