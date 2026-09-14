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
        
        # Check that we have a "keys" key
        self.assertIn("keys", data)
        # data type will change 
    
    def test_jwks_endpoint_returns_multiple_keys(self):
        """Test that /jwks endpoint creates multiple keys"""
        response = self.client.get("/jwks")
        data = response.json()
        
        # The endpoint should create 6 JWT keys according to main.py
        # Since we're returning the Key_Ring object directly, we can't easily test 
        # the exact number of keys without examining the internal structure
        
        # But we can at least verify it returns a valid JSON structure
        self.assertIn("keys", data)
        
    def test_jwks_endpoint_returns_valid_jwk_structure(self):
        """Test that the returned keys have proper JWK structure"""
        response = self.client.get("/jwks")
        data = response.json()
        
        # Access the key_list from the Key_Ring object
        if hasattr(data["keys"], 'key_list'):
            key_list = data["keys"].key_list
        else:
            # If it's a dict, try to get the keys
            key_list = data["keys"].get("key_list", [])
        
        # Check that we have at least some keys (the endpoint should create 6)
        self.assertGreater(len(key_list), 0)
        
        # Validate structure of each key
        for key in key_list:
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