import unittest
from keys import Key_Ring, util_get_modu_and_exp_base64
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

class TestKeyRing(unittest.TestCase):
    def setUp(self):
        self.key_ring = Key_Ring()
    
    def test_create_new_jwk_with_kid(self):
        """Test creating a new JWT key with a specific kid"""
        kid = "test-key-id"
        self.key_ring.create_new_jwk(kid)
        
        # Check that we have one key
        self.assertEqual(len(self.key_ring.key_list), 1)
        
        # Check key properties
        key = self.key_ring.key_list[0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["kid"], kid)
        self.assertEqual(key["alg"], "RS256")
        self.assertIn("n", key)  # modulus
        self.assertIn("e", key)   # exponent
        
    def test_create_new_jwk_without_kid(self):
        """Test creating a new JWT key without specifying kid (should auto-generate)"""
        self.key_ring.create_new_jwk()
        
        # Check that we have one key
        self.assertEqual(len(self.key_ring.key_list), 1)
        
        # Check key properties
        key = self.key_ring.key_list[0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertIsInstance(key["kid"], str)  # Should be auto-generated
        self.assertEqual(key["alg"], "RS256")
        self.assertIn("n", key)  # modulus
        self.assertIn("e", key)   # exponent
    
    def test_multiple_keys(self):
        """Test creating multiple keys"""
        self.key_ring.create_new_jwk("key1")
        self.key_ring.create_new_jwk("key2")
        self.key_ring.create_new_jwk()
        
        # Check that we have three keys
        self.assertEqual(len(self.key_ring.key_list), 3)
        
        # Check each key has proper structure
        for key in self.key_ring.key_list:
            self.assertEqual(key["kty"], "RSA")
            self.assertEqual(key["use"], "sig")
            self.assertEqual(key["alg"], "RS256")
            self.assertIn("n", key)
            self.assertIn("e", key)
    
    def test_util_get_modu_and_exp_base64(self):
        """Test the utility function for base64 encoding"""
        # Generate a test private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Get the base64 encoded components
        result = util_get_modu_and_exp_base64(private_key.public_key())
        
        # Check we get a tuple with two elements
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        
        modulus_b64, exponent_b64 = result
        
        # Check both are strings
        self.assertIsInstance(modulus_b64, str)
        self.assertIsInstance(exponent_b64, str)
        
        # Check they're valid base64 (no errors when decoding)
        try:
            base64.urlsafe_b64decode(modulus_b64)
            base64.urlsafe_b64decode(exponent_b64)
        except Exception as e:
            self.fail(f"Base64 decoding failed: {e}")

    def test_key_structure_integrity(self):
        """Test that generated keys maintain proper structure"""
        # Create a key
        self.key_ring.create_new_jwk("test-key")
        
        key = self.key_ring.key_list[0]
        
        # Check all required fields are present and have correct types
        self.assertIn("kty", key)
        self.assertEqual(key["kty"], "RSA")
        
        self.assertIn("use", key)
        self.assertEqual(key["use"], "sig")
        
        self.assertIn("kid", key)
        self.assertIsInstance(key["kid"], str)
        
        self.assertIn("n", key)
        self.assertIsInstance(key["n"], str)
        
        self.assertIn("e", key)
        self.assertIsInstance(key["e"], str)
        
        self.assertIn("alg", key)
        self.assertEqual(key["alg"], "RS256")

if __name__ == '__main__':
    unittest.main()
