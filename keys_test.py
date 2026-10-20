import base64
import os
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from keys import KeyRing, util_get_modu_and_exp_base64


class TestKeyRing(unittest.TestCase):
    def setUp(self):
        # isolated db per test so we never touch the real key file
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test.db")
        self.key_ring = KeyRing(db_path=self.db_path)
        # constructor seeds one expired and one valid key
        self.base = len(self.key_ring.key_list)

    def tearDown(self):
        self.key_ring.db_con.close()
        self.tmp_dir.cleanup()

    def test_seeded_keys(self):
        """Constructor stores one expired and one valid key"""
        self.assertEqual(self.base, 2)
        self.assertEqual(len(self.key_ring.get_keys()), 1)
        self.assertEqual(len(self.key_ring.get_keys(expired=True)), 1)

    def test_keys_persist_in_db(self):
        """A new KeyRing on the same db reloads the same keys"""
        self.key_ring.create_new_jwk()
        kids = {k["kid"] for k in self.key_ring.key_list}
        other = KeyRing(db_path=self.db_path)
        self.assertEqual({k["kid"] for k in other.key_list}, kids)
        other.db_con.close()

    def test_stored_as_pem_blob(self):
        """Rows in the db hold PEM private keys"""
        con = sqlite3.connect(self.db_path)
        rows = con.execute("SELECT key FROM keys").fetchall()
        con.close()
        self.assertEqual(len(rows), self.base)
        for (blob,) in rows:
            self.assertTrue(blob.startswith(b"-----BEGIN PRIVATE KEY-----"))

    def test_get_keys_no_match_raises(self):
        """Asking for a category with no keys raises LookupError"""
        self.key_ring.key_list = []
        with self.assertRaises(LookupError):
            self.key_ring.get_keys()

    def test_is_unique_kid(self):
        """kid uniqueness check"""
        used = self.key_ring.key_list[0]["kid"]
        self.assertFalse(self.key_ring.is_unique_kid(used))
        self.assertTrue(self.key_ring.is_unique_kid(10**9))
    
    def test_create_new_jwk_with_kid(self):
        """Test creating a new JWT key with a specific kid"""
        kid = 424242
        self.key_ring.create_new_jwk(kid)
        
        # Check that we have one key
        self.assertEqual(len(self.key_ring.key_list), self.base + 1)
        
        # Check key properties
        key = self.key_ring.key_list[-1]
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
        self.assertEqual(len(self.key_ring.key_list), self.base + 1)
        
        # Check key properties
        key = self.key_ring.key_list[-1]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertIsInstance(key["kid"], int)  # assigned by the db
        self.assertEqual(key["alg"], "RS256")
        self.assertIn("n", key)  # modulus
        self.assertIn("e", key)   # exponent
    
    def test_multiple_keys(self):
        """Test creating multiple keys"""
        self.key_ring.create_new_jwk(1001)
        self.key_ring.create_new_jwk(1002)
        self.key_ring.create_new_jwk()
        
        # Check that we have three keys
        self.assertEqual(len(self.key_ring.key_list), self.base + 3)
        
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
            modulus_bytes = base64.urlsafe_b64decode(modulus_b64)
            exponent_bytes = base64.urlsafe_b64decode(exponent_b64)
            
            # Verify the decoded values are valid RSA components
            modulus_int = int.from_bytes(modulus_bytes, byteorder='big')
            exponent_int = int.from_bytes(exponent_bytes, byteorder='big')
            
            # Verify they match what we'd expect from a 2048-bit key
            self.assertGreater(modulus_int, 0)
            self.assertGreater(exponent_int, 0)
            
        except Exception as e:
            self.fail(f"Base64 decoding failed: {e}")

    def test_key_structure_integrity(self):
        """Test that generated keys maintain proper structure"""
        # Create a key
        self.key_ring.create_new_jwk(555)
        
        key = self.key_ring.key_list[-1]
        
        # Check all required fields are present and have correct types
        self.assertIn("kty", key)
        self.assertEqual(key["kty"], "RSA")
        
        self.assertIn("use", key)
        self.assertEqual(key["use"], "sig")
        
        self.assertIn("kid", key)
        self.assertIsInstance(key["kid"], int)
        
        self.assertIn("n", key)
        self.assertIsInstance(key["n"], str)
        
        self.assertIn("e", key)
        self.assertIsInstance(key["e"], str)
        
        self.assertIn("alg", key)
        self.assertEqual(key["alg"], "RS256")
        
        # Check that iat and exp fields are present
        self.assertIn("iat", key)
        self.assertIn("exp", key)
        self.assertIsInstance(key["iat"], int)
        self.assertIsInstance(key["exp"], int)

if __name__ == '__main__':
    unittest.main()
