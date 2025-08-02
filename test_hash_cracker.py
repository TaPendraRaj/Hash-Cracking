import unittest
from hash_cracker import identify_hash_type, hash_func, crack_single_hash

class TestHashCracker(unittest.TestCase):

    def test_identify_hash_type(self):
        self.assertEqual(identify_hash_type("5d41402abc4b2a76b9719d911017c592"), "md5")
        self.assertEqual(identify_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "sha1")
        self.assertEqual(identify_hash_type("e3b0c44298fc1c149afbf4c8996fb924" +
                                            "27ae41e4649b934ca495991b7852b855"), "sha256")
        self.assertEqual(identify_hash_type(""), "unknown")

    def test_hash_func(self):
        self.assertEqual(hash_func("hello", "md5"), "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(hash_func("hello", "sha1"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        self.assertEqual(hash_func("hello", "sha256"),
                         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(hash_func("hello", "sha512"),
                         "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2df4006d1e7f4e"
                         "70f9a565d1326af46e4b6df2500b240d6cfc2f3d0e0c5d7a3392f0a1d5cd5e9f7")

    def test_crack_single_hash(self):
        # Create a mock wordlist file for testing
        test_wordlist = "test_wordlist.txt"
        with open(test_wordlist, "w") as f:
            f.write("admin\npassword\nhello\nletmein\n")

        md5_hash = "5d41402abc4b2a76b9719d911017c592"  # 'hello'
        result = crack_single_hash(md5_hash, "md5", test_wordlist)
        self.assertEqual(result, "hello")

        sha1_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"  # 'hello'
        result = crack_single_hash(sha1_hash, "sha1", test_wordlist)
        self.assertEqual(result, "hello")

if __name__ == '__main__':
    unittest.main()
