import unittest

from ..services.encryption_service import EncryptionService


class EncryptionServiceTest(unittest.TestCase):

    def test_encrypt_decrypt_msg(self):
        """
        After encryting a string, its decrypted version should be the same
        """
        # GIVEN
        service = EncryptionService()
        salt = service.generate_salt()
        password = "my_very_secret_password_Stefan_dont_look_here"
        key = service.derive_aes_key_from_password(password, salt)
        iv = service.generate_iv()
        plaintext_msg = "I am unencrypted! Oh, I feel so naked..."

        # WHEN
        encrypted_msg = service.encrypt_string(key, iv, plaintext_msg)
        decrypted_encrypted_msg = service.decrypt_string(key, iv, encrypted_msg)

        # THEN
        self.assertEqual(decrypted_encrypted_msg, plaintext_msg, 'After encryption/decryption not the same message!')


    def test_decrypt_with_recreated_key(self):
        """
        When the key is recreated with the same password and salt, the encryption/decryption should still work
        """
        # GIVEN
        service = EncryptionService()
        salt = service.generate_salt()
        password = "my_very_secret_password_Stefan_dont_look_here"
        key_original = service.derive_aes_key_from_password(password, salt)
        iv = service.generate_iv()
        plaintext_msg = "I am unencrypted! Oh, I feel so naked..."

        # WHEN
        encrypted_msg = service.encrypt_string(key_original, iv, plaintext_msg)

        key_recreated = service.derive_aes_key_from_password(password, salt)
        decrypted_encrypted_msg = service.decrypt_string(key_recreated, iv, encrypted_msg)

        # THEN
        self.assertEqual(key_original, key_recreated, 'After encryption/decryption not the same message!')
        self.assertEqual(decrypted_encrypted_msg, plaintext_msg, 'After encryption/decryption not the same message!')

    def test_destruct(self):
        # GIVEN
        service = EncryptionService()
        password = "my_very_secret_password_Stefan_dont_look_here"
        plaintext_msg = "I am unencrypted! Oh, I feel so naked..."
        salt = service.generate_salt()
        aes_key = service.derive_aes_key_from_password(password, salt)

        iv = service.generate_iv()
        ciphertext = service.encrypt_string(aes_key, iv, plaintext_msg)
        encrypted_text_with_additions = service.join_salt_iv_ciphertext(salt, iv, ciphertext)

        # WHEN
        salt_destructured, iv_destructured, ciphertext_destructured = service.destructure_salt_iv_encrypted(encrypted_text_with_additions)

        # THEN
        self.assertEqual(salt, salt_destructured, 'Salt is not the same after destructuring!')
        self.assertEqual(iv, iv_destructured, 'IV is not the same after destructuring!')
        self.assertEqual(ciphertext, ciphertext_destructured, 'Ciphertext is not the same after destructuring!')

if __name__ == '__main__':
    unittest.main()