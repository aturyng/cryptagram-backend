
import base64
from django.contrib.auth.hashers import make_password, check_password
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes
from hashlib import pbkdf2_hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class EncryptionService:

    STR_ENCODING = "utf-8"
    SALT_SIZE = 16
    IV_SIZE = 16
    AES_VER = 256
    HASH_ALG = 'sha256'

    def encrypt_string(self, key, iv, plaintext):
        # Create an AES cipher with the provided key and IV
        cipher = Cipher(algorithms.AES256(key), modes.CBC(iv.encode(self.STR_ENCODING)))

        # Create a PKCS7 padding object with the block size of AES (n bytes)
        padder = padding.PKCS7(self.AES_VER).padder()

        # Pad the plaintext data
        padded_data = padder.update(plaintext.encode(self.STR_ENCODING)) + padder.finalize()

        # Create an encryptor object
        encryptor = cipher.encryptor()

        # Encrypt the plaintext
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the encrypted ciphertext
        return ciphertext

    def decrypt_string(self, key, iv, ciphertext):
        # Create an AES cipher with the provided key and IV
        cipher = Cipher(algorithms.AES256(key), modes.CBC(iv.encode(self.STR_ENCODING)))

        # Create an encryptor object
        decryptor = cipher.decryptor()

        # Encrypt the plaintext
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()


        # Remove PKCS7 padding from the decrypted plaintext
        unpadder = padding.PKCS7(self.AES_VER).unpadder()
        decrypted_plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Return the decrypted plaintext
        return decrypted_plaintext.decode(self.STR_ENCODING)

    def hash_password(self, password):
        hashed_password = make_password(password)
        return hashed_password

    def derive_aes_key_from_password(self, password, salt):
        # Derive the AES key using PBKDF2 with HMAC-SHA256
        key = pbkdf2_hmac(hash_name=self.HASH_ALG, password=password.encode(self.STR_ENCODING), salt=salt.encode(self.STR_ENCODING), iterations=100000, dklen=32)
        # Return the derived key as bytes
        return key
    
    def generate_salt(self, length = SALT_SIZE):
        salt = get_random_string(length)
        return salt
    
    def generate_iv(self, length = IV_SIZE):
        iv = get_random_string(length)
        return iv
    

    def join_salt_iv_ciphertext(self, salt, iv, ciphertext):
        combined = salt + iv + ciphertext.hex()
        return combined


    def destructure_salt_iv_encrypted(self, combined_str):
        salt = combined_str[:self.SALT_SIZE]

        iv_plus_ciphertext = combined_str[self.SALT_SIZE:]

        iv = iv_plus_ciphertext[:self.IV_SIZE]

        ciphertext_hex = iv_plus_ciphertext[self.IV_SIZE:]
        ciphertext = bytes.fromhex(ciphertext_hex)
        return salt, iv, ciphertext

    def decode_base64_str(self, base64_str):
        # Decode the bytes using base64 decoding
        decoded_bytes = base64.b64decode(base64_str)

        # Convert the decoded bytes back to a string
        decoded_string = decoded_bytes.decode(self.STR_ENCODING)
        return decoded_string

    def encode_str_to_base64(self, plain_str):
        # Decode the bytes using base64 decoding
        encoded_bytes = base64.b64encode(plain_str.encode(self.STR_ENCODING))

        # Convert the decoded bytes back to a string
        encoded_string = encoded_bytes.decode(self.STR_ENCODING)
        return encoded_string

    def decrypt(self, combined_encrypted_str, password):
        salt, iv, ciphertext = self.destructure_salt_iv_encrypted(combined_encrypted_str)
        aes_key = self.derive_aes_key_from_password(password, salt)
        plain_text = self.decrypt_string(aes_key, iv, ciphertext)
        return plain_text

