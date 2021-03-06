
import base64
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
import os
from dotenv import load_dotenv

# INITS
load_dotenv()

class Encryption_Class:

    def __init__(self):

        # constant AES key for both partners
        self.static_aes_key : str = os.getenv('STATIC_AES_KEY')

        # constant salt used for deriving master runtime AES key
        self.static_hkdf_salt : str = os.getenv('STATIC_HKDF_SALT')

        # constant kdf salt for deriving new master AES key after ever message
        self.static_hkdf_salt_2 : str = os.getenv('STATIC_HKDF_SALT_2') 

        # runtime generated RSA key pair
        self.own_rsa_key_pair = self.generate_rsa_key_pair(4096) 

        # runtime generated AES key
        self.own_runtime_aes_key: str = self.generate_runtime_aes_key() 

        # tells whether the user sent his runtime AES key or not yet
        self.sent_runtime_aes_key: bool = False 

        # this master AES key will be derived from the combination of the runtime AES keys of both partners
        # used to encrypt text messages
        self.__master_runtime_aes: str = "" 

        # stores runtime AES key of the partner after receiving it
        self.__partner_runtime_aes: str = ""

        # stores RSA the public key of the partner after receiving it
        self.__partner_public_key : str = ""

    
    def generate_rsa_key_pair(self, keysize: int):
        rsa_key_pair = RSA.generate(keysize)
        rsa_public_key: bytes = rsa_key_pair.public_key().export_key()
        rsa_private_key: bytes = rsa_key_pair.export_key()
        return (base64.b64encode(rsa_public_key).decode("utf-8"), base64.b64encode(rsa_private_key).decode("utf-8"))
    

    def generate_runtime_aes_key(self) -> str:
        return base64.b64encode(get_random_bytes(32)).decode("utf-8")
    

    # derives a master runtime AES key from the combination of the runtime AES keys of both partners
    # the master runtime AES key is used to encrypt messages
    def derive_master_runtime_aes_key(self, combined_runtime_aes_keys: str, static_hkdf_salt: str):
        bytes_combined_runtime_aes = base64.b64decode(combined_runtime_aes_keys.encode("utf-8"))
        bytes_salt = base64.b64decode(static_hkdf_salt.encode("utf-8"))
        final_runtime_aes = HKDF(bytes_combined_runtime_aes, 32, bytes_salt, SHA512, 1)
        return base64.b64encode(final_runtime_aes).decode("utf-8")


    # derives a new master runtime AES key after every message
    def derive_new_master_runtime_aes_key(self, old_master_runtime_aes_key, static_hkdf_salt_2):
        bytes_old_final_runtime_aes = base64.b64decode(old_master_runtime_aes_key.encode("utf-8"))
        bytes_salt = base64.b64decode(static_hkdf_salt_2.encode("utf-8"))
        new_final_runtime_aes = HKDF(bytes_old_final_runtime_aes, 32, bytes_salt, SHA512, 1)
        return base64.b64encode(new_final_runtime_aes).decode("utf-8")


    # partner public key methods
    def update_partner_public_key(self, partner_public_key):
        self.__partner_public_key = partner_public_key
    
    def return_partner_public_key(self):
        return self.__partner_public_key
    

    # partner runtime AES key methods
    def update_partner_runtime_aes_key(self, partner_runtime_aes_key):
        self.__partner_runtime_aes = partner_runtime_aes_key
    
    def return_partner_runtime_aes_key(self):
        return self.__partner_runtime_aes


    # master runtime AES key methods
    def update_master_runtime_aes_key(self, master_runtime_aes_key):
        self.__master_runtime_aes = master_runtime_aes_key
    
    def return_master_runtime_aes_key(self):
        return self.__master_runtime_aes


    # returns the encrypted messages with the nonce in the end, separated by ":" (base64 encoded)
    def aes_encrypt_string(self, message: str, aes_key: str) -> str:
        bytes_aes_key = base64.b64decode(aes_key.encode("utf-8"))
        bytes_message = base64.b64decode(message.encode("utf-8"))
        cipher = AES.new(bytes_aes_key, AES.MODE_EAX)
        ciphertext, _ = cipher.encrypt_and_digest(bytes_message)
        return (f'{base64.b64encode(ciphertext).decode("utf-8")}:{base64.b64encode(cipher.nonce).decode("utf-8")}')
    
    # returns the decrypted content (base64 encoded)
    def aes_decrypt_string(self, encrypted_content: str, aes_key: str) -> str:
        bytes_aes_key = base64.b64decode(aes_key.encode("utf-8"))
        encrypted_message, nonce = encrypted_content.split(":")
        bytes_encrypted_message, bytes_nonce =  base64.b64decode(encrypted_message.encode("utf-8")), base64.b64decode(nonce.encode("utf-8"))
        cipher = AES.new(bytes_aes_key, AES.MODE_EAX, nonce=bytes_nonce)
        message = cipher.decrypt(bytes_encrypted_message)
        return base64.b64encode(message).decode("utf-8")

    # returns the encrypted message (base64 encoded)
    def rsa_encrypt_string(self, message: str, rsa_public_key: str) -> str:
        bytes_rsa_public_key = base64.b64decode(rsa_public_key.encode("utf-8"))
        bytes_message = base64.b64decode(message.encode("utf-8"))
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(bytes_rsa_public_key))
        ciphertext = cipher_rsa.encrypt(bytes_message)
        return base64.b64encode(ciphertext).decode("utf-8")

    # returns the decrypted content (base64 encoded)
    def rsa_decrypt_string(self, encrypted_message: str, rsa_private_key: str):
        bytes_rsa_private_key = base64.b64decode(rsa_private_key.encode("utf-8"))
        bytes_encrypted_message = base64.b64decode(encrypted_message.encode("utf-8"))
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(bytes_rsa_private_key))
        message = cipher_rsa.decrypt(bytes_encrypted_message)
        return base64.b64encode(message).decode("utf-8")
