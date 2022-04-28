import base64
from Crypto.Random import get_random_bytes

def generate_static_aes_key() -> str:
    return base64.b64encode(get_random_bytes(32)).decode("utf-8")

def generate_static_hkdf_salt():
    return base64.b64encode(get_random_bytes(16)).decode("utf-8")

def display_secrets():
    print(f"STATIC_AES_KEY={generate_static_aes_key()}")
    print(f"STATIC_HKDF_SALT={generate_static_hkdf_salt()}")
    print(f"STATIC_HKDF_SALT_2={generate_static_hkdf_salt()}")

if __name__ == "__main__":
    display_secrets()