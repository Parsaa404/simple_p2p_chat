# crypto.py
# This module will handle the end-to-end encryption and decryption of messages.
# It will use libraries like 'cryptography' or 'PyNaCl'.

from cryptography.fernet import Fernet, InvalidToken

# کلید باید 32 بایت و به صورت URL-safe base64 encoded باشد.
# Fernet.generate_key() یک کلید مناسب تولید می‌کند.
# PRE_SHARED_KEY = Fernet.generate_key()
# برای سادگی و تست، یک کلید از پیش تعریف شده استفاده می‌کنیم.
# هشدار: این کلید نباید در یک برنامه واقعی به این صورت استفاده شود.
# هر دو طرف ارتباط باید این کلید را داشته باشند.
PRE_SHARED_KEY = b'ctH_b9pX_aN4Yc72JaVqZ1t9w0x8R_lO5sK-Pz_nUqE=' # یک کلید نمونه Fernet

def generate_key():
    """Generates a new Fernet key."""
    return Fernet.generate_key()

def encrypt_message(message: str, key: bytes) -> bytes:
    """
    Encrypts a string message using the provided Fernet key.
    Returns the encrypted message as bytes.
    """
    try:
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode('utf-8'))
        return encrypted_message
    except Exception as e:
        print(f"Encryption error: {e}")
        return b'' # Return empty bytes on error

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    """
    Decrypts an encrypted message (bytes) using the provided Fernet key.
    Returns the decrypted message as a string.
    Returns an empty string if decryption fails.
    """
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode('utf-8')
    except InvalidToken:
        print("Decryption error: Invalid token or key.")
        return "Error: Could not decrypt message (Invalid Token/Key)"
    except Exception as e:
        print(f"Decryption error: {e}")
        return "Error: Could not decrypt message"
