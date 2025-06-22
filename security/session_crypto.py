# security/session_crypto.py
# Handles encryption/decryption for a session using a derived key.

from cryptography.fernet import Fernet, InvalidToken

class SessionCipher:
    def __init__(self, symmetric_key: bytes):
        """
        Initializes the cipher with a symmetric key (e.g., derived from DH exchange).
        The key must be a 32-byte URL-safe base64-encoded key for Fernet.
        The DHExchange.calculate_shared_secret already provides such a key via HKDF.
        """
        if not symmetric_key or len(symmetric_key) != 32:
            raise ValueError("Symmetric key must be 32 bytes long for Fernet.")

        # Fernet expects the key to be base64 encoded.
        # The output of HKDF (used in DHExchange) is raw bytes.
        # We need to base64 encode it to be a valid Fernet key.
        import base64
        self.fernet_key = base64.urlsafe_b64encode(symmetric_key)
        self.cipher = Fernet(self.fernet_key)
        print(f"SessionCipher initialized. Fernet key: {self.fernet_key.decode()}")

    def encrypt(self, plaintext_bytes: bytes) -> bytes:
        """Encrypts plaintext bytes."""
        if not plaintext_bytes:
            return b''
        try:
            encrypted_data = self.cipher.encrypt(plaintext_bytes)
            # print(f"DEBUG: Encrypting '{plaintext_bytes.decode('utf-8', errors='ignore')}' to '{encrypted_data.hex()}'")
            return encrypted_data
        except Exception as e:
            print(f"Encryption error: {e}")
            return b'' # Return empty on error

    def decrypt(self, ciphertext_bytes: bytes) -> bytes:
        """Decrypts ciphertext bytes. Returns original plaintext bytes or b'' on error."""
        if not ciphertext_bytes:
            return b''
        try:
            decrypted_data = self.cipher.decrypt(ciphertext_bytes)
            # print(f"DEBUG: Decrypting '{ciphertext_bytes.hex()}' to '{decrypted_data.decode('utf-8', errors='ignore')}'")
            return decrypted_data
        except InvalidToken:
            print("Decryption error: Invalid token or key (likely wrong key or corrupted data).")
            return b'' # Specific error for bad token
        except Exception as e:
            print(f"Decryption error: {e}")
            return b'' # General error

# Example Usage
if __name__ == '__main__':
    # Simulate a derived key (must be 32 raw bytes)
    # In a real scenario, this comes from DHExchange().calculate_shared_secret(...)
    example_derived_key = b'12345678901234567890123456789012' # 32 bytes

    print(f"Simulated derived key (raw bytes): {example_derived_key.hex()}")
    print(f"Length: {len(example_derived_key)} bytes")

    try:
        # Cipher for Peer A
        cipher_a = SessionCipher(example_derived_key)

        # Cipher for Peer B (using the same derived key)
        cipher_b = SessionCipher(example_derived_key)

        # Peer A encrypts a message
        message_to_send = "Hello, this is a secret message for Peer B!"
        print(f"\nOriginal message: '{message_to_send}'")

        encrypted_by_a = cipher_a.encrypt(message_to_send.encode('utf-8'))
        if encrypted_by_a:
            print(f"Encrypted by A: {encrypted_by_a.hex()}")

            # Peer B decrypts the message
            decrypted_by_b = cipher_b.decrypt(encrypted_by_a)
            if decrypted_by_b:
                print(f"Decrypted by B: '{decrypted_by_b.decode('utf-8')}'")
                assert decrypted_by_b.decode('utf-8') == message_to_send
                print("SessionCipher test: SUCCESS!")
            else:
                print("SessionCipher test: FAILED (Decryption failed at B)")
        else:
            print("SessionCipher test: FAILED (Encryption failed at A)")

        print("\n--- Test with incorrect key ---")
        wrong_key = b'anotherkeythatis32byteslong12345'
        cipher_c = SessionCipher(wrong_key)

        encrypted_again = cipher_a.encrypt("Test message".encode('utf-8'))
        print(f"Encrypted with key A: {encrypted_again.hex()}")

        decrypted_with_wrong_key = cipher_c.decrypt(encrypted_again)
        if not decrypted_with_wrong_key:
            print("Decryption with wrong key correctly failed (returned empty).")
        else:
            print(f"Decryption with wrong key INCORRECTLY succeeded: {decrypted_with_wrong_key.decode()}")

        print("\n--- Test with corrupted data ---")
        if encrypted_by_a:
            corrupted_data = encrypted_by_a[:-5] + b'xxxxx' # Corrupt last 5 bytes
            print(f"Corrupted data: {corrupted_data.hex()}")
            decrypted_corrupted = cipher_b.decrypt(corrupted_data)
            if not decrypted_corrupted:
                print("Decryption of corrupted data correctly failed (returned empty).")
            else:
                print(f"Decryption of corrupted data INCORRECTLY succeeded: {decrypted_corrupted.decode()}")

    except ValueError as ve:
        print(f"Initialization error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
