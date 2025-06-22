import threading
import time
from network import send_message, start_listening
from crypto import encrypt_message, decrypt_message, PRE_SHARED_KEY, generate_key

# آدرس IP و پورت خودتان برای گوش دادن
# برای تست در یک ماشین، می‌توانید از 127.0.0.1 استفاده کنید
# اگر در شبکه محلی تست می‌کنید، IP محلی خود را وارد کنید (مثلا 192.168.1.X)
# پورت می‌تواند هر عدد آزادی باشد، مثلا 12345
MY_IP = "127.0.0.1" # یا IP شبکه محلی شما
MY_PORT = 0 # پورت به صورت داینامیک توسط کاربر یا به صورت پیش‌فرض تعیین می‌شود

def handle_received_message(encrypted_data, sender_address):
    """
    Callback function to handle incoming encrypted messages.
    """
    print(f"\n[+] Encrypted message received from {sender_address}")
    decrypted_message = decrypt_message(encrypted_data, PRE_SHARED_KEY)
    if decrypted_message.startswith("Error:"):
        print(f"[-] Decryption failed: {decrypted_message}")
    else:
        print(f"    Decrypted: {decrypted_message}")
    print_prompt()

def print_prompt():
    """Prints the input prompt for the user."""
    print("\nEnter message to send (or type 'exit' to quit, 'newkey' to generate a new shared key):")
    print("Format: <recipient_ip>:<recipient_port> Your message here")
    print("Example: 127.0.0.1:12346 Hello there!")
    print("> ", end="", flush=True)


if __name__ == "__main__":
    print("Starting Peer-to-Peer Anonymous Messenger...")

    while MY_PORT == 0:
        try:
            port_input = input("Enter the port you want to listen on (e.g., 12345): ")
            MY_PORT = int(port_input)
            if not (1024 <= MY_PORT <= 65535):
                print("Port number must be between 1024 and 65535.")
                MY_PORT = 0
        except ValueError:
            print("Invalid port number. Please enter a number.")
            MY_PORT = 0

    print(f"Your address is: {MY_IP}:{MY_PORT}")
    print(f"Using pre-shared key: {PRE_SHARED_KEY.decode()}")
    print("Warning: This key is for demonstration. For secure communication, generate and share a new key ('newkey' command).")

    # شروع گوش دادن به پیام‌های ورودی در یک نخ جدا
    start_listening(MY_IP, MY_PORT, handle_received_message)

    time.sleep(0.5) # کمی تاخیر برای اطمینان از شروع کامل listener
    print_prompt()

    try:
        while True:
            user_input = input()
            if not user_input: # اگر ورودی خالی بود، دوباره prompt نمایش داده شود
                print_prompt()
                continue

            if user_input.lower() == 'exit':
                print("Exiting messenger...")
                break
            elif user_input.lower() == 'newkey':
                new_key = generate_key()
                print(f"New generated pre-shared key: {new_key.decode()}")
                print("Please share this key securely with your peer and restart the application with this new key in crypto.py.")
                print_prompt()
                continue

            try:
                # فرمت ورودی: <ip>:<port> <message>
                parts = user_input.split(" ", 1)
                if len(parts) < 2:
                    print("Invalid format. Use: <ip>:<port> <message>")
                    print_prompt()
                    continue

                address_part, message_to_send = parts[0], parts[1]

                if ':' not in address_part:
                    print("Invalid address format. Use: <ip>:<port>")
                    print_prompt()
                    continue

                recipient_ip, recipient_port_str = address_part.split(":", 1)

                try:
                    recipient_port = int(recipient_port_str)
                    if not (1024 <= recipient_port <= 65535):
                        print("Recipient port number must be between 1024 and 65535.")
                        print_prompt()
                        continue
                except ValueError:
                    print("Invalid recipient port number.")
                    print_prompt()
                    continue

                if not message_to_send.strip():
                    print("Cannot send an empty message.")
                    print_prompt()
                    continue

                print(f"[*] Encrypting: '{message_to_send}'")
                encrypted_message = encrypt_message(message_to_send, PRE_SHARED_KEY)

                if encrypted_message:
                    print(f"[*] Sending to {recipient_ip}:{recipient_port}...")
                    send_message(recipient_ip, recipient_port, encrypted_message)
                    # پیام ارسالی خودمان را نمایش نمی‌دهیم، فقط پیام‌های دریافتی
                else:
                    print("[-] Failed to encrypt message. Not sent.")

                print_prompt()

            except ValueError as ve:
                print(f"Error processing input: {ve}. Please use the format <ip>:<port> <message>")
                print_prompt()
            except Exception as e:
                print(f"An error occurred: {e}")
                print_prompt()

    except KeyboardInterrupt:
        print("\nExiting messenger (Ctrl+C pressed)...")
    finally:
        # هرگونه پاک‌سازی لازم در اینجا انجام شود
        # listener thread به دلیل daemon=True خودکار بسته می‌شود
        print("Messenger shut down.")
