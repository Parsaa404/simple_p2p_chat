# network.py
# This module will handle the peer-to-peer network communication.
# It will use sockets (UDP or TCP) for sending and receiving messages.

def send_message(ip_address, port, message):
    """
    Sends a message to the specified IP address and port.
    """
import socket
import threading

def send_message(ip_address, port, message_bytes: bytes): # Expects bytes
    """
    Sends a message (bytes) to the specified IP address and port using UDP.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message_bytes, (ip_address, port)) # Send bytes directly
    except Exception as e:
        print(f"Error sending message: {e}")

def start_listening(host_ip, port, message_handler_callback):
    """
    Starts listening for incoming UDP messages on the specified host IP and port.
    Calls the message_handler_callback function when a message is received.
    This function runs in a separate thread.
    """
    def listen():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind((host_ip, port))
                print(f"Listening for messages on {host_ip}:{port}...")
                while True:
                    data, addr = s.recvfrom(1024) # buffer size is 1024 bytes
                    print(f"Received raw data from {addr}")
                    message_handler_callback(data, addr)
        except Exception as e:
            print(f"Error while listening for messages: {e}")

    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()
    print(f"Listener thread started for {host_ip}:{port}.")
