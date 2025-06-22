# main.py
# CLI Tester for Core P2P Secure Functionality (TCP, DH Key Exchange, Session Encryption)

import sys
import threading
import time

from network_core.tcp_handler import TCPClient, TCPServer
from security.diffie_hellman import DHExchange
from security.session_crypto import SessionCipher

# --- Configuration ---
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 12345

# --- Helper Functions for Network Data ---
# These helpers ensure that DH parameters and public keys are sent/received correctly over TCP.
# We need a simple protocol: send type of data (e.g., "DH_PARAMS", "DH_PUBKEY") then the data itself.
# Or, more simply, assume a sequence: params, then pubkey.
# For this test, we'll assume a fixed sequence for DH exchange.

def send_framed_data(sock_or_client, data: bytes):
    """Sends length-prefixed data using TCPClient's send_data or a raw socket."""
    if isinstance(sock_or_client, TCPClient):
        return sock_or_client.send_data(data)
    else: # Raw socket
        msg_len = len(data).to_bytes(4, 'big')
        try:
            sock_or_client.sendall(msg_len + data)
            return True
        except Exception as e:
            print(f"Error sending raw framed data: {e}")
            return False


def receive_framed_data(sock_or_client):
    """Receives length-prefixed data using TCPClient's receive_data or a raw socket."""
    if isinstance(sock_or_client, TCPClient):
        return sock_or_client.receive_data()
    else: # Raw socket
        try:
            raw_msglen = sock_or_client.recv(4)
            if not raw_msglen: return None
            msglen = int.from_bytes(raw_msglen, 'big')

            data = bytearray()
            while len(data) < msglen:
                packet = sock_or_client.recv(msglen - len(data))
                if not packet: return None
                data.extend(packet)
            return bytes(data)
        except Exception as e:
            print(f"Error receiving raw framed data: {e}")
            return None

# --- Server Role ---
def run_server_logic(conn, addr, session_cipher_ref):
    peer_id = f"{addr[0]}:{addr[1]}"
    print(f"[Server] Handling connection from {peer_id}")

    # 1. DH Exchange (Server is responder)
    print("[Server] Starting DH Exchange...")
    dh_responder = DHExchange()

    # Receive parameters from client
    print("[Server] Waiting for DH parameters from client...")
    params_bytes = receive_framed_data(conn)
    if not params_bytes:
        print("[Server] Failed to receive DH parameters. Closing.")
        conn.close()
        return

    # Receive client's public key
    print("[Server] Waiting for client's public key...")
    client_pub_key_bytes = receive_framed_data(conn)
    if not client_pub_key_bytes:
        print("[Server] Failed to receive client's public key. Closing.")
        conn.close()
        return

    print("[Server] Received DH parameters and client public key.")

    # Generate own keys using client's parameters
    own_pub_key_bytes = dh_responder.generate_keys_with_parameters(params_bytes)
    if not own_pub_key_bytes:
        print("[Server] Failed to generate keys with client's parameters. Closing.")
        conn.close()
        return

    # Send own public key to client
    print("[Server] Sending own public key to client...")
    if not send_framed_data(conn, own_pub_key_bytes):
        print("[Server] Failed to send own public key. Closing.")
        conn.close()
        return

    # Calculate shared secret
    shared_secret = dh_responder.calculate_shared_secret(client_pub_key_bytes)
    if not shared_secret:
        print("[Server] Failed to calculate shared secret. Closing.")
        conn.close()
        return

    print(f"[Server] DH Exchange complete. Shared secret derived (first 5 bytes): {shared_secret[:5].hex()}...")
    session_cipher_ref[0] = SessionCipher(shared_secret)

    # 2. Encrypted Chat
    print("[Server] Ready for encrypted chat.")
    try:
        for i in range(3): # Exchange a few messages
            encrypted_msg = receive_framed_data(conn)
            if not encrypted_msg:
                print("[Server] Connection closed by client during chat.")
                break

            decrypted_msg_bytes = session_cipher_ref[0].decrypt(encrypted_msg)
            if not decrypted_msg_bytes:
                print("[Server] Failed to decrypt message. Terminating.")
                break
            print(f"[Server] Received & Decrypted: '{decrypted_msg_bytes.decode()}'")

            reply = f"Server acknowledges message {i+1}: '{decrypted_msg_bytes.decode()}'"
            encrypted_reply = session_cipher_ref[0].encrypt(reply.encode())
            if not send_framed_data(conn, encrypted_reply):
                print("[Server] Failed to send encrypted reply.")
                break
            print(f"[Server] Sent encrypted reply: '{reply}'")
            time.sleep(0.1) # Small delay

    except Exception as e:
        print(f"[Server] Error during chat: {e}")
    finally:
        print(f"[Server] Closing connection with {peer_id}.")
        conn.close()


def start_server_role(host, port):
    print(f"Starting Server Role on {host}:{port}")
    # Using a list to pass session_cipher by reference to the handler,
    # as the handler runs in a new thread created by TCPServer.
    # This is a bit of a hack for this test script.
    # In the full app, MainController would manage ciphers.
    session_cipher_container = [None]

    def server_connection_handler(conn, addr):
        # This function is the callback for TCPServer.
        # It runs in a thread managed by TCPServer.
        run_server_logic(conn, addr, session_cipher_container)

    tcp_server = TCPServer(host, port, server_connection_handler)

    try:
        # TCPServer.start() is blocking, so run it in a thread if we want this function to return
        # For this CLI test, blocking is fine for the main server role.
        tcp_server.start()
    except KeyboardInterrupt:
        print("[Server] Shutdown requested.")
    finally:
        print("[Server] Stopping server...")
        tcp_server.stop() # Ensure server stops cleanly


# --- Client Role ---
def start_client_role(host, port):
    print(f"Starting Client Role, connecting to {host}:{port}")
    tcp_client = TCPClient(host, port)
    client_socket_conn_obj = tcp_client.connect() # client_socket_conn_obj is the socket

    if not client_socket_conn_obj or not tcp_client.connected:
        print("[Client] Could not connect to server.")
        return

    session_cipher = None
    try:
        # 1. DH Exchange (Client is initiator)
        print("[Client] Starting DH Exchange...")
        dh_initiator = DHExchange()

        # Generate parameters and own keys
        params, own_pub_key_bytes = dh_initiator.generate_parameters_and_keys()
        params_bytes = dh_initiator.get_parameters_bytes() # Get serialized params

        # Send parameters to server
        print("[Client] Sending DH parameters to server...")
        if not send_framed_data(tcp_client, params_bytes): # Use tcp_client instance
            print("[Client] Failed to send DH parameters. Closing.")
            return

        # Send own public key to server
        print("[Client] Sending own public key to server...")
        if not send_framed_data(tcp_client, own_pub_key_bytes):
            print("[Client] Failed to send own public key. Closing.")
            return

        # Receive server's public key
        print("[Client] Waiting for server's public key...")
        server_pub_key_bytes = receive_framed_data(tcp_client)
        if not server_pub_key_bytes:
            print("[Client] Failed to receive server's public key. Closing.")
            return
        print("[Client] Received server's public key.")

        # Calculate shared secret
        shared_secret = dh_initiator.calculate_shared_secret(server_pub_key_bytes)
        if not shared_secret:
            print("[Client] Failed to calculate shared secret. Closing.")
            return

        print(f"[Client] DH Exchange complete. Shared secret derived (first 5 bytes): {shared_secret[:5].hex()}...")
        session_cipher = SessionCipher(shared_secret)

        # 2. Encrypted Chat
        print("[Client] Ready for encrypted chat.")
        for i in range(3): # Exchange a few messages
            message_to_send = f"Hello from Client - message {i+1}"
            encrypted_message = session_cipher.encrypt(message_to_send.encode())

            if not send_framed_data(tcp_client, encrypted_message):
                print("[Client] Failed to send encrypted message.")
                break
            print(f"[Client] Sent encrypted message: '{message_to_send}'")

            encrypted_reply = receive_framed_data(tcp_client)
            if not encrypted_reply:
                print("[Client] Connection closed by server during chat.")
                break

            decrypted_reply_bytes = session_cipher.decrypt(encrypted_reply)
            if not decrypted_reply_bytes:
                print("[Client] Failed to decrypt reply. Terminating.")
                break
            print(f"[Client] Received & Decrypted reply: '{decrypted_reply_bytes.decode()}'")
            time.sleep(0.1)

    except Exception as e:
        print(f"[Client] Error during operation: {e}")
    finally:
        print("[Client] Closing connection.")
        tcp_client.close()


# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <server|client> [host] [port]")
        print(f"Example (server): python main.py server")
        print(f"Example (client): python main.py client {DEFAULT_HOST} {DEFAULT_PORT}")
        sys.exit(1)

    role = sys.argv[1].lower()
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    try:
        port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
        if not (1024 <= port <= 65535):
            raise ValueError("Port out of range")
    except ValueError:
        print(f"Invalid port. Using default port {DEFAULT_PORT}.")
        port = DEFAULT_PORT


    if role == "server":
        start_server_role(host, port)
    elif role == "client":
        # For client, if it's connecting to a server on the same machine (e.g. DEFAULT_HOST),
        # the host and port arguments for client mode should be those of the server.
        server_host_for_client = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
        try:
            server_port_for_client = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
        except IndexError: # if only 'client' is given, use defaults for server.
             server_port_for_client = DEFAULT_PORT
        except ValueError:
            print(f"Invalid port for client to connect to. Using default {DEFAULT_PORT}")
            server_port_for_client = DEFAULT_PORT

        start_client_role(server_host_for_client, server_port_for_client)
    else:
        print(f"Unknown role: {role}. Use 'server' or 'client'.")
        sys.exit(1)

    print("CLI Tester finished.")
