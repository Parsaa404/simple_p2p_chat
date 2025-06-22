# network_core/tcp_handler.py
# This module will handle TCP connections, sending and receiving data.

import socket
import threading

class TCPServer:
    def __init__(self, host, port, on_new_client_callback):
        self.host = host
        self.port = port
        self.on_new_client_callback = on_new_client_callback
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(5) # Allow up to 5 queued connections
        self.running = True
        print(f"TCP Server listening on {self.host}:{self.port}")

        while self.running:
            try:
                conn, addr = self.sock.accept()
                if not self.running: # Check again in case server was stopped while accept() was blocking
                    conn.close()
                    break
                print(f"Accepted connection from {addr}")
                # Pass the connection and address to the callback
                # The callback should handle this client in a new thread or manage it appropriately
                client_thread = threading.Thread(target=self.on_new_client_callback, args=(conn, addr), daemon=True)
                client_thread.start()
            except socket.error as e:
                if self.running: # Only print error if server was supposed to be running
                    print(f"Socket error in TCPServer: {e}")
                break # Exit loop on socket error (e.g. socket closed)
        print("TCP Server stopped.")

    def stop(self):
        self.running = False
        # To unblock self.sock.accept(), we can connect to it briefly
        try:
            # Create a dummy connection to unblock accept()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
        except socket.error:
            pass # This is expected if the server socket is already closing
        finally:
            if self.sock:
                self.sock.close()
                print("Server socket closed.")


class TCPClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.connected = False

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.connected = True
            print(f"Successfully connected to {self.host}:{self.port}")
            return self.sock # Return the socket for the caller to use
        except socket.error as e:
            print(f"Failed to connect to {self.host}:{self.port}. Error: {e}")
            self.sock = None
            self.connected = False
            return None

    def send_data(self, data: bytes):
        if not self.connected or not self.sock:
            print("Not connected. Cannot send data.")
            return False
        try:
            # Simple framing: send length of message (4 bytes) then message
            message_len = len(data).to_bytes(4, 'big')
            self.sock.sendall(message_len + data)
            return True
        except socket.error as e:
            print(f"Error sending data: {e}")
            self.connected = False # Assume connection is lost
            self.close()
            return False

    def receive_data(self):
        if not self.connected or not self.sock:
            print("Not connected. Cannot receive data.")
            return None
        try:
            # Read message length (4 bytes)
            raw_msglen = self._recv_all(4)
            if not raw_msglen:
                return None # Connection closed or error
            msglen = int.from_bytes(raw_msglen, 'big')
            # Read the message data
            return self._recv_all(msglen)
        except socket.error as e:
            print(f"Error receiving data: {e}")
            self.connected = False # Assume connection is lost
            self.close()
            return None
        except Exception as e: # Catch other errors like struct.error
            print(f"General error receiving data: {e}")
            self.connected = False
            self.close()
            return None

    def _recv_all(self, n):
        # Helper function to receive n bytes or return None if EOF is hit
        data = bytearray()
        while len(data) < n:
            if not self.sock: return None
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None # Connection closed
            data.extend(packet)
        return bytes(data)

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass # Ignore errors on shutdown, socket might already be closed
            finally:
                self.sock.close()
                self.sock = None
        self.connected = False
        print("Client connection closed.")

if __name__ == '__main__':
    # Example Usage (for testing this module directly)

    MY_HOST = '127.0.0.1'
    MY_PORT_SERVER = 12345
    MY_PORT_CLIENT_LISTEN = 12346 # For a second server instance

    def handle_client_connection(conn, addr):
        print(f"Handling connection from {addr}")
        try:
            # In a real app, this would involve DH key exchange first
            # For now, just receive and echo
            while True:
                # Read message length (4 bytes)
                raw_msglen = conn.recv(4)
                if not raw_msglen:
                    print(f"Connection from {addr} closed (no msglen).")
                    break
                msglen = int.from_bytes(raw_msglen, 'big')
                # Read the message data
                data = conn.recv(msglen)
                if not data:
                    print(f"Connection from {addr} closed (no data).")
                    break

                print(f"Server received from {addr}: {data.decode('utf-8')}")

                # Echo back
                response = f"Server received: {data.decode('utf-8')}".encode('utf-8')
                response_len = len(response).to_bytes(4, 'big')
                conn.sendall(response_len + response)
                print(f"Server echoed to {addr}")

                if data.decode('utf-8').lower() == 'exit':
                    print(f"Client {addr} requested exit.")
                    break
        except socket.error as e:
            print(f"Socket error with client {addr}: {e}")
        except Exception as e:
            print(f"Error with client {addr}: {e}")
        finally:
            print(f"Closing connection with {addr}")
            conn.close()

    # Start a server instance
    server = TCPServer(MY_HOST, MY_PORT_SERVER, handle_client_connection)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()

    import time
    time.sleep(1) # Give server a moment to start

    # Client 1 connects to server
    client1 = TCPClient(MY_HOST, MY_PORT_SERVER)
    client1_socket = client1.connect()

    if client1_socket:
        client1.send_data("Hello from Client 1".encode('utf-8'))
        response1 = client1.receive_data()
        if response1:
            print(f"Client 1 received: {response1.decode('utf-8')}")

        client1.send_data("exit".encode('utf-8')) # Tell server to close this connection
        response_exit = client1.receive_data()
        if response_exit:
             print(f"Client 1 received on exit: {response_exit.decode('utf-8')}")
        client1.close()

    print("\n--- Test with two server instances (client connects to the other server) ---")
    # Start a second server instance (acting as the "client" peer's server side)
    server2 = TCPServer(MY_HOST, MY_PORT_CLIENT_LISTEN, handle_client_connection)
    server2_thread = threading.Thread(target=server2.start, daemon=True)
    server2_thread.start()
    time.sleep(1)

    # Client 2 (from first program instance) connects to server2
    client2 = TCPClient(MY_HOST, MY_PORT_CLIENT_LISTEN)
    client2_socket = client2.connect()

    if client2_socket:
        client2.send_data("Hello from Client 2 to Server 2".encode('utf-8'))
        response2 = client2.receive_data()
        if response2:
            print(f"Client 2 received: {response2.decode('utf-8')}")
        client2.send_data("exit".encode('utf-8'))
        response_exit2 = client2.receive_data()
        if response_exit2:
            print(f"Client 2 received on exit: {response_exit2.decode('utf-8')}")
        client2.close()


    print("\nStopping servers...")
    server.stop()
    server2.stop()
    # server_thread.join(timeout=2) # Wait for server thread to finish
    # server2_thread.join(timeout=2)
    print("Test finished.")
