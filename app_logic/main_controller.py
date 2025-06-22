# app_logic/main_controller.py
# This module will act as the main controller orchestrating
# interactions between the GUI, network, and cryptography parts.

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QObject, pyqtSlot, QThread, pyqtSignal

# Assuming other modules will be structured and importable
# from gui.gui_main_window import ChatGUI
# from network_core.tcp_handler import TCPServer, TCPClient # Simplified
# from security.diffie_hellman import DHExchange
# from security.session_crypto import SessionCipher # Assuming this will be created

# Placeholder for SessionCipher if not created yet
class SessionCipher:
    def __init__(self, key):
        self.key = key
        print(f"SessionCipher initialized with key: {key.hex() if key else None}")

    def encrypt(self, plaintext_bytes: bytes) -> bytes:
        if not self.key: return plaintext_bytes # No-op if key not set
        # Placeholder for actual encryption (e.g., Fernet)
        print(f"Encrypting (placeholder): {plaintext_bytes}")
        return b"encrypted_" + plaintext_bytes

    def decrypt(self, ciphertext_bytes: bytes) -> bytes:
        if not self.key: return ciphertext_bytes # No-op if key not set
        # Placeholder for actual decryption
        print(f"Decrypting (placeholder): {ciphertext_bytes}")
        if ciphertext_bytes.startswith(b"encrypted_"):
            return ciphertext_bytes[len(b"encrypted_"):]
        return ciphertext_bytes


# --- Network Worker (for handling server and client connections in a separate thread) ---
class NetworkHandler(QObject):
    message_received_signal = pyqtSignal(str, str) # peer_id, message
    connection_status_signal = pyqtSignal(str, str) # peer_id, status ("connected", "disconnected", "error")
    new_peer_signal = pyqtSignal(str) # peer_id (e.g. "host:port")

    # For DH Exchange
    # For simplicity, we'll handle DH within client/server connection logic for now
    # A more robust system might have explicit states/signals for DH steps

    def __init__(self, host_ip='0.0.0.0', listen_port=0):
        super().__init__()
        self.host_ip = host_ip
        self.listen_port = listen_port
        self.tcp_server = None
        self.clients = {} # Stores active TCPClient instances: peer_id -> {client: TCPClient, session_cipher: SessionCipher}
        self.dh_exchanges = {} # peer_id -> DHExchange
        self.server_thread = None

    def start_server(self, port_to_listen):
        self.listen_port = port_to_listen
        # The TCPServer from tcp_handler needs to be adapted or used carefully with threads
        # For now, let's assume TCPServer's on_new_client_callback is run in a thread by TCPServer itself
        # And that callback will be self.handle_new_server_connection

        # This part needs to be carefully designed.
        # The TCPServer in tcp_handler.py starts its own listening loop.
        # We need a way to integrate it with this QObject based handler.
        # For now, this is a conceptual placeholder.
        print(f"NetworkHandler: Attempting to start server on {self.host_ip}:{self.listen_port}")
        # self.tcp_server = TCPServer(self.host_ip, self.listen_port, self.handle_new_server_connection)
        # self.server_thread = threading.Thread(target=self.tcp_server.start, daemon=True)
        # self.server_thread.start()
        self.connection_status_signal.emit("SERVER", f"Server listening on {self.host_ip}:{self.listen_port} (Conceptual)")


    @pyqtSlot(object, tuple) # conn, addr
    def handle_new_server_connection(self, conn, addr):
        """Callback for TCPServer when a new client connects."""
        peer_id = f"{addr[0]}:{addr[1]}"
        print(f"NetworkHandler: New incoming connection from {peer_id}")
        self.new_peer_signal.emit(peer_id)
        self.connection_status_signal.emit(peer_id, "connected_inbound")

        # Simplified DH Exchange (Initiated by server side for incoming connection)
        # In a real scenario, one side (e.g. connector) initiates DH.
        dh = DHExchange()
        # For incoming, let's assume this side (server) dictates params for now.
        # This needs refinement: client should initiate or a protocol for who sends params first.
        # params_bytes, own_pub_key_bytes = dh.generate_parameters_and_keys()

        # conn.sendall(params_bytes) # Frame this!
        # conn.sendall(own_pub_key_bytes) # Frame this!
        # peer_pub_key_bytes = conn.recv(...) # Frame this!

        # shared_secret = dh.calculate_shared_secret(peer_pub_key_bytes)
        # if shared_secret:
        #     self.clients[peer_id] = {'socket': conn, 'session_cipher': SessionCipher(shared_secret)}
        #     self.dh_exchanges[peer_id] = dh
        #     self.connection_status_signal.emit(peer_id, "dh_complete")
        #     # Start listening loop for this client
        #     # client_listener_thread = threading.Thread(target=self.listen_to_client, args=(conn, peer_id), daemon=True)
        #     # client_listener_thread.start()
        # else:
        #     self.connection_status_signal.emit(peer_id, "dh_failed")
        #     conn.close()
        print(f"NetworkHandler: DH Exchange and client listening loop for {peer_id} (Conceptual - NOT IMPLEMENTED YET)")


    @pyqtSlot(str, str) # host, port
    def connect_to_peer(self, host, port_str):
        peer_id = f"{host}:{port_str}"
        try:
            port = int(port_str)
            if peer_id in self.clients and self.clients[peer_id].get('socket') and self.clients[peer_id]['socket'].connected:
                print(f"Already connected to {peer_id}")
                self.connection_status_signal.emit(peer_id, "already_connected")
                return

            print(f"NetworkHandler: Attempting to connect to {peer_id}")
            # client = TCPClient(host, port) # From tcp_handler
            # client_socket = client.connect() # This blocks, so should be in a thread if GUI is responsive

            # if client_socket:
            #     self.connection_status_signal.emit(peer_id, "connected_outbound")
            #     self.new_peer_signal.emit(peer_id)

            #     # Simplified DH Exchange (Initiated by connector)
            #     dh = DHExchange()
            #     # Peer A (connector) generates parameters and its key pair
            #     params_bytes, own_pub_key_bytes = dh.generate_parameters_and_keys()
            #     serialized_params = dh.get_parameters_bytes()

            #     client.send_data(serialized_params) # Assumes tcp_handler.send_data frames it
            #     client.send_data(own_pub_key_bytes)

            #     peer_pub_key_bytes = client.receive_data() # Assumes tcp_handler.receive_data unframes it
            #     if peer_pub_key_bytes:
            #         shared_secret = dh.calculate_shared_secret(peer_pub_key_bytes)
            #         if shared_secret:
            #             self.clients[peer_id] = {'client': client, 'session_cipher': SessionCipher(shared_secret)}
            #             self.dh_exchanges[peer_id] = dh
            #             self.connection_status_signal.emit(peer_id, "dh_complete")
            #             # Start listening loop for this client
            #             # client_listener_thread = threading.Thread(target=self.listen_to_client_outbound, args=(client, peer_id), daemon=True)
            #             # client_listener_thread.start()
            #         else:
            #             self.connection_status_signal.emit(peer_id, "dh_failed")
            #             client.close()
            #     else:
            #         self.connection_status_signal.emit(peer_id, "dh_no_peer_pubkey")
            #         client.close()
            # else:
            #     self.connection_status_signal.emit(peer_id, "connection_failed")
            print(f"NetworkHandler: Connection and DH for {peer_id} (Conceptual - NOT IMPLEMENTED YET)")

        except ValueError:
            self.connection_status_signal.emit(peer_id, "invalid_port")
        except Exception as e:
            self.connection_status_signal.emit(peer_id, f"error: {e}")


    @pyqtSlot(str, str) # peer_id, message
    def send_message(self, peer_id, message_text):
        if peer_id in self.clients:
            client_info = self.clients[peer_id]
            # tcp_client_or_socket = client_info.get('client') or client_info.get('socket')
            # session_cipher = client_info.get('session_cipher')

            # if tcp_client_or_socket and session_cipher:
            #     encrypted_message = session_cipher.encrypt(message_text.encode('utf-8'))
            #     if isinstance(tcp_client_or_socket, TCPClient): # Outbound connection
            #         success = tcp_client_or_socket.send_data(encrypted_message)
            #     else: # Inbound connection (raw socket)
            #         # Need framing for raw sockets
            #         msg_len_bytes = len(encrypted_message).to_bytes(4, 'big')
            #         tcp_client_or_socket.sendall(msg_len_bytes + encrypted_message)
            #         success = True # Assume success if no immediate error

            #     if success:
            #         print(f"Message sent to {peer_id}: {message_text}")
            #     else:
            #         print(f"Failed to send message to {peer_id}")
            #         self.connection_status_signal.emit(peer_id, "send_error")
            # else:
            #     print(f"No active connection or cipher for {peer_id} to send message.")
            #     self.connection_status_signal.emit(peer_id, "not_ready_to_send")
            print(f"NetworkHandler: Sending message to {peer_id}: '{message_text}' (Conceptual - NOT IMPLEMENTED YET)")

        else:
            print(f"Unknown peer_id {peer_id} for sending message.")

    # Placeholder for listening loops
    # def listen_to_client(self, conn_socket, peer_id): ...
    # def listen_to_client_outbound(self, tcp_client, peer_id): ...


class MainController(QObject):
    def __init__(self):
        super().__init__()
        self.gui = ChatGUI() # from gui.gui_main_window

        # Setup network handler in a separate thread to avoid blocking GUI
        self.network_thread = QThread()
        self.network_handler = NetworkHandler() # host_ip, listen_port can be set later
        self.network_handler.moveToThread(self.network_thread)

        # Connect signals from GUI to slots in NetworkHandler (via controller or directly)
        self.gui.send_message_signal.connect(self.network_handler.send_message) # Will need current_peer_id logic
        self.gui.connect_to_peer_signal.connect(self.network_handler.connect_to_peer)

        # Connect signals from NetworkHandler to slots in GUI (or controller to update GUI)
        self.network_handler.message_received_signal.connect(self.handle_incoming_message)
        self.network_handler.connection_status_signal.connect(self.handle_connection_status)
        self.network_handler.new_peer_signal.connect(self.handle_new_peer)

        # Start the network thread
        self.network_thread.start()

        # TODO: Get listening port from user via GUI or config
        # For now, conceptual start.
        # self.network_handler.start_server(12345) # Example port

        self.current_chat_peer_id = None # To know who "Me: message" is for

        self.gui.show()

    @pyqtSlot(str) # peer_id ("host:port")
    def handle_new_peer(self, peer_id):
        # This needs to be more robust, e.g. check if peer already in list
        self.gui.update_peer_list([peer_id]) # Simplistic update for now
        self.gui.append_message_to_display(f"System: New peer detected/connected: {peer_id}")

    @pyqtSlot(str, str) # peer_id, message
    def handle_incoming_message(self, peer_id, message):
        # If the message is from the currently active chat peer, display it
        # Or, if no chat is active, or if it's a new peer, perhaps highlight or notify
        self.gui.append_message_to_display(f"{peer_id}: {message}")

    @pyqtSlot(str, str) # peer_id, status
    def handle_connection_status(self, peer_id, status):
        self.gui.append_message_to_display(f"System Status ({peer_id}): {status}")

    def shutdown(self):
        print("Controller shutting down...")
        if self.network_handler and self.network_handler.tcp_server:
            self.network_handler.tcp_server.stop()
        self.network_thread.quit()
        self.network_thread.wait()
        print("Network thread finished.")


if __name__ == '__main__':
    # This basic main.py will be expanded significantly
    app = QApplication(sys.argv)

    # Load GUI and Controller
    # controller = MainController()

    # For now, just show the GUI standalone as controller is not fully wired
    gui = ChatGUI() # from gui.gui_main_window

    # --- Example: Simulate NetworkHandler signals to GUI for testing ---
    @pyqtSlot(str)
    def test_gui_send_message(message):
        gui.append_message_to_display(f"GUI Test (send_message_signal): '{message}' would be sent to current peer.")

    @pyqtSlot(str, str)
    def test_gui_connect_peer(host, port):
        gui.append_message_to_display(f"GUI Test (connect_to_peer_signal): Connect to {host}:{port}")
        # Simulate connection status and new peer
        gui.append_message_to_display(f"System Status ({host}:{port}): connected_outbound")
        gui.update_peer_list([f"{host}:{port} (Simulated)"]) # Example update

    gui.send_message_signal.connect(test_gui_send_message)
    gui.connect_to_peer_signal.connect(test_gui_connect_peer)

    # Simulate receiving a message
    # In real app, this would come from NetworkHandler via controller
    # gui.append_message_to_display("PeerX: Hello from simulated peer!")

    gui.show()

    exit_code = app.exec_()
    # controller.shutdown() # If controller was used
    sys.exit(exit_code)
