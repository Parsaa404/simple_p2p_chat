import sys
import threading # For listener threads per connection
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QObject, pyqtSlot, QThread, pyqtSignal, QMetaObject, Qt

from gui.gui_main_window import ChatGUI
from network_core.tcp_handler import TCPServer, TCPClient
from security.diffie_hellman import DHExchange
from security.session_crypto import SessionCipher

# Helper functions from main.py (CLI tester) - might move to a common utils module
def send_framed_data(sock_or_client, data: bytes):
    if isinstance(sock_or_client, TCPClient):
        return sock_or_client.send_data(data)
    else:
        msg_len = len(data).to_bytes(4, 'big')
        try:
            sock_or_client.sendall(msg_len + data)
            return True
        except Exception: return False

def receive_framed_data(sock_or_client):
    if isinstance(sock_or_client, TCPClient):
        return sock_or_client.receive_data()
    else:
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
        except Exception: return None


class NetworkWorker(QObject):
    message_received_signal = pyqtSignal(str, str)  # peer_id, message_text
    connection_status_signal = pyqtSignal(str, str, str)  # peer_id, type ("info", "error", "success"), message
    new_peer_connected_signal = pyqtSignal(str)  # peer_id (e.g., "host:port")
    server_status_signal = pyqtSignal(str, bool) # message, is_error (True if error, False if success/info)

    def __init__(self, host_ip='0.0.0.0'):
        super().__init__()
        self.host_ip = host_ip
        self.listen_port = 0
        self.tcp_server = None
        self.server_running_flag = threading.Event() # To signal TCPServer's loop to stop

        # peer_id -> {"socket": sock, "client_obj": TCPClient_obj, "cipher": SessionCipher, "listener_thread": Thread}
        self.active_connections = {}
        self.connections_lock = threading.Lock() # To protect access to active_connections

    @pyqtSlot(int)
    def start_server_slot(self, port: int):
        self.listen_port = port
        if self.tcp_server and self.server_running_flag.is_set():
            self.server_status_signal.emit(f"Server already running on {self.host_ip}:{self.listen_port}", True)
            return

        self.server_running_flag.set() # Signal that server should be running
        self.tcp_server = TCPServer(self.host_ip, self.listen_port, self._handle_new_server_connection)

        # TCPServer.start() is blocking, run it in its own thread
        # This thread is for the server's main listening loop (accepting new connections)
        server_loop_thread = threading.Thread(target=self.tcp_server.start, daemon=True)
        server_loop_thread.start()

        # Check if server started successfully (e.g. port not in use)
        # This is a bit tricky as TCPServer.start() blocks.
        # A robust way is for TCPServer to emit a signal or use a callback on successful bind.
        # For now, assume it starts if no immediate exception.
        # TCPServer's print statement will indicate listening.
        self.server_status_signal.emit(f"Server started, listening on {self.host_ip}:{self.listen_port}", False)


    def _handle_new_server_connection(self, connection_socket, client_address):
        """Callback for TCPServer, runs in a thread created by TCPServer."""
        peer_id = f"{client_address[0]}:{client_address[1]}"
        self.connection_status_signal.emit(peer_id, "info", f"Incoming connection from {peer_id}. Starting DH exchange...")

        dh_responder = DHExchange()
        try:
            # DH Responder Logic
            params_bytes = receive_framed_data(connection_socket)
            if not params_bytes: raise Exception("Failed to receive DH parameters.")
            self.connection_status_signal.emit(peer_id, "info", "Received DH parameters.")

            client_pub_key_bytes = receive_framed_data(connection_socket)
            if not client_pub_key_bytes: raise Exception("Failed to receive client public key.")
            self.connection_status_signal.emit(peer_id, "info", "Received client public key.")

            own_pub_key_bytes = dh_responder.generate_keys_with_parameters(params_bytes)
            if not own_pub_key_bytes: raise Exception("Failed to generate DH keys with client parameters.")

            if not send_framed_data(connection_socket, own_pub_key_bytes):
                raise Exception("Failed to send own public key.")
            self.connection_status_signal.emit(peer_id, "info", "Sent own public key.")

            shared_secret = dh_responder.calculate_shared_secret(client_pub_key_bytes)
            if not shared_secret: raise Exception("Failed to calculate shared secret.")

            session_cipher = SessionCipher(shared_secret)
            self.connection_status_signal.emit(peer_id, "success", f"DH Exchange with {peer_id} complete.")

            with self.connections_lock:
                listener_thread = threading.Thread(target=self._listen_on_connection,
                                                   args=(connection_socket, peer_id, session_cipher), daemon=True)
                self.active_connections[peer_id] = {
                    "socket": connection_socket, "cipher": session_cipher,
                    "listener_thread": listener_thread, "client_obj": None
                }
            listener_thread.start()
            self.new_peer_connected_signal.emit(peer_id)

        except Exception as e:
            self.connection_status_signal.emit(peer_id, "error", f"DH Exchange failed with {peer_id}: {e}")
            connection_socket.close()


    @pyqtSlot(str, str) # host, port_str
    def connect_to_peer_slot(self, host: str, port_str: str):
        peer_id = f"{host}:{port_str}"
        try:
            port = int(port_str)
            with self.connections_lock:
                if peer_id in self.active_connections:
                    self.connection_status_signal.emit(peer_id, "info", f"Already connected or connecting to {peer_id}.")
                    return

            self.connection_status_signal.emit(peer_id, "info", f"Attempting to connect to {peer_id}...")
            tcp_client = TCPClient(host, port)
            client_socket = tcp_client.connect() # This is blocking.

            if not client_socket or not tcp_client.connected:
                raise ConnectionError(f"Failed to connect to {peer_id}.")

            self.connection_status_signal.emit(peer_id, "info", f"TCP connected to {peer_id}. Starting DH exchange...")

            # DH Initiator Logic
            dh_initiator = DHExchange()
            params, own_pub_key_bytes = dh_initiator.generate_parameters_and_keys()
            params_bytes_to_send = dh_initiator.get_parameters_bytes()

            if not send_framed_data(tcp_client, params_bytes_to_send):
                raise Exception("Failed to send DH parameters.")
            self.connection_status_signal.emit(peer_id, "info", "Sent DH parameters.")

            if not send_framed_data(tcp_client, own_pub_key_bytes):
                raise Exception("Failed to send own public key.")
            self.connection_status_signal.emit(peer_id, "info", "Sent own public key.")

            server_pub_key_bytes = receive_framed_data(tcp_client)
            if not server_pub_key_bytes: raise Exception("Failed to receive server public key.")
            self.connection_status_signal.emit(peer_id, "info", "Received server public key.")

            shared_secret = dh_initiator.calculate_shared_secret(server_pub_key_bytes)
            if not shared_secret: raise Exception("Failed to calculate shared secret.")

            session_cipher = SessionCipher(shared_secret)
            self.connection_status_signal.emit(peer_id, "success", f"DH Exchange with {peer_id} complete.")

            with self.connections_lock:
                listener_thread = threading.Thread(target=self._listen_on_connection,
                                                   args=(tcp_client, peer_id, session_cipher), daemon=True)
                self.active_connections[peer_id] = {
                    "socket": None, "client_obj": tcp_client, "cipher": session_cipher,
                    "listener_thread": listener_thread
                }
            listener_thread.start()
            self.new_peer_connected_signal.emit(peer_id)

        except ValueError:
            self.connection_status_signal.emit(peer_id, "error", "Invalid port number.")
        except ConnectionError as ce:
             self.connection_status_signal.emit(peer_id, "error", str(ce))
        except Exception as e:
            self.connection_status_signal.emit(peer_id, "error", f"Connection or DH failed with {peer_id}: {e}")
            if 'tcp_client' in locals() and tcp_client:
                tcp_client.close()


    def _listen_on_connection(self, conn_obj, peer_id: str, session_cipher: SessionCipher):
        """Listens for messages on an active connection (either TCPClient or raw socket)."""
        is_client_obj = isinstance(conn_obj, TCPClient)
        source_name = "TCPClient" if is_client_obj else "socket"
        # print(f"DEBUG: Listener started for {peer_id} on {source_name}")
        try:
            while True: # self.server_running_flag.is_set(): # Check a flag if worker is shutting down
                encrypted_data = receive_framed_data(conn_obj)
                if not encrypted_data:
                    self.connection_status_signal.emit(peer_id, "info", f"Connection closed by {peer_id}.")
                    break

                decrypted_bytes = session_cipher.decrypt(encrypted_data)
                if not decrypted_bytes: # Decryption failed
                    self.connection_status_signal.emit(peer_id, "error", "Failed to decrypt message. Possible key mismatch or data corruption.")
                    # Decide if to break or continue. For now, continue.
                    continue

                self.message_received_signal.emit(peer_id, decrypted_bytes.decode('utf-8', errors='replace'))

        except Exception as e:
            self.connection_status_signal.emit(peer_id, "error", f"Error listening to {peer_id}: {e}")
        finally:
            # print(f"DEBUG: Listener stopped for {peer_id}")
            self.cleanup_connection(peer_id)


    @pyqtSlot(str, str) # peer_id, message_text
    def send_message_to_peer_slot(self, peer_id: str, message_text: str):
        with self.connections_lock:
            conn_info = self.active_connections.get(peer_id)

        if not conn_info:
            self.connection_status_signal.emit(peer_id, "error", f"Not connected to {peer_id}.")
            return

        cipher = conn_info["cipher"]
        conn_obj = conn_info["client_obj"] or conn_info["socket"] # TCPClient or raw socket

        if not cipher or not conn_obj:
            self.connection_status_signal.emit(peer_id, "error", f"Connection or cipher missing for {peer_id}.")
            return

        try:
            encrypted_message = cipher.encrypt(message_text.encode('utf-8'))
            if not encrypted_message:
                raise Exception("Encryption failed (returned empty).")

            if not send_framed_data(conn_obj, encrypted_message):
                raise Exception("Failed to send data via socket/client.")
            # self.message_received_signal.emit("Me", f"To {peer_id}: {message_text}") # Display own sent message
        except Exception as e:
            self.connection_status_signal.emit(peer_id, "error", f"Failed to send message to {peer_id}: {e}")
            self.cleanup_connection(peer_id) # Assume connection is problematic


    def cleanup_connection(self, peer_id: str):
        with self.connections_lock:
            conn_info = self.active_connections.pop(peer_id, None)

        if conn_info:
            if conn_info["client_obj"]:
                conn_info["client_obj"].close()
            elif conn_info["socket"]:
                try: conn_info["socket"].shutdown(socket.SHUT_RDWR)
                except: pass
                conn_info["socket"].close()

            # listener_thread = conn_info.get("listener_thread")
            # if listener_thread and listener_thread.is_alive():
            #     pass # Daemon threads will exit. If not daemon, would need join with timeout.
            self.connection_status_signal.emit(peer_id, "info", f"Cleaned up connection for {peer_id}.")
            # Optionally, notify GUI to remove peer from active list if not handled by connection_status
            # self.peer_disconnected_signal.emit(peer_id)


    @pyqtSlot()
    def stop_network_worker_slot(self):
        self.server_status_signal.emit("Network worker stopping...", False)
        self.server_running_flag.clear() # Signal TCPServer loop to stop (if it checks)
        if self.tcp_server:
            self.tcp_server.stop() # This should unblock accept and close server socket
            self.tcp_server = None

        with self.connections_lock:
            peer_ids = list(self.active_connections.keys()) # Iterate over a copy
        for peer_id in peer_ids:
            self.cleanup_connection(peer_id)

        self.server_status_signal.emit("Network worker stopped.", False)
        self.thread().quit() # Quit the QThread this worker lives in


class MainController(QObject):
    def __init__(self):
        super().__init__()
        self.gui = ChatGUI()
        self.current_chat_peer_id = None
        self.known_peers = set()

        self.network_thread = QThread(self) # Parent to QThread
        self.network_worker = NetworkWorker()
        self.network_worker.moveToThread(self.network_thread)

        # --- Connect GUI signals to Controller slots ---
        self.gui.send_message_signal.connect(self.on_gui_send_message)
        self.gui.connect_to_peer_signal.connect(self.on_gui_connect_to_peer)
        self.gui.peer_selection_changed_signal.connect(self.on_gui_peer_selection_changed)
        self.gui.start_server_requested_signal.connect(self.on_gui_start_server_requested)
        self.gui.destroyed.connect(self.on_gui_destroyed) # For proper shutdown

        # --- Connect Worker signals to Controller slots ---
        self.network_worker.message_received_signal.connect(self.on_worker_message_received)
        self.network_worker.connection_status_signal.connect(self.on_worker_connection_status)
        self.network_worker.new_peer_connected_signal.connect(self.on_worker_new_peer_connected)
        self.network_worker.server_status_signal.connect(self.on_worker_server_status)

        # --- Controller signals to Worker slots (queued connection) ---
        # These ensure calls to network_worker methods happen in the network_thread
        self.start_server_trigger = pyqtSignal(int)
        self.connect_to_peer_trigger = pyqtSignal(str, str)
        self.send_message_trigger = pyqtSignal(str, str)
        self.stop_worker_trigger = pyqtSignal()

        self.start_server_trigger.connect(self.network_worker.start_server_slot)
        self.connect_to_peer_trigger.connect(self.network_worker.connect_to_peer_slot)
        self.send_message_trigger.connect(self.network_worker.send_message_to_peer_slot)
        self.stop_worker_trigger.connect(self.network_worker.stop_network_worker_slot, Qt.BlockingQueuedConnection) # Ensure it runs before thread quits

        self.network_thread.start()
        self.gui.show()
        self.gui.set_status_bar_message("Application started. Please start listening or connect.", 0)

    @pyqtSlot(str)
    def on_gui_send_message(self, message_text: str):
        if self.current_chat_peer_id:
            self.send_message_trigger.emit(self.current_chat_peer_id, message_text)
            # GUI already displays "Me: message"
        else:
            self.gui.set_status_bar_message("Error: No peer selected to send message.", 5000)

    @pyqtSlot(str, str)
    def on_gui_connect_to_peer(self, host: str, port_str: str):
        self.connect_to_peer_trigger.emit(host, port_str)

    @pyqtSlot(str)
    def on_gui_peer_selection_changed(self, peer_id: str):
        self.current_chat_peer_id = peer_id if peer_id else None
        # GUI handles updating its display for selected peer (e.g., clearing chat history area)

    @pyqtSlot(int)
    def on_gui_start_server_requested(self, port: int):
        self.start_server_trigger.emit(port)

    @pyqtSlot(str, str) # peer_id, message_text
    def on_worker_message_received(self, peer_id: str, message_text: str):
        # TODO: Handle multi-chat window logic if peer_id != self.current_chat_peer_id
        # For now, just display if it's the current chat, or always display with peer_id
        if self.current_chat_peer_id == peer_id:
            self.gui.update_chat_display(f"{peer_id}: {message_text}")
        else:
            # If chat is not active, could show a notification or just log
            self.gui.update_chat_display(f"({peer_id}) {peer_id}: {message_text}")
            self.gui.set_status_bar_message(f"New message from {peer_id}", 3000)


    @pyqtSlot(str, str, str) # peer_id, type, message
    def on_worker_connection_status(self, peer_id: str, type: str, message: str):
        formatted_status = f"[{type.upper()}] {peer_id}: {message}"
        self.gui.update_chat_display(f"System: {formatted_status}")
        if type == "error":
            self.gui.set_status_bar_message(f"Error with {peer_id}", 5000)
        elif type == "success":
             self.gui.set_status_bar_message(f"{peer_id} action successful.", 3000)


    @pyqtSlot(str) # peer_id
    def on_worker_new_peer_connected(self, peer_id: str):
        self.known_peers.add(peer_id)
        self.gui.update_peer_list_gui(list(self.known_peers))
        # Optionally auto-select the new peer if no peer is currently selected
        if not self.current_chat_peer_id:
             items = self.gui.peer_list_widget.findItems(peer_id, Qt.MatchExactly)
             if items:
                 self.gui.peer_list_widget.setCurrentItem(items[0]) # This will trigger on_gui_peer_selection_changed


    @pyqtSlot(str, bool) # message, is_error
    def on_worker_server_status(self, message: str, is_error: bool):
        self.gui.update_chat_display(f"Server System: {message}")
        self.gui.set_status_bar_message(message, 5000 if is_error else 3000)
        if not is_error: # Server started successfully
            self.gui.start_server_action.setEnabled(False) # Disable if server is running
            self.gui.setWindowTitle(f"P2P Secure Messenger (Listening on {self.network_worker.listen_port})")
        # If error, start_server_action remains enabled or could be re-enabled.

    @pyqtSlot()
    def on_gui_destroyed(self):
        print("GUI is being destroyed, shutting down network worker...")
        self.shutdown()

    def shutdown(self):
        print("MainController shutdown initiated.")
        # Signal the worker to stop. Use BlockingQueuedConnection if call must complete before thread exits.
        QMetaObject.invokeMethod(self.network_worker, "stop_network_worker_slot", Qt.QueuedConnection)
        # self.stop_worker_trigger.emit() # This is also fine if stop_network_worker_slot quits the thread

        self.network_thread.quit()
        if not self.network_thread.wait(5000): # Wait up to 5 seconds
            print("Network thread did not terminate gracefully, forcing termination.")
            self.network_thread.terminate()
            self.network_thread.wait() # Wait again after terminate
        print("MainController shutdown complete.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    controller = MainController()
    exit_code = app.exec_()
    # Controller shutdown is now tied to GUI destruction or can be called explicitly if needed
    # controller.shutdown() # This might be redundant if on_gui_destroyed works as expected
    sys.exit(exit_code)

# Note: The placeholder SessionCipher from the original file was removed as we have a real one.
# Ensure all imports for TCPServer, TCPClient, DHExchange, SessionCipher are correct.
# The `send_framed_data` and `receive_framed_data` helpers are now part of this file.
# A proper import structure (e.g. from .network_core.tcp_handler import ...) is assumed if files are in packages.
# For current flat structure, direct imports are used.
# Socket import might be needed in NetworkWorker if not handled by tcp_handler's close methods.
import socket # Added for socket.SHUT_RDWR in cleanup_connection
