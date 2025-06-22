# gui/gui_main_window.py
# This module will contain the main GUI window for the application.

import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QTextEdit, QLineEdit, QPushButton, QListWidget,
                             QMenuBar, QAction, QSplitter, QStatusBar, QMessageBox, QInputDialog) # Added QStatusBar, QMessageBox, QInputDialog
from PyQt5.QtCore import Qt, pyqtSignal, QObject, pyqtSlot # Added pyqtSlot

class ChatGUI(QMainWindow):
    # Signal to emit when a message is to be sent from the GUI
    # The signal will carry the message string. Controller will know the current peer.
    send_message_signal = pyqtSignal(str)

    # Signal to request connection to a peer
    # The signal will carry host and port strings
    connect_to_peer_signal = pyqtSignal(str, str)

    # Signal to indicate a peer has been selected from the list
    # Carries peer_id (e.g., "host:port")
    peer_selection_changed_signal = pyqtSignal(str)

    # Signal to request starting the server
    start_server_requested_signal = pyqtSignal(int) # Carries the port number

    def __init__(self):
        super().__init__()
        self.setWindowTitle("P2P Secure Messenger")
        self.setGeometry(100, 100, 800, 600)
        self.current_chat_peer_id = None # To store the ID of the currently selected peer
        self.init_ui()

    def init_ui(self):
        # --- Menu Bar ---
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File')

        connect_action = QAction('&Connect to Peer...', self)
        connect_action.triggered.connect(self.show_connect_dialog)
        file_menu.addAction(connect_action)

        # Placeholder for starting server listening
        self.start_server_action = QAction('Start &Listening...', self)
        self.start_server_action.triggered.connect(self.show_start_server_dialog) # Placeholder for now
        file_menu.addAction(self.start_server_action)

        file_menu.addSeparator()
        exit_action = QAction('&Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menubar.addMenu('&Help')
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # --- Central Widget & Layout ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        splitter = QSplitter(Qt.Horizontal)

        # --- Peer List (Left Pane) ---
        self.peer_list_widget = QListWidget()
        self.peer_list_widget.setMaximumWidth(250)
        self.peer_list_widget.currentItemChanged.connect(self.peer_selected_in_list)
        splitter.addWidget(self.peer_list_widget)

        # --- Chat Area (Right Pane) ---
        chat_area_widget = QWidget()
        chat_layout = QVBoxLayout(chat_area_widget)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        chat_layout.addWidget(self.chat_display)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here and press Enter...")
        self.message_input.returnPressed.connect(self.send_message_from_gui)
        chat_layout.addWidget(self.message_input)

        send_button = QPushButton("Send Message")
        send_button.clicked.connect(self.send_message_from_gui)
        chat_layout.addWidget(send_button)

        splitter.addWidget(chat_area_widget)
        splitter.setSizes([200, 600])

        main_h_layout = QVBoxLayout(central_widget)
        main_h_layout.addWidget(splitter)
        central_widget.setLayout(main_h_layout)

        # --- Status Bar ---
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready. Please start listening or connect to a peer.")

    def send_message_from_gui(self):
        message_text = self.message_input.text().strip()
        if not self.current_chat_peer_id:
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer from the list to send a message.")
            return
        if message_text:
            self.send_message_signal.emit(message_text) # Controller will use current_chat_peer_id
            self.update_chat_display(f"Me ({self.current_chat_peer_id}): {message_text}")
            self.message_input.clear()
        else:
            self.statusBar.showMessage("Cannot send an empty message.", 3000)

    @pyqtSlot(str)
    def update_chat_display(self, message_text: str):
        self.chat_display.append(message_text)
        self.chat_display.ensureCursorVisible() # Scroll to bottom

    @pyqtSlot(list)
    def update_peer_list_gui(self, peers: list):
        """Updates the peer list widget. `peers` is a list of peer_id strings."""
        self.peer_list_widget.clear()
        if peers:
            self.peer_list_widget.addItems(peers)
        else:
            self.peer_list_widget.addItem("No active peers.")

    @pyqtSlot(str) # status_message
    def set_status_bar_message(self, message: str, timeout=0):
        self.statusBar.showMessage(message, timeout)

    def show_start_server_dialog(self):
        port_str, ok = QInputDialog.getText(self, 'Start Listening', 'Enter port to listen on (e.g., 12345):')
        if ok and port_str:
            try:
                port = int(port_str)
                if not (1024 <= port <= 65535):
                    QMessageBox.warning(self, "Invalid Port", "Port must be between 1024 and 65535.")
                    return
                self.set_status_bar_message(f"Requesting to start server on port {port}...")
                self.start_server_requested_signal.emit(port)
            except ValueError:
                QMessageBox.warning(self, "Invalid Input", "Port must be a number.")


    def show_connect_dialog(self):
        host, ok1 = QInputDialog.getText(self, 'Connect to Peer', 'Enter Peer IP Address (e.g., 127.0.0.1):')
        if ok1 and host:
            port_str, ok2 = QInputDialog.getText(self, 'Connect to Peer', f'Enter Port for {host} (e.g., 12345):')
            if ok2 and port_str:
                try:
                    port = int(port_str)
                    if not (1024 <= port <= 65535):
                         QMessageBox.warning(self, "Invalid Port", "Port must be between 1024 and 65535.")
                         return
                    self.update_chat_display(f"System: Attempting to connect to {host}:{port}...")
                    self.set_status_bar_message(f"Connecting to {host}:{port}...")
                    self.connect_to_peer_signal.emit(host, port_str)
                except ValueError:
                     QMessageBox.warning(self, "Connection Error", "Invalid port number.")
            # else: User cancelled port input
        # else: User cancelled host input

    def show_about_dialog(self):
        QMessageBox.about(self, "About P2P Secure Messenger",
                          "P2P Secure Messenger\nVersion 0.2 (GUI Alpha)\n"
                          "Built with Python and PyQt5.\n"
                          "Secure P2P communication.")

    def peer_selected_in_list(self, current_item, previous_item):
        if current_item:
            peer_id = current_item.text() # Assuming peer_id is the text
            if peer_id == "No active peers.":
                self.current_chat_peer_id = None
                self.chat_display.clear()
                self.chat_display.setPlaceholderText("Select a peer to start chatting.")
                return

            self.current_chat_peer_id = peer_id
            self.setWindowTitle(f"P2P Secure Messenger - Chat with {peer_id}")
            self.chat_display.clear() # Clear previous chat
            self.chat_display.setPlaceholderText(f"Chat history with {peer_id} will appear here (not yet implemented). Say hi!")
            self.update_chat_display(f"System: Chatting with {peer_id}. (Chat history loading not yet implemented)")
            self.set_status_bar_message(f"Selected peer: {peer_id}")
            self.peer_selection_changed_signal.emit(peer_id) # Notify controller
        else:
            self.current_chat_peer_id = None
            self.setWindowTitle("P2P Secure Messenger")
            self.chat_display.clear()
            self.chat_display.setPlaceholderText("Select a peer from the list to start chatting.")
            self.set_status_bar_message("No peer selected.")
            self.peer_selection_changed_signal.emit("") # Empty string for no selection


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_gui = ChatGUI()

    # Example of connecting GUI signals to slots for testing
    @pyqtSlot(str)
    def handle_gui_send_message(message):
        print(f"GUI Test: Message to send via signal: {message} (to {main_gui.current_chat_peer_id or 'Unknown Peer'})")
        main_gui.update_chat_display(f"System (Test): '{message}' would be sent to {main_gui.current_chat_peer_id}.")

    @pyqtSlot(str, str)
    def handle_gui_connect_to_peer(host, port):
        peer_id = f"{host}:{port}"
        print(f"GUI Test: Connect to peer signal: {peer_id}")
        main_gui.update_chat_display(f"System (Test): Would attempt connection to {peer_id}.")
        # Simulate adding peer and selecting it
        main_gui.update_peer_list_gui([peer_id, "Other Peer"])
        # Find the item and set it as current to trigger selection logic
        items = main_gui.peer_list_widget.findItems(peer_id, Qt.MatchExactly)
        if items:
            main_gui.peer_list_widget.setCurrentItem(items[0])

    @pyqtSlot(str)
    def handle_peer_selection_changed(peer_id):
        print(f"GUI Test: Peer selection changed to: {peer_id}")


    main_gui.send_message_signal.connect(handle_gui_send_message)
    main_gui.connect_to_peer_signal.connect(handle_gui_connect_to_peer)
    main_gui.peer_selection_changed_signal.connect(handle_peer_selection_changed)

    # Simulate receiving a message (as if from controller)
    # main_gui.update_chat_display("PeerX (Simulated): Hello from a simulated peer!")
    main_gui.update_peer_list_gui([]) # Start with empty peer list

    main_gui.show()
    sys.exit(app.exec_())
