# gui/gui_main_window.py
# This module will contain the main GUI window for the application.

import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QTextEdit, QLineEdit, QPushButton, QListWidget,
                             QMenuBar, QAction, QSplitter)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

class ChatGUI(QMainWindow):
    # Signal to emit when a message is to be sent from the GUI
    # The signal will carry the message string
    send_message_signal = pyqtSignal(str)
    # Signal to request connection to a peer
    # The signal will carry host and port strings
    connect_to_peer_signal = pyqtSignal(str, str)


    def __init__(self):
        super().__init__()
        self.setWindowTitle("P2P Secure Messenger")
        self.setGeometry(100, 100, 800, 600) # x, y, width, height

        self.init_ui()

    def init_ui(self):
        # --- Menu Bar ---
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File')

        connect_action = QAction('&Connect to Peer...', self)
        connect_action.triggered.connect(self.show_connect_dialog) # Placeholder
        file_menu.addAction(connect_action)

        exit_action = QAction('&Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menubar.addMenu('&Help')
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about_dialog) # Placeholder
        help_menu.addAction(about_action)

        # --- Central Widget & Layout ---
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        # main_layout = QVBoxLayout(central_widget)

        # Use QSplitter for resizable sections
        splitter = QSplitter(Qt.Horizontal)

        # --- Peer List (Left Pane) ---
        self.peer_list_widget = QListWidget()
        self.peer_list_widget.setMaximumWidth(200) # Initial width
        # Example items - will be populated dynamically
        self.peer_list_widget.addItems(["Peer 1 (127.0.0.1:12346)", "LAN User X"])
        self.peer_list_widget.currentItemChanged.connect(self.peer_selected) # Placeholder
        splitter.addWidget(self.peer_list_widget)

        # --- Chat Area (Right Pane) ---
        chat_area_widget = QWidget()
        chat_layout = QVBoxLayout(chat_area_widget)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        chat_layout.addWidget(self.chat_display)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.returnPressed.connect(self.send_message_from_gui) # Send on Enter
        chat_layout.addWidget(self.message_input)

        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message_from_gui)
        chat_layout.addWidget(send_button)

        splitter.addWidget(chat_area_widget)
        splitter.setSizes([200, 600]) # Initial sizes for panes

        # Set the splitter as the main layout for the central widget
        main_h_layout = QVBoxLayout(central_widget) # Main layout to hold the splitter
        main_h_layout.addWidget(splitter)
        central_widget.setLayout(main_h_layout)


    def send_message_from_gui(self):
        message_text = self.message_input.text().strip()
        if message_text:
            # Emit the signal with the message
            self.send_message_signal.emit(message_text)
            self.append_message_to_display(f"Me: {message_text}") # Display own message
            self.message_input.clear()
        else:
            print("GUI: Empty message not sent.")

    def append_message_to_display(self, message_text: str):
        """Appends a message to the chat display area."""
        self.chat_display.append(message_text)
        # TODO: Scroll to bottom if needed

    def update_peer_list(self, peers: list):
        """Updates the peer list widget. `peers` is a list of strings."""
        self.peer_list_widget.clear()
        self.peer_list_widget.addItems(peers)

    def show_connect_dialog(self):
        # Placeholder for a dialog to get peer IP and Port
        # For now, one could use a simple QInputDialog or a custom QDialog
        from PyQt5.QtWidgets import QInputDialog, QMessageBox

        host, ok1 = QInputDialog.getText(self, 'Connect to Peer', 'Enter Peer IP Address:')
        if ok1 and host:
            port_str, ok2 = QInputDialog.getText(self, 'Connect to Peer', f'Enter Port for {host}:')
            if ok2 and port_str:
                try:
                    # Validate port if necessary, here just basic check
                    int(port_str)
                    self.append_message_to_display(f"Attempting to connect to {host}:{port_str}...")
                    # Emit signal to application logic to handle connection
                    self.connect_to_peer_signal.emit(host, port_str)
                except ValueError:
                     QMessageBox.warning(self, "Connection Error", "Invalid port number.")
            else: # Port input cancelled or empty
                 QMessageBox.information(self, "Connection Cancelled", "Connection attempt cancelled by user (port).")

        else: # Host input cancelled or empty
            QMessageBox.information(self, "Connection Cancelled", "Connection attempt cancelled by user (host).")


    def show_about_dialog(self):
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.about(self, "About P2P Secure Messenger",
                          "P2P Secure Messenger\nVersion 0.2 (GUI Alpha)\n"
                          "Built with Python and PyQt5.\n"
                          "Further development in progress.")

    def peer_selected(self, current_item, previous_item):
        # Placeholder for when a peer is selected from the list
        if current_item:
            self.append_message_to_display(f"Selected chat with: {current_item.text()}")
            # Here you would typically load the chat history for this peer
            # and set this peer as the current recipient for messages.
        else: # No item selected or list cleared
            self.append_message_to_display("No peer selected.")


# To run this GUI standalone for testing purposes:
if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_gui = ChatGUI()

    # Example of connecting GUI signals to slots for testing
    def handle_gui_send_message(message):
        print(f"GUI Test: Message to send via signal: {message}")
        # In a real app, this would go to the network layer
        main_gui.append_message_to_display(f"System (Test): '{message}' would be sent.")

    def handle_gui_connect_to_peer(host, port):
        print(f"GUI Test: Connect to peer signal: {host}:{port}")
        main_gui.append_message_to_display(f"System (Test): Would attempt connection to {host}:{port}.")


    main_gui.send_message_signal.connect(handle_gui_send_message)
    main_gui.connect_to_peer_signal.connect(handle_gui_connect_to_peer)

    main_gui.show()
    sys.exit(app.exec_())
