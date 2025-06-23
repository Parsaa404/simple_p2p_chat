# main.py
# Main entry point for the P2P Secure Messenger application.
# This script initializes and runs the GUI.

import sys
from PyQt5.QtWidgets import QApplication
from app_logic.main_controller import MainController

if __name__ == "__main__":
    # Forcing the application to use the XCB QPA plugin if on Linux
    # and if QT_QPA_PLATFORM is not already set. This can help with
    # Wayland/X11 compatibility issues on some Linux distributions.
    # Note: This is a common workaround, but might not be necessary for all systems.
    # If issues arise, this line can be commented out or adjusted.
    # if sys.platform.startswith('linux') and 'QT_QPA_PLATFORM' not in os.environ:
    #    os.environ['QT_QPA_PLATFORM'] = 'xcb'
    # Commented out for now as os module is not imported and might not be needed.

    app = QApplication(sys.argv)
    controller = MainController()
    # The controller shows the GUI in its __init__
    exit_code = app.exec_()
    # Ensure controller's shutdown logic is called if it has any
    # (e.g., stopping threads, saving state)
    # controller.shutdown() # MainController now handles shutdown on GUI close
    sys.exit(exit_code)
