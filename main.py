import sys
import os
from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow
from waf_manager import WAFManager

def main():
    app = QApplication(sys.argv)
    
    # Initialize WAF manager
    waf_manager = WAFManager()
    
    # Create main window
    window = MainWindow(waf_manager)
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()