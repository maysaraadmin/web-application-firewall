from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QStatusBar, 
                            QMessageBox, QVBoxLayout, QWidget)
from PyQt5.QtCore import QTimer
from .dashboard import DashboardTab
from .rules_editor import RulesEditorTab
from waf_manager import WAFManager

class MainWindow(QMainWindow):
    def __init__(self, waf_manager):
        super().__init__()
        self.waf_manager = waf_manager
        self.setWindowTitle("Web Application Firewall Manager")
        self.setGeometry(100, 100, 1200, 800)
        
        self.setup_ui()
        self.setup_timer()
    
    def setup_ui(self):
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.dashboard_tab = DashboardTab(self.waf_manager)
        self.rules_tab = RulesEditorTab(self.waf_manager)
        
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")
        self.tab_widget.addTab(self.rules_tab, "Rules Editor")
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.update_status()
    
    def setup_timer(self):
        # Update status every 5 seconds
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(5000)
    
    def update_status(self):
        status = self.waf_manager.get_status()
        status_text = "WAF Status: RUNNING" if status else "WAF Status: STOPPED"
        self.statusBar.showMessage(status_text)
    
    def closeEvent(self, event):
        # Stop WAF when closing application
        if self.waf_manager.get_status():
            reply = QMessageBox.question(
                self, 'Confirm Exit',
                'WAF is still running. Are you sure you want to exit?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.waf_manager.stop_waf()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()