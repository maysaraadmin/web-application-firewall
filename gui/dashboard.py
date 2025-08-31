from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                            QGroupBox, QTextEdit, QLabel, QSplitter, QFrame)
from PyQt5.QtCore import Qt

class DashboardTab(QWidget):
    def __init__(self, waf_manager):
        super().__init__()
        self.waf_manager = waf_manager
        self.setup_ui()
        self.refresh_logs()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start WAF")
        self.stop_btn = QPushButton("Stop WAF")
        self.refresh_btn = QPushButton("Refresh Logs")
        
        self.start_btn.clicked.connect(self.start_waf)
        self.stop_btn.clicked.connect(self.stop_waf)
        self.refresh_btn.clicked.connect(self.refresh_logs)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.refresh_btn)
        control_layout.addStretch()
        
        # Stats group
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.requests_label = QLabel("Requests: 0")
        self.blocked_label = QLabel("Blocked: 0")
        self.rules_label = QLabel("Active Rules: 0")
        
        stats_layout.addWidget(self.requests_label)
        stats_layout.addWidget(self.blocked_label)
        stats_layout.addWidget(self.rules_label)
        stats_layout.addStretch()
        
        # Logs display
        logs_group = QGroupBox("Recent Logs")
        logs_layout = QVBoxLayout(logs_group)
        
        self.logs_display = QTextEdit()
        self.logs_display.setReadOnly(True)
        self.logs_display.setMaximumHeight(300)
        
        logs_layout.addWidget(self.logs_display)
        
        # Add to main layout
        layout.addLayout(control_layout)
        layout.addWidget(stats_group)
        layout.addWidget(logs_group)
        
        self.update_stats()
    
    def start_waf(self):
        success, message = self.waf_manager.start_waf()
        self.show_message(message, success)
        self.update_stats()
    
    def stop_waf(self):
        success, message = self.waf_manager.stop_waf()
        self.show_message(message, success)
        self.update_stats()
    
    def refresh_logs(self):
        logs = self.waf_manager.get_logs(50)
        self.logs_display.setPlainText(logs)
    
    def update_stats(self):
        rules_count = len(self.waf_manager.list_rules())
        self.rules_label.setText(f"Active Rules: {rules_count}")
        
        # Simulated stats - in real implementation, parse logs
        status = self.waf_manager.get_status()
        if status:
            self.requests_label.setText("Requests: 125")
            self.blocked_label.setText("Blocked: 8")
        else:
            self.requests_label.setText("Requests: 0")
            self.blocked_label.setText("Blocked: 0")
    
    def show_message(self, message, success=True):
        # Simple message display - could be enhanced with proper dialog
        print(f"{'SUCCESS' if success else 'ERROR'}: {message}")