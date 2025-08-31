from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                            QListWidget, QTextEdit, QSplitter, QGroupBox,
                            QInputDialog, QMessageBox, QLabel)
from PyQt5.QtCore import Qt

class RulesEditorTab(QWidget):
    def __init__(self, waf_manager):
        super().__init__()
        self.waf_manager = waf_manager
        self.current_rule = None
        self.setup_ui()
        self.load_rules_list()
    
    def setup_ui(self):
        main_layout = QHBoxLayout(self)
        
        # Left panel - rules list
        left_panel = QGroupBox("Rules")
        left_layout = QVBoxLayout(left_panel)
        
        self.rules_list = QListWidget()
        self.rules_list.itemSelectionChanged.connect(self.on_rule_selected)
        
        # Buttons for rules management
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Rule")
        self.remove_btn = QPushButton("Remove Rule")
        self.save_btn = QPushButton("Save Changes")
        
        self.add_btn.clicked.connect(self.add_rule)
        self.remove_btn.clicked.connect(self.remove_rule)
        self.save_btn.clicked.connect(self.save_rule)
        
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.remove_btn)
        btn_layout.addWidget(self.save_btn)
        
        left_layout.addWidget(self.rules_list)
        left_layout.addLayout(btn_layout)
        
        # Right panel - rule editor
        right_panel = QGroupBox("Rule Editor")
        right_layout = QVBoxLayout(right_panel)
        
        self.rule_editor = QTextEdit()
        self.rule_editor.setPlaceholderText("Select a rule to edit or create a new one...")
        
        # Rule info
        self.rule_info = QLabel("No rule selected")
        
        right_layout.addWidget(self.rule_info)
        right_layout.addWidget(self.rule_editor)
        
        # Add panels to main layout
        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(right_panel, 2)
    
    def load_rules_list(self):
        self.rules_list.clear()
        rules = self.waf_manager.list_rules()
        self.rules_list.addItems(rules)
    
    def on_rule_selected(self):
        selected_items = self.rules_list.selectedItems()
        if selected_items:
            rule_name = selected_items[0].text()
            self.current_rule = rule_name
            content = self.waf_manager.get_rule_content(rule_name)
            self.rule_editor.setPlainText(content)
            self.rule_info.setText(f"Editing: {rule_name}")
        else:
            self.current_rule = None
            self.rule_editor.clear()
            self.rule_info.setText("No rule selected")
    
    def add_rule(self):
        rule_name, ok = QInputDialog.getText(
            self, "Add New Rule", "Enter rule name:"
        )
        
        if ok and rule_name:
            if not rule_name.endswith('.conf'):
                rule_name += '.conf'
            
            # Basic rule template
            template = f"""# {rule_name}
SecRule REQUEST_URI "@contains test" \\
    "id:1000,\\
    phase:2,\\
    deny,\\
    status:403,\\
    msg:'Test rule detected'"
"""
            
            success, message = self.waf_manager.add_rule(template, rule_name[:-5])
            if success:
                self.load_rules_list()
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def remove_rule(self):
        if not self.current_rule:
            QMessageBox.warning(self, "Error", "No rule selected")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete rule '{self.current_rule}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success, message = self.waf_manager.remove_rule(self.current_rule)
            if success:
                self.load_rules_list()
                self.rule_editor.clear()
                self.current_rule = None
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def save_rule(self):
        if not self.current_rule:
            QMessageBox.warning(self, "Error", "No rule selected")
            return
        
        content = self.rule_editor.toPlainText()
        success, message = self.waf_manager.add_rule(content, self.current_rule)
        
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)