import subprocess
import json
import os
import sys
import signal
import platform
from pathlib import Path
from datetime import datetime

class WAFManager:
    def __init__(self):
        # Use absolute paths
        base_dir = Path(__file__).parent.absolute()
        self.config_path = str(base_dir / "config" / "modsecurity.conf")
        self.rules_dir = str(base_dir / "config" / "rules")
        self.log_file = str(base_dir / "logs" / "modsec_audit.log")
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        self.process = None
    
    def start_waf(self):
        """Start ModSecurity service"""
        if self.get_status():
            return False, "WAF is already running"
            
        try:
            # Check if ModSecurity is installed
            if platform.system() == 'Windows':
                cmd = ['where', 'modsecurity']
            else:
                cmd = ['which', 'modsecurity']
                
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError:
                return False, "ModSecurity is not installed or not in PATH"
                
            # Start ModSecurity
            cmd = ["modsecurity", "-c", self.config_path]
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == 'Windows' else 0
            )
            return True, "WAF started successfully"
        except Exception as e:
            return False, f"Failed to start WAF: {str(e)}"
    
    def stop_waf(self):
        """Stop ModSecurity service"""
        try:
            if self.process:
                if platform.system() == 'Windows':
                    import ctypes
                    ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, self.process.pid)
                else:
                    self.process.terminate()
                self.process.wait(timeout=5)
                self.process = None
                return True, "WAF stopped successfully"
            return False, "No running WAF process found"
        except Exception as e:
            return False, f"Failed to stop WAF: {str(e)}"
    
    def get_status(self):
        """Check if WAF is running"""
        if self.process is not None:
            return self.process.poll() is None
            
        try:
            if platform.system() == 'Windows':
                cmd = ['tasklist', '/FI', 'IMAGENAME eq modsecurity.exe']
                result = subprocess.run(cmd, capture_output=True, text=True)
                return 'modsecurity.exe' in result.stdout
            else:
                result = subprocess.run(['pgrep', '-f', 'modsecurity'], 
                                     capture_output=True, text=True)
                return len(result.stdout.strip()) > 0
        except Exception:
            return False
    
    def add_rule(self, rule_content, rule_name):
        """Add a new rule file"""
        try:
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
            with open(rule_path, 'w') as f:
                f.write(rule_content)
            return True, f"Rule {rule_name} added successfully"
        except Exception as e:
            return False, f"Failed to add rule: {str(e)}"
    
    def remove_rule(self, rule_name):
        """Remove a rule file"""
        try:
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
            if os.path.exists(rule_path):
                os.remove(rule_path)
                return True, f"Rule {rule_name} removed successfully"
            return False, "Rule not found"
        except Exception as e:
            return False, f"Failed to remove rule: {str(e)}"
    
    def list_rules(self):
        """List all rule files"""
        rules = []
        for file in os.listdir(self.rules_dir):
            if file.endswith('.conf'):
                rules.append(file[:-5])  # Remove .conf extension
        return rules
    
    def get_rule_content(self, rule_name):
        """Get content of a specific rule"""
        try:
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
            with open(rule_path, 'r') as f:
                return f.read()
        except:
            return ""
    
    def get_logs(self, lines=100):
        """Get recent logs"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    logs = f.readlines()[-lines:]
                return "".join(logs)
            return "No logs available"
        except Exception as e:
            return f"Error reading logs: {str(e)}"
    
    def test_request(self, url, method="GET", headers=None, data=None):
        """Test a request against WAF rules
        
        Args:
            url (str): The URL to test
            method (str): HTTP method (GET, POST, etc.)
            headers (dict): Request headers
            data (str): Request body
            
        Returns:
            dict: Test results including whether the request was blocked
        """
        if not self.get_status():
            return {
                "blocked": False,
                "matched_rules": [],
                "score": 0,
                "error": "WAF is not running"
            }
            
        try:
            import requests
            from urllib.parse import urlparse
            
            # Parse URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL provided")
                
            # Prepare headers
            headers = headers or {}
            headers['User-Agent'] = headers.get('User-Agent', 'WAF-Tester/1.0')
            
            # Make the request
            response = requests.request(
                method.upper(),
                url,
                headers=headers,
                data=data,
                timeout=10
            )
            
            # Check if request was blocked (403 Forbidden is common for blocked requests)
            blocked = response.status_code == 403
            
            return {
                "blocked": blocked,
                "status_code": response.status_code,
                "matched_rules": [],  # This would be parsed from ModSecurity logs
                "score": 0,  # This would be calculated based on rules triggered
                "action": "PASS"
            }
        except Exception as e:
            return {
                "blocked": False,
                "matched_rules": [],
                "score": 0,
                "error": str(e)
            }