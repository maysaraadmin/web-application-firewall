import os
import re
import json
import yaml
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WAFManager:
    def __init__(self):
        # Use absolute paths
        base_dir = Path(__file__).parent.absolute()
        self.config_dir = str(base_dir / "config")
        self.rules_dir = str(base_dir / "config" / "rules")
        self.log_file = str(base_dir / "logs" / "waf_audit.log")
        
        # Ensure directories exist
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Initialize WAF
        self.waf = None
        self._initialize_waf()
    
    def _initialize_waf(self) -> bool:
        """Initialize the WAF with basic rules
        
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        self.rules = []
        self.patterns = {
            'sqli': [
                r'\b(?:select\s.*?from|insert\s+into|update\s+\w+\s+set|delete\s+from)\b',
                r'\b(?:union\s+(?:all\s+)?select|union\s*\()',
                r'\b(?:exec\s*\(|xp_cmdshell|sp_executesql)\b',
                r'\b(?:--|#|\/\*|\*\/|;--|;\*|;)\s',
                r'\b(?:or\s+\d+=\d+|"\s*or\s*"[^=]+"\s*=\s*"[^"]+")\b',
            ],
            'xss': [
                r'(?i)<script[^>]*>.*?</script>',
                r'(?i)on\w+\s*=',
                r'(?i)javascript:',
                r'<[^>]*(?:src|href)=\s*["\']?javascript:',
                r'<[^>]*(?:on\w+)=\s*[\"\'][^\"]*[\"\']',
            ],
            'path_traversal': [
                r'(?:\.\.(?:%2e%2e|%252e%252e|\/|\\))+',
                r'\b(?:etc\/|etc\\)',
                r'\b(?:passwd|shadow|hosts|\/etc\/|c:\\windows\\system32\\|\/bin\/sh)\b',
            ]
        }
        
        try:
            # Ensure rules directory exists
            if not os.path.exists(self.rules_dir):
                os.makedirs(self.rules_dir, exist_ok=True)
                logger.info(f"Created rules directory at {self.rules_dir}")
                
            # Load rules from files
            rule_files = [f for f in os.listdir(self.rules_dir) 
                         if f.endswith(('.conf', '.rule')) and os.path.isfile(os.path.join(self.rules_dir, f))]
            
            for rule_file in rule_files:
                rule_path = os.path.join(self.rules_dir, rule_file)
                try:
                    with open(rule_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                try:
                                    compiled = re.compile(line, re.IGNORECASE)
                                    self.rules.append((rule_file, line, compiled))
                                except re.error as e:
                                    logger.warning(f"Invalid regex in {rule_file}: {line} - {str(e)}")
                except (IOError, OSError) as e:
                    logger.error(f"Error reading rule file {rule_file}: {str(e)}")
                    continue
                    
            logger.info(f"WAF initialized with {len(self.rules)} rules")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize WAF: {str(e)}", exc_info=True)
            return False
    
    def start_waf(self) -> Tuple[bool, str]:
        """Start the WAF service"""
        if self.get_status():
            return False, "WAF is already running"
            
        try:
            if not self._initialize_waf():
                return False, "Failed to initialize WAF"
            
            logger.info("WAF started successfully")
            return True, "WAF started successfully"
            
        except Exception as e:
            logger.error(f"Failed to start WAF: {str(e)}")
            return False, f"Failed to start WAF: {str(e)}"
    
    def stop_waf(self) -> Tuple[bool, str]:
        """Stop the WAF service"""
        try:
            self.rules = None
            logger.info("WAF stopped successfully")
            return True, "WAF stopped successfully"
        except Exception as e:
            logger.error(f"Failed to stop WAF: {str(e)}")
            return False, f"Failed to stop WAF: {str(e)}"
    
    def get_status(self) -> bool:
        """Check if WAF is running"""
        try:
            return self.rules is not None
        except Exception as e:
            logger.error(f"Error checking WAF status: {str(e)}")
            return False
            
    def add_rule(self, rule_content: str, rule_name: str) -> Tuple[bool, str]:
        """Add a new rule file
        
        Args:
            rule_content: The rule content (regex pattern)
            rule_name: Name for the rule file (without extension)
            
        Returns:
            Tuple of (success, message)
            
        Raises:
            ValueError: If rule_name is invalid, contains path traversal,
                       or if rule_content is not a valid regex pattern
        """
        if not rule_name or not isinstance(rule_name, str) or not rule_name.strip():
            raise ValueError("Rule name must be a non-empty string")
            
        # Prevent path traversal in rule name
        if '..' in rule_name or '/' in rule_name or '\\' in rule_name:
            raise ValueError("Invalid rule name: cannot contain path traversal characters")
            
        # Check for duplicate rule names
        existing_rules = [r.lower() for r in self.list_rules()]
        if rule_name.lower() in existing_rules:
            return False, f"A rule named '{rule_name}' already exists"
        
        # Validate rule content
        if not rule_content or not isinstance(rule_content, str) or not rule_content.strip():
            return False, "Rule content cannot be empty"
            
        # Test if the rule is a valid regex
        try:
            re.compile(rule_content)
        except re.error as e:
            return False, f"Invalid regex pattern: {str(e)}"
        
        # Ensure rule has correct extension
        if not rule_name.endswith(('.conf', '.rule')):
            rule_name += '.rule'
                
        rule_path = os.path.join(self.rules_dir, rule_name)
        
        # Ensure rules directory exists
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Save rule to file with atomic write
        temp_path = f"{rule_path}.tmp"
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)
                f.flush()
                os.fsync(f.fileno())
            
            # Atomic rename on POSIX, not atomic on Windows but best effort
            if os.path.exists(rule_path):
                os.remove(temp_path)
                return False, f"Rule '{rule_name}' was created by another process"
                
            os.rename(temp_path, rule_path)
            
            # Reload rules if WAF is running
            if self.get_status():
                self.rules = []
                self._initialize_waf()
                
            logger.info(f"Rule {rule_name} added successfully")
            return True, f"Rule {rule_name} added successfully"
            
        except (IOError, OSError) as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            logger.error(f"Failed to add rule: {str(e)}", exc_info=True)
            return False, f"Failed to add rule: {str(e)}"
    
    def remove_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Remove a rule file
        
        Args:
            rule_name: Name of the rule to remove (with or without .conf extension)
            
        Returns:
            Tuple of (success, message)
        """
        if not rule_name or not isinstance(rule_name, str) or not rule_name.strip():
            return False, "Rule name cannot be empty"
            
        try:
            # Ensure rule has correct extension
            if not rule_name.endswith(('.conf', '.rule')):
                rule_name += '.conf'
                
            rule_path = os.path.join(self.rules_dir, rule_name)
            
            if not os.path.exists(rule_path):
                # Try with .rule extension if .conf not found
                if rule_name.endswith('.conf'):
                    rule_path = os.path.join(self.rules_dir, rule_name[:-5] + '.rule')
                    if not os.path.exists(rule_path):
                        return False, "Rule not found"
                else:
                    return False, "Rule not found"
                    
            # Delete rule file
            os.remove(rule_path)
            
            # Reinitialize WAF to reload rules
            if self.get_status():
                self._initialize_waf()
                
            logger.info(f"Rule {rule_name} removed successfully")
            return True, f"Rule {rule_name} removed successfully"
            
        except Exception as e:
            logger.error(f"Failed to remove rule: {str(e)}")
            return False, f"Failed to remove rule: {str(e)}"
    
    def list_rules(self) -> List[str]:
        """List all rule files
        
        Returns:
            list: List of rule names without extensions
        """
        try:
            rules = []
            if not os.path.exists(self.rules_dir):
                return rules
                
            for file in os.listdir(self.rules_dir):
                if file.endswith(('.conf', '.rule')):
                    rules.append(os.path.splitext(file)[0])  # Remove extension
            return rules
        except Exception as e:
            logger.error(f"Error listing rules: {str(e)}")
            return []
    
    def get_rule_content(self, rule_name: str) -> str:
        """Get content of a specific rule
        
        Args:
            rule_name: Name of the rule (with or without extension)
            
        Returns:
            str: Content of the rule file, or empty string if not found
        """
        if not rule_name or not isinstance(rule_name, str):
            return ""
            
        try:
            # Try with .conf extension first
            if not rule_name.endswith(('.conf', '.rule')):
                rule_path = os.path.join(self.rules_dir, f"{rule_name}.conf")
                if not os.path.exists(rule_path):
                    # Fall back to .rule extension
                    rule_path = os.path.join(self.rules_dir, f"{rule_name}.rule")
            else:
                rule_path = os.path.join(self.rules_dir, rule_name)
            
            if not os.path.exists(rule_path):
                return ""
                
            with open(rule_path, 'r', encoding='utf-8') as f:
                return f.read()
                
        except Exception as e:
            logger.error(f"Error getting rule content: {str(e)}")
            return ""
    
    def get_logs(self, lines: int = 100) -> str:
        """Get recent logs
        
        Args:
            lines: Number of lines to return (most recent)
            
        Returns:
            str: The log content or error message
        """
        try:
            if not os.path.exists(self.log_file):
                return "No logs available"
                
            with open(self.log_file, 'r', encoding='utf-8') as f:
                # Read last N lines efficiently
                log_lines = []
                for line in f:
                    log_lines.append(line)
                    if len(log_lines) > lines:
                        log_lines.pop(0)
                
                return "".join(log_lines)
                
        except Exception as e:
            logger.error(f"Error reading logs: {str(e)}")
            return f"Error reading logs: {str(e)}"
    
    def _check_patterns(self, value: str) -> List[Dict[str, str]]:
        """Check value against attack patterns
        
        Args:
            value: The string value to check against patterns
            
        Returns:
            List of dictionaries with match details
        """
        matches = []
        if not value or not isinstance(value, str):
            return matches
            
        value = value.lower()
            
        # Check built-in patterns
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, value, re.IGNORECASE):
                        matches.append({
                            'category': category,
                            'pattern': pattern,
                            'value': value
                        })
                except re.error as e:
                    logger.warning(f"Invalid pattern in {category}: {pattern} - {str(e)}")
        
        # Check custom rules if WAF is running
        if self.rules is not None:
            for rule_file, rule_pattern, _ in self.rules:
                try:
                    if re.search(rule_pattern, value, re.IGNORECASE):
                        matches.append({
                            'category': 'custom_rule',
                            'pattern': rule_pattern,
                            'value': value,
                            'source': rule_file
                        })
                except re.error as e:
                    logger.warning(f"Invalid pattern in {rule_file}: {rule_pattern} - {str(e)}")
        
        return matches

    def test_request(self, url: str, method: str = "GET", 
                    headers: Optional[Dict] = None, 
                    data: Optional[str] = None) -> Dict:
        """Test a request against WAF rules
        
        Args:
            url: The URL to test
            method: HTTP method (GET, POST, etc.)
            headers: Request headers
            data: Request body
            
        Returns:
            dict: Test results including whether the request was blocked
            
        Raises:
            ValueError: If URL is invalid or WAF is not running
        """
        if not self.get_status():
            raise ValueError("WAF is not running")
        
        # Validate URL format
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
        
        try:
            # Parse and validate URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid URL format. Must include scheme (http/https) and hostname")
            
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            matches = []
            
            # Check URL
            url_matches = self._check_patterns(url)
            matches.extend([f"URL: {m['pattern']}" for m in url_matches])
            
            # Check headers
            headers = headers or {}
            for name, value in headers.items():
                header_matches = self._check_patterns(f"{name}: {value}")
                matches.extend([f"Header {name}: {m['pattern']}" for m in header_matches])
            
            # Check request body
            if data:
                body_matches = self._check_patterns(str(data))
                matches.extend([f"Body: {m['pattern']}" for m in body_matches])
            
            # If we found any matches, block the request
            if matches:
                return {
                    "blocked": True,
                    "status_code": 403,
                    "matched_rules": matches,
                    "score": len(matches),
                    "action": "DENY"
                }
            
            # If we get here, request was not blocked
            return {
                "blocked": False,
                "status_code": 200,
                "matched_rules": [],
                "score": 0,
                "action": "PASS"
            }
            
        except Exception as e:
            logger.error(f"Error testing request: {str(e)}", exc_info=True)
            return {
                "blocked": False,
                "matched_rules": [],
                "score": 0,
                "error": str(e)
            }