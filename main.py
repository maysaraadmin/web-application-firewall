import argparse
import sys
import os
from PyQt5.QtWidgets import QApplication
from waf_manager import WAFManager
from gui.main_window import MainWindow

def main():
    parser = argparse.ArgumentParser(description='Web Application Firewall Manager')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start the WAF')
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop the WAF')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check WAF status')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test a request against WAF rules')
    test_parser.add_argument('url', help='URL to test')
    test_parser.add_argument('--method', default='GET', help='HTTP method (default: GET)')
    
    # Add rule command
    add_rule_parser = subparsers.add_parser('add-rule', help='Add a new rule')
    add_rule_parser.add_argument('rule', help='Rule content (regex pattern)')
    add_rule_parser.add_argument('--name', required=True, help='Name for the rule file')
    
    # List rules command
    list_rules_parser = subparsers.add_parser('list-rules', help='List all rules')
    
    # GUI command
    gui_parser = subparsers.add_parser('gui', help='Launch the WAF Manager GUI')
    
    args = parser.parse_args()
    
    waf = WAFManager()
    
    if args.command == 'start':
        success, message = waf.start_waf()
        print(f"{'SUCCESS' if success else 'ERROR'}: {message}")
    
    elif args.command == 'stop':
        success, message = waf.stop_waf()
        print(f"{'SUCCESS' if success else 'ERROR'}: {message}")
    
    elif args.command == 'status':
        if waf.get_status():
            print("WAF is running")
        else:
            print("WAF is not running")
    
    elif args.command == 'test':
        result = waf.test_request(args.url, method=args.method)
        if result.get('error'):
            print(f"ERROR: {result['error']}")
        elif result['blocked']:
            print(f"BLOCKED: Request was blocked by WAF")
            print("Matched rules:")
            for rule in result['matched_rules']:
                print(f"- {rule}")
        else:
            print("PASSED: Request was allowed by WAF")
    
    elif args.command == 'add-rule':
        success, message = waf.add_rule(args.rule, args.name)
        print(f"{'SUCCESS' if success else 'ERROR'}: {message}")
    
    elif args.command == 'list-rules':
        rules = waf.list_rules()
        if rules:
            print("Available rules:")
            for rule in rules:
                print(f"- {rule}")
        else:
            print("No rules found")
            
    elif args.command == 'gui':
        app = QApplication(sys.argv)
        window = MainWindow(waf)
        window.show()
        sys.exit(app.exec_())
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()