from flask import Flask, request, jsonify
import ast
import collections
import re
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

class CodeAuditor:
    
    def __init__(self, code):
        
        self.code = code
        self.tree = ast.parse(self.code)
        self.variables = collections.defaultdict(list)
        self.functions = collections.defaultdict(list)
        self.unsafe_transfers = []
        self.double_free_errors = []

    def audit_variables(self):
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name):
                self.variables[node.id].append(node.lineno)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.variables[target.id].append(node.lineno)

    def audit_functions(self):
        
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                self.functions[node.name].append(node.lineno)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.functions[node.func.id].append(node.lineno)

    def search_unsafe_transfer_errors(self):
        
        for line_num, line in enumerate(self.code.split('\n'), start=1):
            if 'transfer' in line.lower() and ('http://' in line.lower() or 'https://' in line.lower()):
                self.unsafe_transfers.append((line_num, line.strip()))

            if 'unsafe' in line.lower() and 'transfer' in line.lower():
                self.unsafe_transfers.append((line_num, line.strip()))

            if 'transfer' in line.lower() and 'user_input' in line.lower():
                self.unsafe_transfers.append((line_num, line.strip()))

    def search_double_free_errors(self):
        
        lines = self.code.split('\n')
        for i, line in enumerate(lines):
            if "free(" in line:
                # Look for the same memory address being freed again
                address = re.search(r'free\s*\(\s*([^)]+)\s*\)', line)
                if address:
                    address = address.group(1)
                    if lines[:i].count(address) > 1:
                        self.double_free_errors.append((i + 1, line.strip()))

    def detect_security_issues(self):
        
        # Initialize a list to store detected security issues
        self.security_issues = []

        # Detect potential SQL injection vulnerabilities
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and hasattr(node, 'func') and isinstance(node.func, ast.Name) and node.func.id == 'execute_sql':
                for arg in node.args:
                    if isinstance(arg, ast.Str):
                        if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE)\b', arg.s):
                            self.security_issues.append((node.lineno, f"Potential SQL injection vulnerability: {arg.s}"))

        # Detect potential cross-site scripting (XSS) vulnerabilities
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and hasattr(node, 'func') and isinstance(node.func, ast.Name) and node.func.id == 'print_html':
                for arg in node.args:
                    if isinstance(arg, ast.Str):
                        if '<script>' in arg.s:
                            self.security_issues.append((node.lineno, f"Potential XSS vulnerability: {arg.s}"))

    def analyze(self):
        
        self.audit_variables()
        self.audit_functions()
        self.search_unsafe_transfer_errors()
        self.search_double_free_errors()
        self.detect_security_issues()

    def report(self):
        
        report = []
        if self.variables:
            report.append('\nVariable usage:')
            for variable, lines in self.variables.items():
                report.append(f"Variable '{variable}' found on lines {', '.join(map(str, lines))}")
        if self.functions:
            report.append('\nFunction usage:')
            for function, lines in self.functions.items():
                report.append(f"Function '{function}' called on lines {', '.join(map(str, lines))}")
        if self.unsafe_transfers:
            report.append('\nUnsafe transfer errors:')
            for line_num, line in self.unsafe_transfers:
                report.append(f"Unsafe transfer error on line {line_num}: {line}")
        if self.double_free_errors:
            report.append('\nDouble free errors:')
            for line_num, line in self.double_free_errors:
                report.append(f"Double free error on line {line_num}: {line}")
        if self.security_issues:
            report.append('\nSecurity issues:')
            for line_num, issue in self.security_issues:
                report.append(f"Security issue on line {line_num}: {issue}")
        return '\n'.join(report)

# @app.route('/')
# def home():
#     return 'Welcome to the Python code auditor! To use this service, please POST your Python code to the "/audit" endpoint.'

@app.route('/', methods=['POST'])
def audit():
    code = request.get_data().decode('utf-8')
    auditor = CodeAuditor(code)
    auditor.analyze()
    report = auditor.report()
    return jsonify({'report': report})

if __name__ == '__main__':
    app.run(port=5000)
