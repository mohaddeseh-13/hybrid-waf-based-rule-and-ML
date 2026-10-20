"""
OWASP Top 10
LDAP Injection, Open Redirect, Path Traversal,
Command Injection, XXE, SSRF
"""

import re
from typing import Dict


class LDAPInjectionDetector:
    """LDAP Injection"""

    def detect(self, input_string: str) -> Dict:
        dangerous_chars = ['*', '(', ')', '\\', '|', '&']
        count = sum(1 for char in dangerous_chars if char in input_string)
        confidence = count * 0.2

        return {
            'is_attack': confidence >= 0.5,
            'confidence': min(confidence, 1.0),
            'attack_type': 'LDAP Injection',
            'detector': 'LDAP Detector'
        }


class OpenRedirectDetector:
    """Open Redirect"""

    def detect(self, input_string: str) -> Dict:
        indicators = ['http://', 'https://', '//', 'redirect=', 'url=']
        count = sum(1 for ind in indicators if ind in input_string.lower())
        confidence = count * 0.3

        return {
            'is_attack': confidence >= 0.5,
            'confidence': min(confidence, 1.0),
            'attack_type': 'Open Redirect',
            'detector': 'Open Redirect Detector'
        }


class PathTraversalDetector:
    """Path Traversal"""

    def __init__(self):
        self.patterns = [
            r'\.\.[/\\]',
            r'%2e%2e[/\\]',
            r'/etc/passwd',
            r'c:\\windows',
        ]

    def detect(self, input_string: str) -> Dict:
        confidence = 0.0

        for pattern in self.patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                confidence += 0.4

        return {
            'is_attack': confidence >= 0.5,
            'confidence': min(confidence, 1.0),
            'attack_type': 'Path Traversal',
            'detector': 'Path Traversal Detector'
        }


class CommandInjectionDetector:
    """Command Injection"""

    def __init__(self):
        self.patterns = [
            r'[;&|]\s*\w+',
            r'\$\(.+\)',
            r'`[^`]+`',
        ]

    def detect(self, input_string: str) -> Dict:
        confidence = 0.0

        for pattern in self.patterns:
            if re.search(pattern, input_string):
                confidence += 0.3

        return {
            'is_attack': confidence >= 0.5,
            'confidence': min(confidence, 1.0),
            'attack_type': 'Command Injection',
            'detector': 'Command Injection Detector'
        }


class XXEDetector:
    """XXE (XML External Entity)"""

    def detect(self, input_string: str) -> Dict:
        dangerous = ['<!ENTITY', 'SYSTEM', '<!DOCTYPE']
        count = sum(1 for d in dangerous if d in input_string.upper())
        confidence = count * 0.4

        return {
            'is_attack': confidence >= 0.5,
            'confidence': min(confidence, 1.0),
            'attack_type': 'XXE Injection',
            'detector': 'XXE Detector'
        }


class SSRFDetector:
    """SSRF (Server-Side Request Forgery)"""

    def detect(self, input_string: str) -> Dict:
        dangerous = [
            'localhost', '127.0.0.1', '0.0.0.0',
            'metadata', '169.254.169.254',
            '192.168.', '10.', '172.16.'
        ]

        count = sum(1 for d in dangerous if d in input_string.lower())
        confidence = count * 0.4

        return {
            'is_attack': confidence >= 0.5,
            'confidence': min(confidence, 1.0),
            'attack_type': 'SSRF',
            'detector': 'SSRF Detector'
        }
