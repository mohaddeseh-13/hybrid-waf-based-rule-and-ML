"""
 SQL Injection
"""

import re
from typing import Dict, List
from urllib.parse import unquote


class SQLInjectionDetector:
    '''paterns'''
    def __init__(self):
        self.patterns = [
            # Union-based
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bUNION\b.*\bALL\b.*\bSELECT\b)",
            
            # Boolean-based
            r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(\bAND\b\s+\d+\s*=\s*\d+)",
            r"('\s*OR\s*'1'\s*=\s*'1)",
            r"('\s*OR\s*1\s*=\s*1)",
            
            # Comments
            r"(--|\#|\/\*)",
            r"(?i)\bOR\b\s+1\s*=\s*1",

            # Time-based
            r"(\bSLEEP\b\s*\(\d+\))",
            r"(\bWAITFOR\b\s+\bDELAY\b)",
            r"(\bBENCHMARK\b\s*\()",
            
            # Stacked queries
            r"(;\s*\bDROP\b)",
            r"(;\s*\bDELETE\b)",
            r"(;\s*\bUPDATE\b)",
            
            # Database enumeration
            r"(\bINFORMATION_SCHEMA\b)",
            r"(\bSYSOBJECTS\b)",
            
            # Hex encoding
            r"(0x[0-9a-fA-F]+)",
        ]
        
        # کلمات کلیدی SQL
        self.sql_keywords = [
            'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
            'CREATE', 'ALTER', 'EXEC', 'SLEEP', 'WAITFOR', 'BENCHMARK'
        ]
    
    def detect(self, input_string: str) -> Dict:
        """تشخیص SQL Injection"""
        if not input_string:
            return self._create_result(False, 0.0, [], "None")
        
        # URL decode
        decoded = unquote(input_string)
        upper_input = decoded.upper()
        
        matched_patterns = []
        confidence = 0.0
        
        # بررسی الگوها
        for pattern in self.patterns:
            if re.search(pattern, upper_input, re.IGNORECASE):
                matched_patterns.append(pattern)
                confidence += 0.3
        
        # بررسی کلمات کلیدی
        keyword_count = sum(1 for kw in self.sql_keywords if kw in upper_input)
        if keyword_count >= 2:
            confidence += 0.2 * keyword_count
        
        # محاسبه نهایی
        confidence = min(confidence, 1.0)
        is_attack = confidence >= 0.5
        
        return self._create_result(
            is_attack, confidence, matched_patterns, "SQL Injection" if is_attack else "None")
    
    def _create_result(self, is_attack: bool, confidence: float, 
                       patterns: List, attack_type: str) -> Dict:
        return {
            'is_attack': is_attack,
            'confidence': round(confidence, 2),
            'matched_patterns': patterns[:3],
            'attack_type': attack_type,
            'detector': 'SQL Injection Detector'
        }