"""
XSS (Cross-Site Scripting)
"""

import re
from typing import Dict
from html import unescape
from urllib.parse import unquote


class XSSDetector:
    """
    تشخیص حملات XSS
    """
    
    def __init__(self):
        '''paterns'''
        self.patterns = [
            # Script tags
            r"<script[^>]*>",
            r"</script>",
            
            # Event handlers
            r"on\w+\s*=",
            
            # JavaScript protocol
            r"javascript:",
            r"vbscript:",
            
            # Dangerous tags
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<svg[^>]*>",
            
            # Image with events
            r"<img[^>]*onerror",
            r"<img[^>]*onload",
            
            # Alert/Eval
            r"(alert|eval|prompt|confirm)\s*\(",
            
            # document.cookie
            r"document\.(cookie|write)",
        ]
    
    def detect(self, input_string: str) -> Dict:
        """تشخیص XSS"""
        if not input_string:
            return self._create_result(False, 0.0, "None")
        
        # Decode
        decoded = unquote(input_string)
        decoded = unescape(decoded)
        
        confidence = 0.0
        matched = []
        
        # بررسی الگوها
        for pattern in self.patterns:
            if re.search(pattern, decoded, re.IGNORECASE):
                matched.append(pattern)
                confidence += 0.3
        
        confidence = min(confidence, 1.0)
        is_attack = confidence >= 0.5
        
        return self._create_result(is_attack, confidence, 
                                   "XSS" if is_attack else "None")
    
    def _create_result(self, is_attack: bool, confidence: float, 
                       attack_type: str) -> Dict:
        return {
            'is_attack': is_attack,
            'confidence': round(confidence, 2),
            'attack_type': attack_type,
            'detector': 'XSS Detector'
        }