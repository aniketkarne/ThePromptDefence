import math
import re
import binascii

class StructuralDetector:
    # Minimum decoded length before we treat an alphabet-only token as a real
    # encoded payload. Without this, plain-English words longer than 30 chars
    # (URLs, JWT secrets, hash-like IDs) decode to gibberish but still match the
    # base64/hex alphabet — see test_structural.py "regression" cases.
    _MIN_DECODED_LEN = 8
    # Decoded text must be at least this fraction alphabetic chars + spaces.
    # Real encoded payloads ("Ignore all previous instructions" -> base64)
    # decode to >90% letters+spaces; plain English matched as base64 decodes
    # to ~20-30% letters+spaces, mostly binary garbage.
    _MIN_ALPHA_RATIO = 0.5

    def __init__(self):
        # Thresholds
        self.entropy_threshold = 5.2 # Tuned slightly higher to avoid false positives on complex text
        self.base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
        self.hex_pattern = re.compile(r"^[0-9a-fA-F]+$")

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum(p * math.log(p) / math.log(2.0) for p in prob)
        return entropy

    @staticmethod
    def _looks_like_text(decoded: bytes) -> bool:
        """Reject decoded payloads that are mostly non-printable binary garbage.

        Real encoded payloads of injection phrases decode to readable English,
        which is mostly alphabetic chars + spaces. Plain English words that
        happen to match the base64/hex alphabet decode to gibberish — high
        ratio of non-printable / control / non-ascii-letter bytes.
        """
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if len(text) < StructuralDetector._MIN_DECODED_LEN:
            return False
        alpha = sum(1 for c in text if c.isalpha() or c == " ")
        return (alpha / len(text)) >= StructuralDetector._MIN_ALPHA_RATIO

    def check(self, prompt: str):
        """
        Returns: (is_injection, risk_score, category)
        """
        # Check 1: Base64/Hex (Specific checks first)
        # Look for suspicious long words
        words = prompt.split()
        for word in words:
            if len(word) > 30: # Long contiguous string
                if self.hex_pattern.match(word):
                    try:
                        decoded = bytes.fromhex(word)
                        if self._looks_like_text(decoded):
                            return True, 1.0, "Hex Encoding"
                    except ValueError:
                        pass

                if self.base64_pattern.match(word):
                    # Try to decode to see if it's valid
                    try:
                        # Add padding if missing just in case, though regex handles standard
                        missing_padding = len(word) % 4
                        if missing_padding:
                            word += '=' * (4 - missing_padding)
                        decoded = binascii.a2b_base64(word)
                        if self._looks_like_text(decoded):
                            return True, 1.0, "Base64 Obfuscation"
                    except binascii.Error:
                        pass

        # Check 2: High Entropy
        if len(prompt) > 16:
            entropy = self.calculate_entropy(prompt)
            if entropy > self.entropy_threshold:
                return True, min(entropy / 8.0, 1.0), "High Entropy/Obfuscation"

        return False, 0.0, None
