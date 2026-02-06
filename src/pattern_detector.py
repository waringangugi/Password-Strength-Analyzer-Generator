"""
Pattern Detector Module

This module detects common password patterns and weaknesses that make passwords
easier to crack despite having good length or character diversity.

Patterns detected:
- Keyboard walks (qwerty, asdfgh, etc.)
- Sequential patterns (abc, 123, etc.)
- Repeated characters and sequences
- Common letter-to-number substitutions (leetspeak)
- Date patterns
- Common word patterns
"""

import re
from typing import Dict, List, Tuple, Set
from datetime import datetime


class PatternDetector:
    """
    Detect common patterns and weaknesses in passwords.
    
    This class identifies patterns that make passwords predictable or
    easier to crack using pattern-based attacks.
    """
    
    # Keyboard layout patterns (US QWERTY)
    KEYBOARD_ROWS = [
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm',
        '1234567890',
        '!@#$%^&*()'
    ]
    
    # Common keyboard walks (adjacent keys)
    KEYBOARD_WALKS = [
        'qwerty', 'asdfgh', 'zxcvbn',
        'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm', 'ik', 'ol', 'p',
        '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik', '9ol', '0p'
    ]
    
    # Common leetspeak substitutions
    LEET_SUBSTITUTIONS = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7'],
        'l': ['1'],
        'g': ['9'],
        'b': ['8'],
        'z': ['2']
    }
    
    # Common password patterns
    COMMON_PATTERNS = [
        'password', 'admin', 'welcome', 'login', 'user',
        'letmein', 'monkey', 'dragon', 'master', 'sunshine'
    ]
    
    def __init__(self):
        """Initialize the pattern detector"""
        self.detected_patterns = []
    
    def detect_all_patterns(self, password: str) -> Dict[str, any]:
        """
        Perform comprehensive pattern detection on a password.
        
        Args:
            password (str): Password to analyze
            
        Returns:
            dict: Dictionary containing all detected patterns and scores
        """
        self.detected_patterns = []
        
        results = {
            'keyboard_patterns': self.detect_keyboard_patterns(password),
            'sequential_patterns': self.detect_sequential_patterns(password),
            'repetition_patterns': self.detect_repetition_patterns(password),
            'leet_speak': self.detect_leet_speak(password),
            'date_patterns': self.detect_date_patterns(password),
            'common_words': self.detect_common_words(password),
            'character_patterns': self.analyze_character_patterns(password),
            'overall_score': 0,
            'pattern_count': 0,
            'warnings': []
        }
        
        # Calculate overall pattern score (0-100, higher is worse)
        pattern_score = self._calculate_pattern_score(results)
        results['overall_score'] = pattern_score
        results['pattern_count'] = len(self.detected_patterns)
        results['warnings'] = self._generate_warnings(results)
        
        return results
    
    def detect_keyboard_patterns(self, password: str) -> Dict[str, any]:
        """
        Detect keyboard walk patterns in password.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Information about keyboard patterns found
        """
        password_lower = password.lower()
        found_patterns = []
        
        # Check for keyboard rows
        for row in self.KEYBOARD_ROWS:
            for length in range(3, len(row) + 1):
                for start in range(len(row) - length + 1):
                    pattern = row[start:start + length]
                    if pattern in password_lower and len(pattern) >= 3:
                        found_patterns.append({
                            'type': 'keyboard_row',
                            'pattern': pattern,
                            'length': len(pattern),
                            'position': password_lower.index(pattern)
                        })
                        self.detected_patterns.append(f"Keyboard row: {pattern}")
        
        # Check for common keyboard walks
        for walk in self.KEYBOARD_WALKS:
            if walk in password_lower:
                found_patterns.append({
                    'type': 'keyboard_walk',
                    'pattern': walk,
                    'length': len(walk)
                })
                self.detected_patterns.append(f"Keyboard walk: {walk}")
        
        # Check for reversed patterns
        for row in self.KEYBOARD_ROWS:
            reversed_row = row[::-1]
            for length in range(3, len(reversed_row) + 1):
                for start in range(len(reversed_row) - length + 1):
                    pattern = reversed_row[start:start + length]
                    if pattern in password_lower and len(pattern) >= 3:
                        found_patterns.append({
                            'type': 'reversed_keyboard',
                            'pattern': pattern,
                            'length': len(pattern)
                        })
        
        return {
            'found': len(found_patterns) > 0,
            'patterns': found_patterns,
            'count': len(found_patterns)
        }
    
    def detect_sequential_patterns(self, password: str) -> Dict[str, any]:
        """
        Detect sequential characters (abc, 123, etc.).
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Information about sequential patterns
        """
        found_sequences = []
        password_lower = password.lower()
        
        # Check for alphabetic sequences (length 3+)
        for i in range(len(password_lower) - 2):
            # Forward sequence
            if (ord(password_lower[i+1]) == ord(password_lower[i]) + 1 and
                ord(password_lower[i+2]) == ord(password_lower[i]) + 2):
                
                # Extend the sequence
                seq_len = 3
                while (i + seq_len < len(password_lower) and
                       ord(password_lower[i + seq_len]) == ord(password_lower[i]) + seq_len):
                    seq_len += 1
                
                sequence = password_lower[i:i+seq_len]
                found_sequences.append({
                    'type': 'alphabetic_forward',
                    'sequence': sequence,
                    'length': seq_len,
                    'position': i
                })
                self.detected_patterns.append(f"Alphabetic sequence: {sequence}")
            
            # Backward sequence
            if (ord(password_lower[i+1]) == ord(password_lower[i]) - 1 and
                ord(password_lower[i+2]) == ord(password_lower[i]) - 2):
                
                seq_len = 3
                while (i + seq_len < len(password_lower) and
                       ord(password_lower[i + seq_len]) == ord(password_lower[i]) - seq_len):
                    seq_len += 1
                
                sequence = password_lower[i:i+seq_len]
                found_sequences.append({
                    'type': 'alphabetic_backward',
                    'sequence': sequence,
                    'length': seq_len,
                    'position': i
                })
                self.detected_patterns.append(f"Reverse alphabetic: {sequence}")
        
        # Check for numeric sequences
        for i in range(len(password) - 2):
            if password[i:i+3].isdigit():
                num1, num2, num3 = int(password[i]), int(password[i+1]), int(password[i+2])
                
                # Forward sequence
                if num2 == num1 + 1 and num3 == num2 + 1:
                    seq_len = 3
                    while (i + seq_len < len(password) and password[i+seq_len].isdigit() and
                           int(password[i+seq_len]) == int(password[i]) + seq_len):
                        seq_len += 1
                    
                    sequence = password[i:i+seq_len]
                    found_sequences.append({
                        'type': 'numeric_forward',
                        'sequence': sequence,
                        'length': seq_len,
                        'position': i
                    })
                    self.detected_patterns.append(f"Numeric sequence: {sequence}")
                
                # Backward sequence
                if num2 == num1 - 1 and num3 == num2 - 1:
                    seq_len = 3
                    while (i + seq_len < len(password) and password[i+seq_len].isdigit() and
                           int(password[i+seq_len]) == int(password[i]) - seq_len):
                        seq_len += 1
                    
                    sequence = password[i:i+seq_len]
                    found_sequences.append({
                        'type': 'numeric_backward',
                        'sequence': sequence,
                        'length': seq_len,
                        'position': i
                    })
                    self.detected_patterns.append(f"Reverse numeric: {sequence}")
        
        return {
            'found': len(found_sequences) > 0,
            'sequences': found_sequences,
            'count': len(found_sequences)
        }
    
    def detect_repetition_patterns(self, password: str) -> Dict[str, any]:
        """
        Detect repeated characters or sequences.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Information about repetition patterns
        """
        repetitions = []
        
        # Check for repeated single characters (aaa, 111, etc.)
        i = 0
        while i < len(password):
            char = password[i]
            count = 1
            
            while i + count < len(password) and password[i + count] == char:
                count += 1
            
            if count >= 3:
                repetitions.append({
                    'type': 'character_repetition',
                    'character': char,
                    'count': count,
                    'position': i
                })
                self.detected_patterns.append(f"Repeated character: '{char}' x{count}")
            
            i += count
        
        # Check for repeated sequences (abcabc, 123123, etc.)
        for seq_len in range(2, len(password) // 2 + 1):
            for i in range(len(password) - seq_len * 2 + 1):
                sequence = password[i:i+seq_len]
                if password[i+seq_len:i+seq_len*2] == sequence:
                    # Count how many times it repeats
                    repeat_count = 2
                    pos = i + seq_len * 2
                    while pos + seq_len <= len(password) and password[pos:pos+seq_len] == sequence:
                        repeat_count += 1
                        pos += seq_len
                    
                    if repeat_count >= 2:
                        repetitions.append({
                            'type': 'sequence_repetition',
                            'sequence': sequence,
                            'repeat_count': repeat_count,
                            'position': i
                        })
                        self.detected_patterns.append(
                            f"Repeated sequence: '{sequence}' x{repeat_count}"
                        )
                        break
        
        return {
            'found': len(repetitions) > 0,
            'repetitions': repetitions,
            'count': len(repetitions)
        }
    
    def detect_leet_speak(self, password: str) -> Dict[str, any]:
        """
        Detect common leetspeak substitutions.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Information about leetspeak usage
        """
        leet_chars_found = []
        
        for char_lower in password.lower():
            for letter, substitutes in self.LEET_SUBSTITUTIONS.items():
                if char_lower in substitutes and password[password.lower().index(char_lower)].isdigit() or \
                   password[password.lower().index(char_lower)] in ['@', '$', '!']:
                    leet_chars_found.append({
                        'original': letter,
                        'substitute': password[password.lower().index(char_lower)]
                    })
        
        # Check for common leet patterns
        leet_score = 0
        if re.search(r'[4@]', password):  # a -> 4/@
            leet_score += 1
        if re.search(r'3', password):  # e -> 3
            leet_score += 1
        if re.search(r'[1!]', password):  # i -> 1/!
            leet_score += 1
        if re.search(r'0', password):  # o -> 0
            leet_score += 1
        if re.search(r'[5$]', password):  # s -> 5/$
            leet_score += 1
        
        uses_leet = leet_score >= 2
        
        if uses_leet:
            self.detected_patterns.append("Uses leetspeak substitutions")
        
        return {
            'found': uses_leet,
            'leet_score': leet_score,
            'substitutions': leet_chars_found,
            'strength_reduction': leet_score * 5  # Percentage reduction in strength
        }
    
    def detect_date_patterns(self, password: str) -> Dict[str, any]:
        """
        Detect date patterns in password (birthdays, years, etc.).
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Information about date patterns
        """
        dates_found = []
        current_year = datetime.now().year
        
        # Check for 4-digit years (1900-2099)
        year_pattern = re.finditer(r'(19\d{2}|20\d{2})', password)
        for match in year_pattern:
            year = int(match.group())
            if 1900 <= year <= current_year + 10:
                dates_found.append({
                    'type': 'year',
                    'value': year,
                    'position': match.start()
                })
                self.detected_patterns.append(f"Year detected: {year}")
        
        # Check for date formats (MMDDYYYY, DDMMYYYY)
        date_patterns = [
            r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}',  # MMDDYYYY
            r'(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(19|20)\d{2}',  # DDMMYYYY
        ]
        
        for pattern in date_patterns:
            matches = re.finditer(pattern, password)
            for match in matches:
                dates_found.append({
                    'type': 'full_date',
                    'value': match.group(),
                    'position': match.start()
                })
                self.detected_patterns.append(f"Date pattern: {match.group()}")
        
        return {
            'found': len(dates_found) > 0,
            'dates': dates_found,
            'count': len(dates_found)
        }
    
    def detect_common_words(self, password: str) -> Dict[str, any]:
        """
        Detect common password base words.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Information about common words found
        """
        password_lower = password.lower()
        found_words = []
        
        for word in self.COMMON_PATTERNS:
            if word in password_lower:
                found_words.append({
                    'word': word,
                    'position': password_lower.index(word)
                })
                self.detected_patterns.append(f"Common word: {word}")
        
        return {
            'found': len(found_words) > 0,
            'words': found_words,
            'count': len(found_words)
        }
    
    def analyze_character_patterns(self, password: str) -> Dict[str, any]:
        """
        Analyze overall character distribution and patterns.
        
        Args:
            password (str): Password to analyze
            
        Returns:
            dict: Character pattern statistics
        """
        if not password:
            return {}
        
        # Character position patterns
        starts_with_upper = password[0].isupper()
        ends_with_digit = password[-1].isdigit()
        ends_with_special = not password[-1].isalnum()
        
        # Common pattern: Uppercase first, lowercase middle, digits/special at end
        follows_common_structure = (
            starts_with_upper and
            any(c.islower() for c in password[1:-2]) and
            (ends_with_digit or ends_with_special)
        )
        
        if follows_common_structure:
            self.detected_patterns.append(
                "Follows common structure: Upper+lower+digits/special"
            )
        
        # Check character clustering
        digit_positions = [i for i, c in enumerate(password) if c.isdigit()]
        special_positions = [i for i, c in enumerate(password) if not c.isalnum()]
        
        digits_clustered = len(digit_positions) > 1 and \
                          max(digit_positions) - min(digit_positions) < len(password) / 2
        
        specials_clustered = len(special_positions) > 1 and \
                            max(special_positions) - min(special_positions) < len(password) / 2
        
        return {
            'starts_with_uppercase': starts_with_upper,
            'ends_with_digit': ends_with_digit,
            'ends_with_special': ends_with_special,
            'follows_common_structure': follows_common_structure,
            'digits_clustered': digits_clustered,
            'specials_clustered': specials_clustered
        }
    
    def _calculate_pattern_score(self, results: Dict) -> int:
        """
        Calculate overall pattern score (0-100, higher is worse).
        
        Args:
            results (dict): Detection results
            
        Returns:
            int: Pattern score
        """
        score = 0
        
        # Keyboard patterns (20 points max)
        if results['keyboard_patterns']['found']:
            score += min(20, results['keyboard_patterns']['count'] * 10)
        
        # Sequential patterns (20 points max)
        if results['sequential_patterns']['found']:
            score += min(20, results['sequential_patterns']['count'] * 8)
        
        # Repetition patterns (15 points max)
        if results['repetition_patterns']['found']:
            score += min(15, results['repetition_patterns']['count'] * 7)
        
        # Leetspeak (10 points max)
        if results['leet_speak']['found']:
            score += min(10, results['leet_speak']['leet_score'] * 3)
        
        # Date patterns (15 points max)
        if results['date_patterns']['found']:
            score += min(15, results['date_patterns']['count'] * 10)
        
        # Common words (20 points max)
        if results['common_words']['found']:
            score += min(20, results['common_words']['count'] * 15)
        
        return min(100, score)
    
    def _generate_warnings(self, results: Dict) -> List[str]:
        """
        Generate human-readable warnings based on detected patterns.
        
        Args:
            results (dict): Detection results
            
        Returns:
            list: Warning messages
        """
        warnings = []
        
        if results['keyboard_patterns']['found']:
            warnings.append("⚠️ Contains keyboard pattern sequences")
        
        if results['sequential_patterns']['found']:
            warnings.append("⚠️ Contains sequential characters (abc, 123)")
        
        if results['repetition_patterns']['found']:
            warnings.append("⚠️ Contains repeated characters or sequences")
        
        if results['leet_speak']['found']:
            warnings.append("⚠️ Uses predictable leetspeak substitutions")
        
        if results['date_patterns']['found']:
            warnings.append("⚠️ Contains date or year information")
        
        if results['common_words']['found']:
            warnings.append("⚠️ Based on common password words")
        
        if results['character_patterns']['follows_common_structure']:
            warnings.append("⚠️ Follows predictable password structure")
        
        return warnings


# Example usage and testing
if __name__ == "__main__":
    print("=" * 70)
    print("PASSWORD PATTERN DETECTOR")
    print("=" * 70)
    
    detector = PatternDetector()
    
    # Test passwords with various patterns
    test_passwords = [
        "qwerty123",
        "Password1!",
        "abcd1234",
        "MyP@ssw0rd2024",
        "aaaaaa",
        "12345678",
        "Tr0ub4dor&3",
        "Welcome2024!",
        "asdfghjkl",
        "abc123xyz"
    ]
    
    print("\nAnalyzing passwords for patterns:\n")
    
    for pwd in test_passwords:
        print(f"\nPassword: {pwd}")
        print("-" * 70)
        
        results = detector.detect_all_patterns(pwd)
        
        print(f"Pattern Score: {results['overall_score']}/100 (higher = more patterns)")
        print(f"Patterns Found: {results['pattern_count']}")
        
        if results['warnings']:
            print("\nWarnings:")
            for warning in results['warnings']:
                print(f"  {warning}")
        
        if detector.detected_patterns:
            print("\nDetected Patterns:")
            for pattern in detector.detected_patterns[-5:]:  # Show last 5
                print(f"  • {pattern}")
        
        # Reset for next password
        detector.detected_patterns = []
    
    print("\n" + "=" * 70)