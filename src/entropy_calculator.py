"""
Entropy Calculator Module

This module provides mathematical entropy calculations for password strength analysis.
Entropy is measured in bits and represents the unpredictability of a password.

Higher entropy = harder to crack through brute force attacks.
"""

import math
import re
from typing import Dict, List, Tuple
from collections import Counter


class EntropyCalculator:
    """
    Calculate password entropy using various methods.
    
    Entropy is calculated based on the character pool size and password length.
    Formula: Entropy = log2(pool_size ^ length)
    """
    
    # Character pool sizes
    LOWERCASE_POOL = 26
    UPPERCASE_POOL = 26
    DIGITS_POOL = 10
    SPECIAL_POOL = 32  # Common special characters
    
    def __init__(self):
        """Initialize the entropy calculator"""
        self.calculation_history = []
    
    def calculate_shannon_entropy(self, password: str) -> float:
        """
        Calculate Shannon entropy of a password.
        
        Shannon entropy measures the average amount of information contained in each character.
        This is different from password entropy as it considers actual character distribution.
        
        Args:
            password (str): The password to analyze
            
        Returns:
            float: Shannon entropy in bits
            
        Example:
            >>> calc = EntropyCalculator()
            >>> calc.calculate_shannon_entropy("password")
            2.75
        """
        if not password:
            return 0.0
        
        # Count frequency of each character
        length = len(password)
        frequencies = Counter(password)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
    
    def calculate_password_entropy(self, password: str) -> Dict[str, float]:
        """
        Calculate password entropy based on character pool size.
        
        This is the standard entropy calculation used in password strength estimation.
        It assumes an attacker knows which character pools are used.
        
        Args:
            password (str): The password to analyze
            
        Returns:
            dict: Dictionary containing:
                - pool_size: Number of possible characters
                - entropy_bits: Entropy in bits
                - combinations: Total possible combinations
                
        Example:
            >>> calc = EntropyCalculator()
            >>> result = calc.calculate_password_entropy("P@ssw0rd")
            >>> result['entropy_bits']
            52.56
        """
        if not password:
            return {
                'pool_size': 0,
                'entropy_bits': 0.0,
                'combinations': 0
            }
        
        pool_size = self._calculate_pool_size(password)
        length = len(password)
        
        # Calculate entropy: log2(pool_size ^ length)
        entropy_bits = length * math.log2(pool_size)
        
        # Calculate total combinations
        combinations = pool_size ** length
        
        return {
            'pool_size': pool_size,
            'entropy_bits': round(entropy_bits, 2),
            'combinations': combinations,
            'length': length
        }
    
    def _calculate_pool_size(self, password: str) -> int:
        """
        Determine the character pool size based on password composition.
        
        Args:
            password (str): The password to analyze
            
        Returns:
            int: Total size of character pool
        """
        pool_size = 0
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            pool_size += self.LOWERCASE_POOL
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            pool_size += self.UPPERCASE_POOL
        
        # Check for digits
        if re.search(r'\d', password):
            pool_size += self.DIGITS_POOL
        
        # Check for special characters
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += self.SPECIAL_POOL
        
        return pool_size
    
    def calculate_ideal_entropy(self, length: int, use_all_pools: bool = True) -> float:
        """
        Calculate the ideal entropy for a password of given length.
        
        This represents the maximum possible entropy if all character pools are used.
        
        Args:
            length (int): Password length
            use_all_pools (bool): Whether to use all character types
            
        Returns:
            float: Ideal entropy in bits
        """
        if use_all_pools:
            pool_size = (self.LOWERCASE_POOL + self.UPPERCASE_POOL + 
                        self.DIGITS_POOL + self.SPECIAL_POOL)
        else:
            pool_size = self.LOWERCASE_POOL + self.UPPERCASE_POOL
        
        ideal_entropy = length * math.log2(pool_size)
        return round(ideal_entropy, 2)
    
    def get_entropy_strength(self, entropy_bits: float) -> str:
        """
        Convert entropy bits to a human-readable strength rating.
        
        Strength levels based on NIST guidelines:
        - < 28 bits: Very Weak
        - 28-35 bits: Weak
        - 36-59 bits: Reasonable
        - 60-127 bits: Strong
        - >= 128 bits: Very Strong
        
        Args:
            entropy_bits (float): Entropy in bits
            
        Returns:
            str: Strength rating
        """
        if entropy_bits < 28:
            return "Very Weak"
        elif entropy_bits < 36:
            return "Weak"
        elif entropy_bits < 60:
            return "Reasonable"
        elif entropy_bits < 128:
            return "Strong"
        else:
            return "Very Strong"
    
    def estimate_crack_time(self, entropy_bits: float, 
                           guesses_per_second: int = 1_000_000_000) -> Dict[str, str]:
        """
        Estimate time to crack password based on entropy.
        
        Args:
            entropy_bits (float): Entropy in bits
            guesses_per_second (int): Attack speed (default: 1 billion/sec for GPU)
            
        Returns:
            dict: Time estimates for different scenarios
        """
        # Calculate total possible combinations
        total_combinations = 2 ** entropy_bits
        
        # Average time to crack (on average, 50% of combinations need to be tried)
        average_seconds = (total_combinations / 2) / guesses_per_second
        
        # Worst case (100% of combinations)
        worst_seconds = total_combinations / guesses_per_second
        
        return {
            'average_case': self._format_time(average_seconds),
            'worst_case': self._format_time(worst_seconds),
            'combinations': f"{total_combinations:.2e}",
            'attack_speed': f"{guesses_per_second:,} guesses/second"
        }
    
    def _format_time(self, seconds: float) -> str:
        """
        Convert seconds to human-readable time format.
        
        Args:
            seconds (float): Time in seconds
            
        Returns:
            str: Formatted time string
        """
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
        elif seconds < 31536000:
            days = seconds / 86400
            return f"{days:.1f} days"
        elif seconds < 31536000 * 100:
            years = seconds / 31536000
            return f"{years:.1f} years"
        elif seconds < 31536000 * 1000:
            years = seconds / 31536000
            return f"{years:.0f} years"
        elif seconds < 31536000 * 1_000_000:
            years = seconds / 31536000
            return f"{years/1000:.1f} thousand years"
        elif seconds < 31536000 * 1_000_000_000:
            years = seconds / 31536000
            return f"{years/1_000_000:.1f} million years"
        else:
            years = seconds / 31536000
            return f"{years/1_000_000_000:.1f} billion years"
    
    def analyze_complete(self, password: str) -> Dict:
        """
        Perform complete entropy analysis on a password.
        
        Args:
            password (str): Password to analyze
            
        Returns:
            dict: Comprehensive entropy analysis
        """
        shannon = self.calculate_shannon_entropy(password)
        password_entropy = self.calculate_password_entropy(password)
        strength = self.get_entropy_strength(password_entropy['entropy_bits'])
        crack_time = self.estimate_crack_time(password_entropy['entropy_bits'])
        ideal = self.calculate_ideal_entropy(len(password))
        
        # Calculate efficiency (how close to ideal entropy)
        efficiency = (password_entropy['entropy_bits'] / ideal * 100) if ideal > 0 else 0
        
        result = {
            'shannon_entropy': shannon,
            'password_entropy': password_entropy['entropy_bits'],
            'ideal_entropy': ideal,
            'efficiency_percentage': round(efficiency, 1),
            'strength_rating': strength,
            'pool_size': password_entropy['pool_size'],
            'length': len(password),
            'crack_time_estimates': crack_time,
            'total_combinations': password_entropy['combinations']
        }
        
        # Store in history
        self.calculation_history.append({
            'password_length': len(password),
            'entropy': password_entropy['entropy_bits'],
            'strength': strength
        })
        
        return result
    
    def compare_passwords(self, passwords: List[str]) -> List[Dict]:
        """
        Compare entropy of multiple passwords.
        
        Args:
            passwords (list): List of passwords to compare
            
        Returns:
            list: Analysis for each password, sorted by strength
        """
        results = []
        
        for pwd in passwords:
            analysis = self.analyze_complete(pwd)
            analysis['password_preview'] = pwd[:3] + '*' * (len(pwd) - 3)
            results.append(analysis)
        
        # Sort by entropy (strongest first)
        results.sort(key=lambda x: x['password_entropy'], reverse=True)
        
        return results


def calculate_minimum_entropy_for_security_level(security_level: str) -> float:
    """
    Get minimum entropy required for different security levels.
    
    Args:
        security_level (str): One of 'low', 'medium', 'high', 'critical'
        
    Returns:
        float: Minimum entropy in bits
    """
    levels = {
        'low': 28,      # Basic protection
        'medium': 36,   # Standard user accounts
        'high': 60,     # Sensitive accounts
        'critical': 80  # High-value targets
    }
    
    return levels.get(security_level.lower(), 36)


# Example usage and testing
if __name__ == "__main__":
    print("=" * 60)
    print("PASSWORD ENTROPY ANALYZER")
    print("=" * 60)
    
    calc = EntropyCalculator()
    
    # Test passwords
    test_passwords = [
        "password",
        "P@ssw0rd",
        "MyP@ssw0rd2024!",
        "correct horse battery staple",
        "Tr0ub4dor&3",
        "xK8#mQ9$vL2@nP5!"
    ]
    
    print("\nAnalyzing test passwords:\n")
    
    for pwd in test_passwords:
        print(f"\nPassword: {pwd[:5]}{'*' * (len(pwd) - 5)}")
        print("-" * 60)
        
        analysis = calc.analyze_complete(pwd)
        
        print(f"Length: {analysis['length']} characters")
        print(f"Character Pool Size: {analysis['pool_size']}")
        print(f"Shannon Entropy: {analysis['shannon_entropy']} bits")
        print(f"Password Entropy: {analysis['password_entropy']} bits")
        print(f"Ideal Entropy: {analysis['ideal_entropy']} bits")
        print(f"Efficiency: {analysis['efficiency_percentage']}%")
        print(f"Strength Rating: {analysis['strength_rating']}")
        print(f"Avg. Crack Time: {analysis['crack_time_estimates']['average_case']}")
        print(f"Total Combinations: {analysis['crack_time_estimates']['combinations']}")
    
    print("\n" + "=" * 60)
    print("COMPARISON OF ALL PASSWORDS")
    print("=" * 60)
    
    comparison = calc.compare_passwords(test_passwords)
    
    print(f"\n{'Rank':<6} {'Password':<30} {'Entropy':<12} {'Strength'}")
    print("-" * 70)
    
    for i, result in enumerate(comparison, 1):
        print(f"{i:<6} {result['password_preview']:<30} "
              f"{result['password_entropy']:<12} {result['strength_rating']}")