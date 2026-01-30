import re
from zxcvbn import zxcvbn

def analyze_password(password):
    """Analyze password strength and return results"""
    
    # Basic checks
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    # Calculate score
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1
    
    # Use zxcvbn for entropy analysis
    result = zxcvbn(password)
    
    return {
        'length': length,
        'has_uppercase': has_upper,
        'has_lowercase': has_lower,
        'has_digits': has_digit,
        'has_special': has_special,
        'score': score,
        'entropy_score': result['score'],  # 0-4 scale
        'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    }

def get_strength_label(score):
    """Convert score to strength label"""
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"

# Test it
if __name__ == "__main__":
    test_password = input("Enter a password to test: ")
    results = analyze_password(test_password)
    strength = get_strength_label(results['score'])
    
    print(f"\nPassword Analysis:")
    print(f"Length: {results['length']}")
    print(f"Strength: {strength}")
    print(f"Estimated crack time: {results['crack_time']}")