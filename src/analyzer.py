import re
import hashlib
import requests
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

def check_pwned_password(password):
    """Check if password has been in a data breach using HaveIBeenPwned API"""
    
    # Hash the password with SHA-1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Split into first 5 chars and rest
    first5, tail = sha1_password[:5], sha1_password[5:]
    
    # Query the API with first 5 characters
    url = f'https://api.pwnedpasswords.com/range/{first5}'
    
    try:
        response = requests.get(url)
        
        if response.status_code != 200:
            return None, "Could not check breach database"
        
        # Check if our hash suffix appears in the response
        hashes = (line.split(':') for line in response.text.splitlines())
        
        for hash_suffix, count in hashes:
            if hash_suffix == tail:
                return True, int(count)
        
        return False, 0
        
    except requests.RequestException:
        return None, "Error connecting to breach database"

# Test it
if __name__ == "__main__":
    test_password = input("Enter a password to test: ")
    results = analyze_password(test_password)
    strength = get_strength_label(results['score'])
    
    print(f"\nPassword Analysis:")
    print(f"Length: {results['length']}")
    print(f"Strength: {strength}")
    print(f"Estimated crack time: {results['crack_time']}")
    
    # Check if password has been breached
    is_pwned, count = check_pwned_password(test_password)
    
    if is_pwned is None:
        print(f"Breach check: {count}")
    elif is_pwned:
        print(f"WARNING: This password has been found in {count:,} data breaches!")
    else:
        print("✓ This password has not been found in known data breaches")