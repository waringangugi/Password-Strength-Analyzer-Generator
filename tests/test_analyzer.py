"""Basic tests for password analyzer"""
from src.analyzer import analyze_password, get_strength_label, check_pwned_password

def test_weak_password():
    result = analyze_password("pass")
    assert result['length'] == 4
    assert get_strength_label(result['score']) == "Weak"

def test_strong_password():
    result = analyze_password("MyS3cur3P@ssw0rd!2024")
    assert result['length'] == 21
    assert get_strength_label(result['score']) == "Strong"
    assert result['has_uppercase'] == True
    assert result['has_lowercase'] == True
    assert result['has_digits'] == True
    assert result['has_special'] == True

def test_known_breach():
    is_pwned, count = check_pwned_password("password123")
    assert is_pwned == True
    assert count > 0

def test_unique_password():
    is_pwned, count = check_pwned_password("MyUn1qu3P@ssw0rd!XYZ999")
    assert is_pwned == False

if __name__ == "__main__":
    test_weak_password()
    test_strong_password()
    test_known_breach()
    test_unique_password()
    print("✓ All tests passed!")