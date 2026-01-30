import secrets
import string

def generate_password(length=16, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, use_special=True):
    """Generate a cryptographically secure random password"""
    
    # Build character pool based on options
    characters = ""
    
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    # If no character types selected, default to all
    if not characters:
        characters = string.ascii_letters + string.digits + string.punctuation
    
    # Generate password using secrets (cryptographically secure)
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    return password

def generate_multiple_passwords(count=5, length=16):
    """Generate multiple password options"""
    passwords = []
    for _ in range(count):
        passwords.append(generate_password(length))
    return passwords

# Test it
if __name__ == "__main__":
    print("Password Generator\n")
    
    # Ask user for preferences
    length = int(input("Password length (default 16): ") or 16)
    count = int(input("How many passwords to generate (default 5): ") or 5)
    
    print(f"\nGenerating {count} secure passwords of length {length}:\n")
    
    passwords = generate_multiple_passwords(count, length)
    for i, pwd in enumerate(passwords, 1):
        print(f"{i}. {pwd}")