# Password Security Analyzer & Generator

A Python tool that analyzes password strength based on security best practices and generates cryptographically secure passwords.

## Current Features
- Password strength analysis based on:
  - Length requirements
  - Character complexity (uppercase, lowercase, digits, special characters)
  - Entropy calculation using zxcvbn library
  - Estimated crack time for offline attacks
- **Data breach detection via HaveIBeenPwned API**
  - Checks password against 600+ million breached passwords
  - Privacy-preserving k-anonymity implementation (only sends partial hash)
- Cryptographically secure password generation
  - Customizable length
  - Uses Python's secrets module for true randomness

## Installation

1. Clone the repository:
```bash
git clone https://github.com/waringangugi/Password-Strength-Analyzer-Generator.git
cd Password-Strength-Analyzer-Generator
```

2. Create and activate virtual environment:
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Mac/Linux:
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Analyze a Password
```bash
python src/analyzer.py
```
Enter a password when prompted to see its strength analysis and breach status.

### Generate Secure Passwords
```bash
python src/generator.py
```
Enter desired length and quantity when prompted.

### Run Tests
```bash
python tests/test_analyzer.py
```

## Example Output

### Password Analysis
```
Enter a password to test: password123
Password Analysis:
Length: 11
Strength: Medium
Estimated crack time: 2 hours
⚠️  WARNING: This password has been found in 2,384,028 data breaches!
```

```
Enter a password to test: Waringa&Ev3
Password Analysis:
Length: 11
Strength: Strong
Estimated crack time: 1 day
✓ This password has not been found in known data breaches
```

```
Enter a password to test: MyS3cur3P@ssw0rd!
Password Analysis:
Length: 16
Strength: Strong
Estimated crack time: centuries
✓ This password has not been found in known data breaches
```

### Password Generation
```
Password Generator
Password length (default 16): 16
How many passwords to generate (default 5): 3

Generating 3 secure passwords of length 16:
1. K8#mP@xQ2vL9$wNz
2. 7rT!yU3oI#pA5sD&
3. nM$4bV@cX8kL#1qW
```

## Security Concepts Demonstrated
- **Password Complexity**: Checking for multiple character types (uppercase, lowercase, digits, symbols)
- **Entropy Analysis**: Using industry-standard zxcvbn library to calculate password unpredictability
- **Crack Time Estimation**: Understanding real-world attack scenarios
- **K-Anonymity**: Privacy-preserving API integration with HaveIBeenPwned (only partial hash transmitted)
- **Threat Intelligence**: Integration with real-world breach databases
- **Cryptographic Randomness**: Using secrets module instead of pseudo-random generators


## Technologies Used
- Python 3.x
- requests - HTTP library for API calls
- zxcvbn - Password strength estimation
- secrets - Cryptographically secure random generation
- Regular expressions for pattern matching

## What I Learned
- Password security fundamentals and entropy analysis
- Privacy-preserving API integration (k-anonymity)
- Cryptographic best practices (using secrets vs random)
- Working with external security APIs
- Writing unit tests for security functions

## Resources
- [Detailed Security Concepts Documentation](docs/security_concepts.md)
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)