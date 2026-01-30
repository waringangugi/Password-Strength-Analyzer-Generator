# Password Security Analyzer

A Python tool that analyzes password strength based on security best practices and generates secure passwords.

## Current Features
- Password strength analysis based on:
  - Length requirements
  - Character complexity (uppercase, lowercase, digits, special characters)
  - Entropy calculation using zxcvbn library
  - Estimated crack time for offline attacks
- Cryptographically secure password generation
  - Customizable length
  - Uses Python's secrets module for true randomness

## Installation

1. Clone the repository:
```bash
git clone https://github.com/waringangugi/Password-Strength-Analyzer-Generator.git
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

Run the password analyzer:
```bash
python src/analyzer.py
```

Enter a password when prompted to see its strength analysis.

## Example Output
```
Enter a password to test: Waringa
Password Analysis:
Length: 7
Strength: Weak
Estimated crack time: 23 seconds
```
```
Enter a password to test: War1ng@Ev3!
Password Analysis:
Length: 11
Strength: Strong
Estimated crack time: 5 days
```
```
Enter a password to test: MyS3cur3P@ssw0rd!
Password Analysis:
Length: 16
Strength: Strong
Estimated crack time: centuries
```

## Usage

### Analyze a Password
Run the password analyzer:
```bash
python src/analyzer.py
```

### Generate Secure Passwords
Run the password generator:
```bash
python src/generator.py
```

Enter desired length and quantity when prompted.

## Security Concepts Demonstrated
- **Password Complexity**: Checking for multiple character types (uppercase, lowercase, digits, symbols)
- **Entropy Analysis**: Using industry-standard zxcvbn library to calculate password unpredictability
- **Crack Time Estimation**: Understanding real-world attack scenarios


## Technologies Used
- Python 3.x
- zxcvbn - Password strength estimation
- Regular expressions for pattern matching
