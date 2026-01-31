# Password Security Analyzer & Generator

A full-stack web application that analyzes password strength based on security best practices and generates cryptographically secure passwords. Built with Python Flask and deployed on Render.

## Live Demo
**[Try it here: https://your-app-name.onrender.com](https://your-app-name.onrender.com)**

> Note: Replace with your actual Render URL after deployment

## Features
- **Password Strength Analysis**
  - Length and character complexity checking
  - Entropy calculation using zxcvbn library
  - Real-time crack time estimation for offline attacks
- **Data Breach Detection via HaveIBeenPwned API**
  - Checks against 600+ million breached passwords
  - Privacy-preserving k-anonymity implementation (only sends partial hash)
- **Cryptographically Secure Password Generation**
  - Customizable length (8-128 characters)
  - Uses Python's secrets module for true randomness
- **Clean Web Interface**
  - Modern, responsive design
  - Real-time analysis results
  - No installation required for users

## Usage

### Web Interface (Recommended)
Simply visit the [live demo](https://your-app-name.onrender.com) and:
1. Enter a password to analyze its strength and check for breaches
2. Or generate a secure password with your desired length

### Command Line Interface

**Analyze a Password:**
```bash
python src/analyzer.py
```

**Generate Secure Passwords:**
```bash
python src/generator.py
```

**Run Tests:**
```bash
python tests/test_analyzer.py
```

### Password Analysis
The tool provides detailed feedback on password strength:
- Character composition (uppercase, lowercase, digits, symbols)
- Estimated crack time
- Breach detection status with count

### Password Generation
Generate cryptographically secure passwords with customizable length.

## Local Development

### Installation

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

4. Run the Flask app:
```bash
python app.py
```

5. Open your browser and navigate to `http://127.0.0.1:5000`

## Example Output (CLI)

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
- **Password Complexity**: Multi-factor character type validation
- **Entropy Analysis**: Industry-standard zxcvbn library implementation
- **Crack Time Estimation**: Real-world attack scenario modeling
- **K-Anonymity**: Privacy-preserving API integration (only partial hash transmitted)
- **Threat Intelligence**: Integration with real-world breach databases
- **Cryptographic Randomness**: Using secrets module vs pseudo-random generators

## Technologies Used
- **Backend**: Python 3.x, Flask, Gunicorn
- **Security Libraries**: 
  - zxcvbn - Password strength estimation
  - secrets - Cryptographically secure random generation
  - requests - HTTP library for API calls
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Deployment**: Render
- **API Integration**: HaveIBeenPwned API v3


## What I Learned
- Password security fundamentals and entropy analysis
- Privacy-preserving API integration using k-anonymity
- Cryptographic best practices (secrets vs random module)
- Flask web development and RESTful API design
- Deploying Python applications to production
- Writing unit tests for security-critical functions
- Full-stack development (Python backend + JavaScript frontend)

## Deployment
This application is deployed on Render using:
- **Gunicorn** as the production WSGI server
- **Python 3.11** runtime environment
- Automatic deployments from the main branch

To deploy your own instance:
1. Fork this repository
2. Sign up for [Render](https://render.com)
3. Create a new Web Service and connect your repo
4. Render will automatically detect and deploy the Flask app

## Resources
- [Detailed Security Concepts Documentation](docs/security_concepts.md)
- [HaveIBeenPwned API Documentation](https://haveibeenpwned.com/API/v3)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)


## Author
**Your Name**
- GitHub: [@waringangugi](https://github.com/waringangugi)
- Project Link: [https://github.com/waringangugi/Password-Strength-Analyzer-Generator](https://github.com/waringangugi/Password-Strength-Analyzer-Generator)