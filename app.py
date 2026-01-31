from flask import Flask, render_template, request, jsonify
from src.analyzer import analyze_password, get_strength_label, check_pwned_password
from src.generator import generate_password

app = Flask(__name__)

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze password strength"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    # Analyze the password
    results = analyze_password(password)
    strength = get_strength_label(results['score'])
    
    # Check if breached
    is_pwned, count = check_pwned_password(password)
    
    return jsonify({
        'length': results['length'],
        'strength': strength,
        'crack_time': results['crack_time'],
        'has_uppercase': results['has_uppercase'],
        'has_lowercase': results['has_lowercase'],
        'has_digits': results['has_digits'],
        'has_special': results['has_special'],
        'is_breached': is_pwned,
        'breach_count': count if is_pwned else 0
    })

@app.route('/generate', methods=['POST'])
def generate():
    """Generate secure password"""
    data = request.get_json()
    length = data.get('length', 16)
    
    try:
        length = int(length)
        if length < 8 or length > 128:
            return jsonify({'error': 'Length must be between 8 and 128'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid length'}), 400
    
    password = generate_password(length)
    
    return jsonify({'password': password})

if __name__ == '__main__':
    app.run(debug=True)