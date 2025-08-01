# api.py - CrackLab API Blueprint
# This version doesn't depend on the missing core.py module

from flask import Blueprint, request, jsonify
import hashlib
import string
import random
import secrets

api_bp = Blueprint('api', __name__)

# Common passwords for educational purposes
COMMON_PASSWORDS = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
    'admin', 'welcome', 'login', 'guest', 'test', 'user', 'root',
    'pass', 'master', 'letmein', 'monkey', 'dragon', 'sunshine'
]

# Simulated breach database
BREACH_COUNTS = {
    'password': 9545824,
    '123456': 37304980,
    '123456789': 7870923,
    'qwerty': 3912816,
    'abc123': 2877297,
    'password123': 2335534,
}

def analyze_strength(password):
    """Analyze password strength"""
    if not password:
        return {
            "score": 0,
            "level": "Very Weak",
            "description": "No password entered",
            "feedback": ["Enter a password to analyze"]
        }
    
    score = 0
    feedback = []
    
    # Length checks
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    
    if len(password) >= 12:
        score += 1
    
    # Character variety
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")
    
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1
    else:
        feedback.append("Add symbols")
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 2)
        feedback.append("Avoid common passwords")
    
    # Ensure score is within valid range
    score = max(0, min(3, score))
    
    levels = ["Very Weak", "Weak", "Good", "Strong"]
    
    return {
        "score": score,
        "level": levels[score],
        "description": f"Password strength: {levels[score]}",
        "feedback": feedback
    }

def breach_lookup(password):
    """Check if password appears in breach database"""
    if not password:
        return 0
    
    lower_password = password.lower()
    return BREACH_COUNTS.get(lower_password, 0)

def simulate_dictionary_crack(password_hash, hash_func='md5', wordlist=None):
    """Simulate dictionary attack (educational purposes)"""
    if wordlist is None:
        wordlist = COMMON_PASSWORDS
    
    # Get the hash function
    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    
    hasher = hash_funcs.get(hash_func, hashlib.md5)
    
    # Try each word in the wordlist
    for word in wordlist:
        if hasher(word.encode()).hexdigest() == password_hash:
            return word
    
    return None

def simulate_bruteforce_crack(password_hash, hash_func='md5', charset=None, max_length=4):
    """Simulate brute force attack (educational purposes)"""
    if charset is None:
        charset = string.ascii_lowercase
    
    # Get the hash function
    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    
    hasher = hash_funcs.get(hash_func, hashlib.md5)
    
    # Limit max_length for educational purposes
    max_length = min(max_length, 4)
    
    # Try all combinations up to max_length
    import itertools
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempt = ''.join(combo)
            if hasher(attempt.encode()).hexdigest() == password_hash:
                return attempt
    
    return None

def cracker_vs_defender(password, hash_func='sha1', method='dictionary', 
                       wordlist=None, charset=None, max_length=4):
    """Simulate attack game mode"""
    # Hash the password
    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    
    hasher = hash_funcs.get(hash_func, hashlib.sha1)
    password_hash = hasher(password.encode()).hexdigest()
    
    # Attempt to crack
    if method == 'dictionary':
        cracked = simulate_dictionary_crack(password_hash, hash_func, wordlist)
    else:
        cracked = simulate_bruteforce_crack(password_hash, hash_func, charset, max_length)
    
    # Analyze the password
    strength = analyze_strength(password)
    
    return {
        'cracked': cracked is not None,
        'cracked_password': cracked,
        'original_hash': password_hash,
        'method_used': method,
        'strength_score': strength['score'],
        'defender_won': cracked is None
    }

# API Routes
@api_bp.route('/analyze', methods=['POST'])
def analyze_route():
    """Analyze password strength"""
    try:
        pwd = request.json.get('password', '')
        if not pwd:
            return jsonify({'error': 'No password provided'}), 400
        
        if len(pwd) > 128:
            return jsonify({'error': 'Password too long. Maximum 128 characters.'}), 400
        
        result = analyze_strength(pwd)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/breach', methods=['POST'])
def breach_route():
    """Check password breach status"""
    try:
        pwd = request.json.get('password', '')
        if not pwd:
            return jsonify({'error': 'No password provided'}), 400
        
        if len(pwd) > 128:
            return jsonify({'error': 'Password too long. Maximum 128 characters.'}), 400
        
        count = breach_lookup(pwd)
        return jsonify({'count': count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/crack/dictionary', methods=['POST'])
def crack_dictionary():
    """Simulate dictionary crack"""
    try:
        data = request.json
        password_hash = data.get('hash', '')
        hash_func = data.get('hash_func', 'md5')
        wordlist = data.get('wordlist', COMMON_PASSWORDS)
        
        if not password_hash:
            return jsonify({'error': 'No hash provided'}), 400
        
        # Validate hash function
        if hash_func not in ['md5', 'sha1', 'sha256']:
            return jsonify({'error': 'Invalid hash function'}), 400
        
        cracked = simulate_dictionary_crack(password_hash, hash_func, wordlist)
        return jsonify({'cracked': cracked})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/crack/bruteforce', methods=['POST'])
def crack_bruteforce():
    """Simulate brute force crack"""
    try:
        data = request.json
        password_hash = data.get('hash', '')
        hash_func = data.get('hash_func', 'md5')
        charset = data.get('charset', string.ascii_lowercase)
        max_length = data.get('max_length', 4)
        
        if not password_hash:
            return jsonify({'error': 'No hash provided'}), 400
        
        # Validate inputs
        if hash_func not in ['md5', 'sha1', 'sha256']:
            return jsonify({'error': 'Invalid hash function'}), 400
        
        if max_length > 6:
            return jsonify({'error': 'Max length limited to 6 for educational purposes'}), 400
        
        cracked = simulate_bruteforce_crack(password_hash, hash_func, charset, max_length)
        return jsonify({'cracked': cracked})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/game', methods=['POST'])
def game_route():
    """Cracker vs Defender game mode"""
    try:
        data = request.json
        password = data.get('password', '')
        hash_func = data.get('hash_func', 'sha1')
        method = data.get('method', 'dictionary')
        wordlist = data.get('wordlist', COMMON_PASSWORDS)
        charset = data.get('charset', string.ascii_lowercase)
        max_length = data.get('max_length', 4)
        
        if not password:
            return jsonify({'error': 'No password provided'}), 400
        
        if len(password) > 128:
            return jsonify({'error': 'Password too long. Maximum 128 characters.'}), 400
        
        result = cracker_vs_defender(password, hash_func, method, wordlist, charset, max_length)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate_personal', methods=['POST'])
def generate_personal():
    data = request.get_json()
    cues = [
        data.get('place','').strip(),
        data.get('pet',  '').strip(),
        data.get('num',  '').strip(),
        data.get('hobby','').strip()
    ]
    if any(not c for c in cues):
        return jsonify({'error':'All four cues are required.'}), 400

    def transform(s):
        clean = ''.join(ch for ch in s if ch.isalnum())
        part = clean[:3].capitalize()
        length_code = max(len(clean)-2, 0)
        return f"{part}{length_code}"

    parts = [transform(c) for c in cues]
    sep = secrets.choice(['-','.','_'])
    symbols = '!@#$%^&*'
    secrets.SystemRandom().shuffle(parts)
    pwd = sep.join(parts) + secrets.choice(symbols)
    return jsonify({'password': pwd})