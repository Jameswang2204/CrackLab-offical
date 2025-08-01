# app.py - CrackLab Flask Backend (Fixed Version)
# Educational Cybersecurity Tool for Password Security Learning

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
import os
import logging
import hashlib
import string
import itertools
import random
import math
import secrets

# ----- Flask & SocketIO setup -----
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'CRACKLAB_SECRET_KEY',
    'cracklab-educational-tool-2024'
)

# Initialize SocketIO BEFORE any handlers
socketio = SocketIO(app, cors_allowed_origins="*")

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----- Dashboard stats storage & routes -----
attack_stats = {
    "total_attempts": 0,
    "successful_cracks": 0,
    "total_crack_time": 0.0
}

@socketio.on('attack_result')
def on_attack_result(data):
    # data might contain fields like {'attempts': N, 'cracked': bool, 'time': float}
    attack_stats["total_attempts"] += data.get("attempts", 0)
    if data.get("cracked"):
        attack_stats["successful_cracks"] += 1
        attack_stats["total_crack_time"] += data.get("time", 0.0)

@app.route('/api/dashboard')
def get_dashboard():
    avg = (
        attack_stats["total_crack_time"] / attack_stats["successful_cracks"]
        if attack_stats["successful_cracks"] else 0
    )
    return jsonify({
        "totalAttempts": attack_stats["total_attempts"],
        "successfulCracks": attack_stats["successful_cracks"],
        "averageTime": round(avg, 2)
    })

# ----- Thread‑safe attack session management -----
attack_sessions = {}
attack_sessions_lock = threading.Lock()

# Constants
MAX_PASSWORD_LENGTH    = 128
MAX_ATTACK_DURATION    = 600    # seconds
BRUTE_FORCE_MAX_LENGTH = 10

# ----- PasswordAnalyzer & AttackSimulator classes -----
class PasswordAnalyzer:
    """Analyzes password strength and security"""
    def __init__(self):
        # Extended list of common passwords
        self.common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'welcome', 'login', 'guest', 'test', 'user', 'root',
            'pass', 'master', 'letmein', 'monkey', 'dragon', 'sunshine',
            '1234567', '12345678', '1234567890', 'football', 'iloveyou',
            'password1', 'welcome123', 'admin123', 'qwerty123', 'letmein123',
            'princess', 'computer', 'internet', 'hello', 'world', 'love',
            'money', 'freedom', 'whatever', 'nothing', 'something', 'anything',
            'baseball', 'dragon', 'football', 'monkey', 'shadow', 'master',
            'michael', 'superman', 'batman', 'trustno1', '000000', '111111',
            'access', 'jordan', 'password1', 'password123', '123123', 'qwertyuiop',
        ]
        self.common_passwords = list(dict.fromkeys(self.common_passwords))

        self.breach_counts = {
            'password': 9545824,
            '123456': 37304980,
            '123456789': 7870923,
            'qwerty': 3912816,
            'abc123': 2877297,
            'password123': 2335534,
            'admin': 1358134,
            'welcome': 486138,
            'letmein': 992515,
            '12345678': 2984937,
            'football': 354839,
            'iloveyou': 1653303
        }

    def analyze_strength(self, password):
        """Analyze password strength using multiple criteria"""
        if not password:
            return {
                "score": 0,
                "level": "Very Weak",
                "description": "No password entered",
                "feedback": {"warning": None, "suggestions": ["Enter a password to analyze"]},
                "entropy": 0,
                "guesses": 1,
                "charset_size": 0,
                "length": 0
            }
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Use at least 8 characters")
            
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        
        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        if has_lower:
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if has_upper:
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if has_digit:
            score += 1
        else:
            feedback.append("Add numbers")
            
        if has_symbol:
            score += 1
        else:
            feedback.append("Add symbols")
        
        # Common patterns (negative points)
        if password.lower() in self.common_passwords:
            score -= 3
            feedback.append("Avoid common passwords")
            
        # Repeated characters
        if len(password) >= 3 and any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)):
            score -= 1
            feedback.append("Avoid repeated characters")
        
        # Sequential patterns
        sequential_patterns = ['123', 'abc', 'qwe']
        if any(seq in password.lower() for seq in sequential_patterns):
            score -= 1
            feedback.append("Avoid sequential patterns")
        
        # Ensure score is within valid range 0-3
        score = max(0, min(3, score))
        
        strength_levels = [
            "Very Weak",
            "Weak", 
            "Good",
            "Strong"
        ]
        
        # Calculate entropy
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32
        
        if charset_size == 0:
            charset_size = 26  # Default to lowercase
            
        entropy = len(password) * math.log2(charset_size)
        guesses = charset_size ** len(password)
        
        return {
            "score": score,
            "level": strength_levels[score],
            "description": f"Password strength: {strength_levels[score]}",
            "feedback": {
                "warning": "This is a common password!" if password.lower() in self.common_passwords else None,
                "suggestions": feedback
            },
            "entropy": round(entropy, 2),
            "guesses": min(guesses, 1e18),  # Cap at 1 quintillion
            "charset_size": charset_size,
            "length": len(password)
        }

    def check_breaches(self, password):
        """Check if password appears in known breaches (simulated)"""
        if not password:
            return {
                "found": False,
                "count": 0,
                "message": "Enter a password to check"
            }
        
        lower_password = password.lower()
        
        # Check exact match first
        if lower_password in self.breach_counts:
            count = self.breach_counts[lower_password]
            return {
                "found": True,
                "count": count,
                "message": f"⚠️ This password has been found in {count:,} data breaches!"
            }
        
        # Check if it's in common passwords list
        elif lower_password in self.common_passwords:
            # Generate a realistic count for educational purposes
            count = random.randint(10000, 500000)
            return {
                "found": True,
                "count": count,
                "message": f"⚠️ This password has been found in {count:,} data breaches!"
            }
        else:
            return {
                "found": False,
                "count": 0,
                "message": "✅ This password was not found in common breaches (simulated check)"
            }

class AttackSimulator:
    """Simulates password cracking attacks"""
    def __init__(self):
        self.analyzer = PasswordAnalyzer()
        self.charset_lower = string.ascii_lowercase
        self.charset_upper = string.ascii_uppercase
        self.charset_digits = string.digits
        self.charset_symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'

    def get_charset(self, password):
        """Determine character set based on password"""
        charset = ''
        if any(c.islower() for c in password):
            charset += self.charset_lower
        if any(c.isupper() for c in password):
            charset += self.charset_upper
        if any(c.isdigit() for c in password):
            charset += self.charset_digits
        if any(c in self.charset_symbols for c in password):
            charset += self.charset_symbols
        
        if not charset:
            charset = self.charset_lower + self.charset_digits
            
        return charset

    def estimate_crack_time(self, password):
        """Estimate time to crack password"""
        if not password:
            return "-"
        
        charset_size = len(self.get_charset(password))
        password_length = len(password)
        
        # Calculate combinations
        total_combinations = sum(charset_size ** i for i in range(1, password_length + 1))
        
        # Assume 10 billion attempts per second
        seconds = total_combinations / 10_000_000_000
        
        if seconds < 0.001:
            return "Instant"
        elif seconds < 1:
            return f"{seconds*1000:.1f} milliseconds"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"

    def dictionary_attack(self, password, session_id):
        """Simulate dictionary attack"""
        start_time = time.time()
        attempts = 0
        
        with attack_sessions_lock:
            attack_sessions[session_id] = {
                'active': True,
                'type': 'dictionary',
                'start_time': start_time,
                'attempts': 0,
                'found': False
            }
        
        extended_list = self.analyzer.common_passwords.copy()
        
        socketio.emit('attack_info', {
            'message': f"🔍 Starting Dictionary Attack...\nTarget: \"{password}\"\nDictionary size: {len(extended_list)} passwords\n"
        }, room=session_id)
        
        for attempt in extended_list:
            # Check if attack should continue
            with attack_sessions_lock:
                if not attack_sessions.get(session_id, {}).get('active', False):
                    break
                    
            attempts += 1
            
            with attack_sessions_lock:  # Fixed: removed parentheses
                if session_id in attack_sessions:
                    attack_sessions[session_id]['attempts'] = attempts
            
            # Emit progress update
            if attempts % 10 == 0 or attempts == 1:
                socketio.emit('attack_progress', {
                    'type': 'dictionary',
                    'attempt': attempt,
                    'attempts': attempts,
                    'total': len(extended_list),
                    'time_elapsed': time.time() - start_time
                }, room=session_id)
            
            if attempt.lower() == password.lower():
                socketio.emit('attack_success', {
                    'type': 'dictionary',
                    'password': attempt,
                    'attempts': attempts,
                    'time_elapsed': time.time() - start_time
                }, room=session_id)
                return
            
            time.sleep(0.001)  # Simulate realistic speed
            
            if time.time() - start_time > MAX_ATTACK_DURATION:
                socketio.emit('attack_info', {
                    'message': "⏰ Attack timeout reached"
                }, room=session_id)
                break
        
        # Attack completed without finding password
        socketio.emit('attack_complete', {
            'type': 'dictionary',
            'found': False,
            'attempts': attempts,
            'time_elapsed': time.time() - start_time
        }, room=session_id)

    def brute_force_attack(self, password, session_id):
        """Simulate brute force attack"""
        start_time = time.time()
        attempts = 0
        charset = self.get_charset(password)
        found = False
        
        with attack_sessions_lock:
            attack_sessions[session_id] = {
                'active': True,
                'type': 'brute_force',
                'start_time': start_time,
                'attempts': 0,
                'found': False
            }
        
        charset_desc = []
        if any(c.islower() for c in password):
            charset_desc.append('lowercase')
        if any(c.isupper() for c in password):
            charset_desc.append('uppercase')
        if any(c.isdigit() for c in password):
            charset_desc.append('numbers')
        if any(c in self.charset_symbols for c in password):
            charset_desc.append('symbols')
        
        socketio.emit('attack_info', {
            'message': f"⚡ Starting Brute Force Attack...\nTarget: \"{password}\" ({len(password)} characters)\nCharacter set: {len(charset)} characters ({', '.join(charset_desc)})\n"
        }, room=session_id)
        
        # Try each length up to password length
        for length in range(1, min(len(password) + 1, BRUTE_FORCE_MAX_LENGTH + 1)):
            if found:
                break
                
            with attack_sessions_lock:
                if not attack_sessions.get(session_id, {}).get('active', False):
                    break
                    
            socketio.emit('attack_info', {
                'message': f"--- Trying length {length} ---"
            }, room=session_id)
            
            # Generate attempts for current length
            for attempt_tuple in itertools.product(charset, repeat=length):
                with attack_sessions_lock:
                    if not attack_sessions.get(session_id, {}).get('active', False):
                        break
                        
                attempt = ''.join(attempt_tuple)
                attempts += 1
                
                with attack_sessions_lock:  # Fixed: removed parentheses
                    if session_id in attack_sessions:
                        attack_sessions[session_id]['attempts'] = attempts
                
                # Emit progress based on attempt count
                emit_frequency = 10000 if attempts > 100000 else 1000 if attempts > 10000 else 100
                if attempts % emit_frequency == 0 or attempt == password:
                    socketio.emit('attack_progress', {
                        'type': 'brute_force',
                        'attempt': attempt,
                        'attempts': attempts,
                        'time_elapsed': time.time() - start_time,
                        'speed': int(attempts / (time.time() - start_time + 0.001))
                    }, room=session_id)
                
                if attempt == password:
                    found = True
                    with attack_sessions_lock:
                        if session_id in attack_sessions:
                            attack_sessions[session_id]['found'] = True
                            
                    socketio.emit('attack_success', {
                        'type': 'brute_force',
                        'password': attempt,
                        'attempts': attempts,
                        'time_elapsed': time.time() - start_time
                    }, room=session_id)
                    break
                
                # Brief delay every 10k attempts
                if attempts % 10000 == 0:
                    time.sleep(0.001)
                
                # Check timeout
                if time.time() - start_time > MAX_ATTACK_DURATION:
                    socketio.emit('attack_info', {
                        'message': "⏰ Attack timeout reached"
                    }, room=session_id)
                    return
        
        if not found:
            socketio.emit('attack_complete', {
                'type': 'brute_force',
                'found': False,
                'attempts': attempts,
                'time_elapsed': time.time() - start_time
            }, room=session_id)

# Instantiate
analyzer = PasswordAnalyzer()
simulator = AttackSimulator()

# ----- Flask routes & SocketIO event handlers -----
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    try:
        data = request.get_json()
        pw = data.get('password', '')
        
        if len(pw) > MAX_PASSWORD_LENGTH:
            return jsonify({'error': f'Password too long (max {MAX_PASSWORD_LENGTH}).'}), 400
            
        strength = analyzer.analyze_strength(pw)
        breach_info = analyzer.check_breaches(pw)
        ttc = simulator.estimate_crack_time(pw)
        
        return jsonify({
            'strength': strength,
            'breach_info': breach_info,
            'estimated_crack_time': ttc
        })
    except Exception as e:
        logger.error(f"/api/analyze error: {e}")
        return jsonify({'error': 'analysis failed'}), 500

@app.route('/api/breach', methods=['POST'])
def api_breach():
    try:
        data = request.get_json()
        pw = data.get('password', '')
        if len(pw) > MAX_PASSWORD_LENGTH:
            return jsonify({'error': f'Password too long (max {MAX_PASSWORD_LENGTH}).'}), 400
        return jsonify(analyzer.check_breaches(pw))
    except Exception as e:
        logger.error(f"/api/breach error: {e}")
        return jsonify({'error': 'breach failed'}), 500

@app.route('/api/hash', methods=['POST'])
def hash_password():
    """Generate hash for given text using specified algorithm"""
    try:
        data = request.get_json()
        text = data.get('password', '')  # Using 'password' to match frontend, but can hash any text
        algorithm = data.get('algorithm', 'md5').lower()
        
        if not text:
            return jsonify({'error': 'No text provided to hash'}), 400
            
        if len(text) > MAX_PASSWORD_LENGTH:
            return jsonify({'error': f'Text too long (max {MAX_PASSWORD_LENGTH} characters)'}), 400
        
        # Validate algorithm
        supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        if algorithm not in supported_algorithms:
            return jsonify({
                'error': f'Unsupported algorithm. Supported: {", ".join(supported_algorithms)}'
            }), 400
        
        # Generate hash
        hash_func = getattr(hashlib, algorithm)
        text_bytes = text.encode('utf-8')
        hash_result = hash_func(text_bytes).hexdigest()
        
        return jsonify({
            'algorithm': algorithm.upper(),
            'hash': hash_result,
            'input_length': len(text),
            'hash_length': len(hash_result)
        })
        
    except AttributeError:
        return jsonify({'error': 'Invalid algorithm specified'}), 400
    except Exception as e:
        logger.error(f"/api/hash error: {e}")
        return jsonify({'error': 'Hash generation failed'}), 500

@socketio.on('connect')
def on_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    with attack_sessions_lock:
        if sid in attack_sessions:
            attack_sessions[sid]['active'] = False
    logger.info(f"Client disconnected: {sid}")

@socketio.on('start_dictionary_attack')
def on_start_dict(data):
    pwd = data.get('password', '')
    if not pwd:
        emit('error', {'message': 'Password required'})
        return
    threading.Thread(
        target=simulator.dictionary_attack,
        args=(pwd, request.sid),
        daemon=True
    ).start()

@socketio.on('start_brute_force_attack')
def on_start_bruteforce(data):
    pwd = data.get('password', '')
    if not pwd:
        emit('error', {'message': 'Password required'})
        return
    if len(pwd) > BRUTE_FORCE_MAX_LENGTH:
        emit('error', {'message': f'Max {BRUTE_FORCE_MAX_LENGTH} characters for brute force'})
        return
    threading.Thread(
        target=simulator.brute_force_attack,
        args=(pwd, request.sid),
        daemon=True
    ).start()

@socketio.on('stop_attack')
def on_stop_attack():
    sid = request.sid
    with attack_sessions_lock:
        if sid in attack_sessions:
            attack_sessions[sid]['active'] = False
    emit('attack_stopped', {'message': 'Attack stopped by user'})

# ----- New: Personalized Passphrase endpoint -----
@app.route('/api/generate_personal', methods=['POST'])
def generate_personal():
    data = request.get_json()
    cues = [
        data.get('place', '').strip(),
        data.get('pet', '').strip(),
        data.get('num', '').strip(),
        data.get('hobby', '').strip()
    ]
    if any(not c for c in cues):
        return jsonify({'error': 'All four cues are required.'}), 400

    def transform(s):
        clean = ''.join(ch for ch in s if ch.isalnum())
        part = clean[:3].capitalize()
        code = max(len(clean) - 2, 0)
        return f"{part}{code}"

    parts = [transform(c) for c in cues]
    sep = secrets.choice(['-', '.', '_'])
    syms = '!@#$%^&*'
    secrets.SystemRandom().shuffle(parts)
    pwd = sep.join(parts) + secrets.choice(syms)

    return jsonify({'password': pwd})

# ----- Run server via SocketIO -----
if __name__ == '__main__':
    print("🔐 CrackLab Python Edition")
    print("=" * 50)
    print("Educational Cybersecurity Tool")
    print("Server starting...")
    print("Access the application at: http://localhost:5000")
    print("=" * 50)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

@app.route('/api/hash', methods=['POST'])
def hash_password():
    """Generate hash for given text using specified algorithm"""
    try:
        data = request.get_json()
        text = data.get('password', '')  # Using 'password' to match frontend, but can hash any text
        algorithm = data.get('algorithm', 'md5').lower()
        
        if not text:
            return jsonify({'error': 'No text provided to hash'}), 400
            
        if len(text) > MAX_PASSWORD_LENGTH:
            return jsonify({'error': f'Text too long (max {MAX_PASSWORD_LENGTH} characters)'}), 400
        
        # Validate algorithm
        supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        if algorithm not in supported_algorithms:
            return jsonify({
                'error': f'Unsupported algorithm. Supported: {", ".join(supported_algorithms)}'
            }), 400
        
        # Generate hash
        hash_func = getattr(hashlib, algorithm)
        text_bytes = text.encode('utf-8')
        hash_result = hash_func(text_bytes).hexdigest()
        
        return jsonify({
            'algorithm': algorithm.upper(),
            'hash': hash_result,
            'input_length': len(text),
            'hash_length': len(hash_result)
        })
        
    except AttributeError:
        return jsonify({'error': 'Invalid algorithm specified'}), 400
    except Exception as e:
        logger.error(f"/api/hash error: {e}")
        return jsonify({'error': 'Hash generation failed'}), 500

