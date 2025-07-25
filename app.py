#!/usr/bin/env python3
"""
YaraMan - YARA Rules Manager & File Scanner

A standalone Flask application for managing YARA rules and scanning files.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, make_response
import os
import json
import zipfile
import yara
import hashlib
import sqlite3
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import configparser
import secrets
from datetime import timedelta

def load_config(config_file='app.conf'):
    """Load configuration from app.conf file with environment variable override"""
    config = configparser.ConfigParser()
    
    # Set default values
    defaults = {
        'application': {
            'debug': 'false',
            'host': '0.0.0.0',
            'port': '5002',
            'secret_key': 'yaraman-default-secret-key-change-in-production'
        },
        'directories': {
            'yara_rules_folder': 'yara_rules',
            'upload_folder': 'uploads'
        },
        'limits': {
            'max_content_length': '104857600',
            'max_string_instances': '5',
            'max_strings_per_match': '10',
            'max_match_data_length': '100'
        },
        'authentication': {
            'admin_username': 'admin',
            'admin_password': 'admin123'
        },
        'security': {
            'enable_cors': 'false',
            'allowed_origins': '',
            'file_extensions_yara': '.yar,.yara',
            'file_extensions_upload': ''
        },
        'logging': {
            'log_level': 'INFO',
            'log_file': '',
            'console_logging': 'true'
        },
        'scanning': {
            'compile_timeout': '30',
            'scan_timeout': '60',
            'chunk_size': '4096'
        }
    }
    
    # Load defaults first
    config.read_dict(defaults)
    
    # Load from config file if it exists
    if os.path.exists(config_file):
        config.read(config_file)
    
    # Environment variable overrides
    env_mappings = {
        'SECRET_KEY': ('application', 'secret_key'),
        'ADMIN_USERNAME': ('authentication', 'admin_username'),
        'ADMIN_PASSWORD': ('authentication', 'admin_password'),
        'YARA_RULES_FOLDER': ('directories', 'yara_rules_folder'),
        'UPLOAD_FOLDER': ('directories', 'upload_folder'),
        'DEBUG': ('application', 'debug'),
        'HOST': ('application', 'host'),
        'PORT': ('application', 'port')
    }
    
    for env_var, (section, key) in env_mappings.items():
        value = os.environ.get(env_var)
        if value:
            config.set(section, key, value)
    
    return config

# Load configuration
config = load_config()

app = Flask(__name__)
app.config['YARA_RULES_FOLDER'] = config.get('directories', 'yara_rules_folder')
app.config['UPLOAD_FOLDER'] = config.get('directories', 'upload_folder')
app.config['MAX_CONTENT_LENGTH'] = config.getint('limits', 'max_content_length')
app.config['SECRET_KEY'] = config.get('application', 'secret_key')
app.config['ADMIN_USERNAME'] = config.get('authentication', 'admin_username')
app.config['ADMIN_PASSWORD'] = config.get('authentication', 'admin_password')
app.config['DEBUG'] = config.getboolean('application', 'debug')
app.config['HOST'] = config.get('application', 'host')
app.config['PORT'] = config.getint('application', 'port')

# Additional config for scanning limits
app.config['MAX_STRING_INSTANCES'] = config.getint('limits', 'max_string_instances')
app.config['MAX_STRINGS_PER_MATCH'] = config.getint('limits', 'max_strings_per_match')
app.config['MAX_MATCH_DATA_LENGTH'] = config.getint('limits', 'max_match_data_length')
app.config['CHUNK_SIZE'] = config.getint('scanning', 'chunk_size')

def init_database():
    """Initialize SQLite database for user management"""
    db_path = 'yaraman.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create sessions table for complete server-side session management
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_valid BOOLEAN DEFAULT 1,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default admin user if none exists
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    admin_count = cursor.fetchone()[0]
    
    if admin_count == 0:
        admin_username = app.config['ADMIN_USERNAME']
        admin_password = app.config['ADMIN_PASSWORD']
        password_hash = generate_password_hash(admin_password)
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        ''', (admin_username, password_hash, 'admin'))
        
        print(f"Created default admin user: {admin_username}")
    
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    """Authenticate user against database"""
    conn = sqlite3.connect('yaraman.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, password_hash, role
        FROM users 
        WHERE username = ? AND role = 'admin'
    ''', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user[2], password):
        return {
            'id': user[0],
            'username': user[1],
            'role': user[3]
        }
    return None

def create_session(user_info, ip_address=None, user_agent=None):
    """Create a new server-side session"""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=24)  # 24 hour session
    
    conn = sqlite3.connect('yaraman.db')
    cursor = conn.cursor()
    
    # Invalidate all existing sessions for this user
    cursor.execute('''
        UPDATE user_sessions 
        SET is_valid = 0 
        WHERE user_id = ? AND is_valid = 1
    ''', (user_info['id'],))
    
    # Create new session with all user data stored server-side
    cursor.execute('''
        INSERT INTO user_sessions (
            session_id, user_id, username, role, expires_at, 
            ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, user_info['id'], user_info['username'], 
          user_info['role'], expires_at, ip_address, user_agent))
    
    # Update last login timestamp
    cursor.execute('''
        UPDATE users 
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (user_info['id'],))
    
    conn.commit()
    conn.close()
    
    return session_id

def get_session_data(session_id):
    """Get session data from server-side storage"""
    if not session_id:
        return None
    
    conn = sqlite3.connect('yaraman.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_id, username, role, expires_at, ip_address, user_agent
        FROM user_sessions
        WHERE session_id = ? 
        AND is_valid = 1 
        AND expires_at > CURRENT_TIMESTAMP
    ''', (session_id,))
    
    result = cursor.fetchone()
    
    if result:
        # Update last accessed time
        cursor.execute('''
            UPDATE user_sessions 
            SET last_accessed = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        
        conn.close()
        return {
            'user_id': result[0],
            'username': result[1],
            'role': result[2],
            'expires_at': result[3],
            'ip_address': result[4],
            'user_agent': result[5]
        }
    
    conn.close()
    return None

def invalidate_session(session_id):
    """Invalidate a specific session"""
    if not session_id:
        return
        
    conn = sqlite3.connect('yaraman.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE user_sessions 
        SET is_valid = 0 
        WHERE session_id = ?
    ''', (session_id,))
    
    conn.commit()
    conn.close()

def invalidate_user_sessions(user_id):
    """Invalidate all sessions for a user"""
    conn = sqlite3.connect('yaraman.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE user_sessions 
        SET is_valid = 0 
        WHERE user_id = ? AND is_valid = 1
    ''', (user_id,))
    
    conn.commit()
    conn.close()

def cleanup_expired_sessions():
    """Clean up expired sessions"""
    conn = sqlite3.connect('yaraman.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        DELETE FROM user_sessions 
        WHERE expires_at < CURRENT_TIMESTAMP OR is_valid = 0
    ''')
    
    conn.commit()
    conn.close()

def get_session_id():
    """Get session ID from request cookie"""
    return request.cookies.get('yaraman_session_id')

def set_session_cookie(response, session_id):
    """Set secure session cookie"""
    response.set_cookie(
        'yaraman_session_id',
        session_id,
        max_age=24*60*60,  # 24 hours
        httponly=True,     # Prevent JavaScript access
        secure=False,      # Set to True in production with HTTPS
        samesite='Lax'     # CSRF protection
    )
    return response

def clear_session_cookie(response):
    """Clear session cookie"""
    response.set_cookie(
        'yaraman_session_id',
        '',
        expires=0,
        httponly=True,
        secure=False,
        samesite='Lax'
    )
    return response

def admin_required(f):
    """Decorator to require admin authentication for YARA management endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = get_session_id()
        if not session_id:
            return jsonify({'error': 'Admin authentication required'}), 401
        
        # Get session data from server-side storage
        session_data = get_session_data(session_id)
        if not session_data or session_data['role'] != 'admin':
            return jsonify({'error': 'Admin authentication required'}), 401
        
        # Clean up expired sessions periodically
        cleanup_expired_sessions()
            
        return f(*args, **kwargs)
    return decorated_function

def validate_yara_rule(rule_content):
    """Validate YARA rule syntax"""
    try:
        yara.compile(source=rule_content)
        return True, None
    except yara.SyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def get_yara_rules():
    """Get list of available YARA rules"""
    rules = []
    yara_folder = app.config['YARA_RULES_FOLDER']
    
    if not os.path.exists(yara_folder):
        return rules
    
    allowed_extensions = tuple(ext.strip() for ext in config.get('security', 'file_extensions_yara').split(','))
    for filename in os.listdir(yara_folder):
        if filename.endswith(allowed_extensions):
            filepath = os.path.join(yara_folder, filename)
            try:
                stat = os.stat(filepath)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract rule names from content
                rule_names = []
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    line = line.strip()
                    if line.startswith('rule '):
                        # Handle both "rule name {" and "rule name\n{"
                        if '{' in line:
                            rule_name = line.split('rule ')[1].split()[0].rstrip('{').rstrip(':')
                        else:
                            rule_name = line.split('rule ')[1].split()[0].rstrip(':')
                        rule_names.append(rule_name)
                
                rules.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'rule_names': rule_names,
                    'rule_count': len(rule_names)
                })
            except Exception as e:
                rules.append({
                    'filename': filename,
                    'size': 0,
                    'modified': '',
                    'rule_names': [],
                    'rule_count': 0,
                    'error': str(e)
                })
    
    return sorted(rules, key=lambda x: x['filename'])

def compile_yara_rules():
    """Compile all YARA rules for scanning"""
    yara_folder = app.config['YARA_RULES_FOLDER']
    
    if not os.path.exists(yara_folder):
        return None
    
    all_rules_source = {}
    rule_count = 0
    compilation_errors = []
    
    allowed_extensions = tuple(ext.strip() for ext in config.get('security', 'file_extensions_yara').split(','))
    for filename in os.listdir(yara_folder):
        if filename.endswith(allowed_extensions):
            filepath = os.path.join(yara_folder, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Try to compile individual rule to validate it (including imports)
                    try:
                        yara.compile(source=content)
                        namespace = f"rules_{rule_count}"
                        all_rules_source[namespace] = content
                        rule_count += 1
                        print(f"Successfully added rule: {filename}")
                    except Exception as rule_error:
                        print(f"Error validating YARA rule {filename}: {rule_error}")
                        compilation_errors.append(f"{filename}: {str(rule_error)}")
                        
            except Exception as e:
                print(f"Error reading YARA rule {filename}: {e}")
                compilation_errors.append(f"{filename}: {str(e)}")
    
    if not all_rules_source:
        print("No valid YARA rules found for compilation")
        if compilation_errors:
            print("Compilation errors:")
            for error in compilation_errors:
                print(f"  - {error}")
        return None
    
    try:
        compiled_rules = yara.compile(sources=all_rules_source)
        print(f"Successfully compiled {len(all_rules_source)} YARA rule file(s)")
        if compilation_errors:
            print("Some rules were skipped:")
            for error in compilation_errors:
                print(f"  - {error}")
        return compiled_rules
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None

def scan_file_with_yara(file_path):
    """Scan a file with compiled YARA rules"""
    compiled_rules = compile_yara_rules()
    
    if not compiled_rules:
        return {
            'filename': os.path.basename(file_path),
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            'matches': [],
            'error': 'No YARA rules available for scanning'
        }
    
    try:
        # Get file info
        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)
        
        # Scan file
        matches = compiled_rules.match(filepath=file_path)
        
        # Format matches
        formatted_matches = []
        for match in matches:
            formatted_matches.append({
                'rule': match.rule,
                'tags': list(match.tags),
                'namespace': match.namespace,
                'meta': {key: value for key, value in match.meta.items()},
                'strings': [
                    {
                        'identifier': s.identifier,
                        'instances': [
                            {
                                'offset': instance.offset,
                                'matched_length': len(instance.matched_data),
                                'match_data': instance.matched_data.decode('utf-8', errors='replace')[:app.config['MAX_MATCH_DATA_LENGTH']]
                            } for instance in s.instances[:app.config['MAX_STRING_INSTANCES']]
                        ]
                    } for s in match.strings[:app.config['MAX_STRINGS_PER_MATCH']]
                ]
            })
        
        return {
            'filename': filename,
            'size': file_size,
            'matches': formatted_matches,
            'md5': get_file_hash(file_path, 'md5'),
            'sha256': get_file_hash(file_path, 'sha256')
        }
    
    except Exception as e:
        return {
            'filename': os.path.basename(file_path),
            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            'matches': [],
            'error': f"Scan error: {str(e)}"
        }

def get_file_hash(file_path, hash_type='sha256'):
    """Calculate file hash"""
    hash_func = hashlib.new(hash_type)
    try:
        with open(file_path, 'rb') as f:
            chunk_size = app.config['CHUNK_SIZE']
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None

@app.route('/')
@app.route('/<path:path>')
def index(path=''):
    """Main page - catch all routes for SPA"""
    # Serve API routes normally (they have their own handlers)
    if path.startswith('api/') or path.startswith('assets/'):
        # Let Flask handle 404 for missing API/asset routes
        from flask import abort
        abort(404)
    
    # Serve index.html for all other routes (SPA routing)
    return send_from_directory('.', 'index.html')

@app.route('/api/ui/admin-features')
def get_admin_features():
    """API endpoint to get admin UI features based on authentication"""
    session_id = get_session_id()
    admin_logged_in = False
    
    if session_id:
        session_data = get_session_data(session_id)
        if session_data and session_data['role'] == 'admin':
            admin_logged_in = True
    
    return jsonify({
        'show_upload_button': admin_logged_in,
        'show_delete_buttons': admin_logged_in,
        'show_admin_dropdown': admin_logged_in,
        'show_login_button': not admin_logged_in,
        'can_access_rules_page': admin_logged_in
    })

@app.route('/assets/<path:filename>')
def assets(filename):
    """Serve static assets"""
    return send_from_directory('assets', filename)

@app.route('/api/auth/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        user = authenticate_user(username, password)
        if user:
            # Get client info for session tracking
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
            user_agent = request.headers.get('User-Agent')
            
            # Create new server-side session
            session_id = create_session(user, ip_address, user_agent)
            
            # Create response with session cookie
            response = make_response(jsonify({'message': 'Login successful', 'admin': True}))
            response = set_session_cookie(response, session_id)
            
            return response
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def admin_logout():
    """Admin logout endpoint"""
    session_id = get_session_id()
    
    # Invalidate the session in database
    if session_id:
        invalidate_session(session_id)
    
    # Create response and clear session cookie
    response = make_response(jsonify({'message': 'Logout successful'}))
    response = clear_session_cookie(response)
    
    return response

@app.route('/api/auth/status')
def auth_status():
    """Check current authentication status"""
    session_id = get_session_id()
    admin_logged_in = False
    username = None
    
    if session_id:
        session_data = get_session_data(session_id)
        if session_data and session_data['role'] == 'admin':
            admin_logged_in = True
            username = session_data['username']
    
    return jsonify({
        'admin_logged_in': admin_logged_in,
        'username': username
    })

@app.route('/api/yara/rules')
def list_yara_rules():
    """API endpoint to list available YARA rules"""
    try:
        rules = get_yara_rules()
        return jsonify({'rules': rules})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/yara/rules/<filename>')
def get_yara_rule(filename):
    """API endpoint to get a specific YARA rule content"""
    try:
        allowed_extensions = tuple(ext.strip() for ext in config.get('security', 'file_extensions_yara').split(','))
        if not filename.endswith(allowed_extensions):
            return jsonify({'error': 'Invalid file extension'}), 400
        
        filepath = os.path.join(app.config['YARA_RULES_FOLDER'], filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'Rule file not found'}), 404
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({'filename': filename, 'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/yara/rules', methods=['POST'])
@admin_required
def upload_yara_rule():
    """API endpoint to upload YARA rule(s)"""
    try:
        # Handle file upload
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        yara_folder = app.config['YARA_RULES_FOLDER']
        if not os.path.exists(yara_folder):
            os.makedirs(yara_folder)
        
        results = []
        
        # Handle ZIP files
        if file.filename.lower().endswith('.zip'):
            try:
                with zipfile.ZipFile(file) as zip_file:
                    allowed_extensions = tuple(ext.strip() for ext in config.get('security', 'file_extensions_yara').split(','))
                    for zip_info in zip_file.infolist():
                        if zip_info.filename.endswith(allowed_extensions) and not zip_info.is_dir():
                            # Extract and validate YARA rule
                            rule_content = zip_file.read(zip_info).decode('utf-8')
                            is_valid, error = validate_yara_rule(rule_content)
                            
                            if is_valid:
                                # Save the rule file
                                rule_filename = secure_filename(os.path.basename(zip_info.filename))
                                rule_path = os.path.join(yara_folder, rule_filename)
                                
                                # Handle filename conflicts
                                counter = 1
                                original_filename = rule_filename
                                while os.path.exists(rule_path):
                                    name, ext = os.path.splitext(original_filename)
                                    rule_filename = f"{name}_{counter}{ext}"
                                    rule_path = os.path.join(yara_folder, rule_filename)
                                    counter += 1
                                
                                with open(rule_path, 'w', encoding='utf-8') as f:
                                    f.write(rule_content)
                                
                                results.append({
                                    'filename': rule_filename,
                                    'status': 'success',
                                    'message': 'Rule uploaded successfully'
                                })
                            else:
                                results.append({
                                    'filename': zip_info.filename,
                                    'status': 'error',
                                    'message': f'Invalid YARA rule: {error}'
                                })
            except zipfile.BadZipFile:
                return jsonify({'error': 'Invalid ZIP file'}), 400
            except Exception as e:
                return jsonify({'error': f'Error processing ZIP file: {str(e)}'}), 500
        
        # Handle single YARA rule files
        elif file.filename.lower().endswith(tuple(ext.strip() for ext in config.get('security', 'file_extensions_yara').split(','))):
            rule_content = file.read().decode('utf-8')
            is_valid, error = validate_yara_rule(rule_content)
            
            if is_valid:
                # Save the rule file
                rule_filename = secure_filename(file.filename)
                rule_path = os.path.join(yara_folder, rule_filename)
                
                # Handle filename conflicts
                counter = 1
                original_filename = rule_filename
                while os.path.exists(rule_path):
                    name, ext = os.path.splitext(original_filename)
                    rule_filename = f"{name}_{counter}{ext}"
                    rule_path = os.path.join(yara_folder, rule_filename)
                    counter += 1
                
                with open(rule_path, 'w', encoding='utf-8') as f:
                    f.write(rule_content)
                
                results.append({
                    'filename': rule_filename,
                    'status': 'success',
                    'message': 'Rule uploaded successfully'
                })
            else:
                results.append({
                    'filename': file.filename,
                    'status': 'error',
                    'message': f'Invalid YARA rule: {error}'
                })
        else:
            allowed_exts = config.get('security', 'file_extensions_yara')
            return jsonify({'error': f'Invalid file type. Only {allowed_exts} and .zip files are allowed'}), 400
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/yara/rules/<filename>', methods=['DELETE'])
@admin_required
def delete_yara_rule(filename):
    """API endpoint to delete a YARA rule"""
    try:
        allowed_extensions = tuple(ext.strip() for ext in config.get('security', 'file_extensions_yara').split(','))
        if not filename.endswith(allowed_extensions):
            return jsonify({'error': 'Invalid file extension'}), 400
        
        filepath = os.path.join(app.config['YARA_RULES_FOLDER'], filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'Rule file not found'}), 404
        
        os.remove(filepath)
        return jsonify({'message': 'Rule deleted successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def scan_files():
    """API endpoint to scan uploaded files with YARA rules"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No files selected'}), 400
        
        # Create upload directory if it doesn't exist
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        results = []
        
        for file in files:
            if file.filename == '':
                continue
            
            # Save uploaded file temporarily
            filename = secure_filename(file.filename)
            filepath = os.path.join(upload_folder, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
            file.save(filepath)
            
            try:
                # Scan the file
                scan_result = scan_file_with_yara(filepath)
                results.append(scan_result)
            except Exception as e:
                results.append({
                    'filename': filename,
                    'size': 0,
                    'matches': [],
                    'error': f"Scan failed: {str(e)}"
                })
            finally:
                # Clean up temporary file
                if os.path.exists(filepath):
                    os.remove(filepath)
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def init_app():
    """Initialize the application directories and database"""
    if not os.path.exists(app.config['YARA_RULES_FOLDER']):
        os.makedirs(app.config['YARA_RULES_FOLDER'])
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Initialize database
    init_database()

# Initialize on startup
init_app()

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], host=app.config['HOST'], port=app.config['PORT'])