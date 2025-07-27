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
import re
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

def secure_path(path):
    """Secure a file path while preserving directory structure"""
    if not path:
        return ""
    
    # Normalize path separators to forward slashes
    path = path.replace('\\', '/')
    
    # Remove any leading/trailing slashes
    path = path.strip('/')
    
    # Split into components and secure each part
    parts = path.split('/')
    secured_parts = []
    
    for part in parts:
        # Skip empty parts and current/parent directory references
        if not part or part in ('.', '..'):
            continue
        
        # Secure each filename component individually
        secured_part = secure_filename(part)
        if secured_part:  # Only add non-empty parts
            secured_parts.append(secured_part)
    
    # Rejoin with forward slashes
    return '/'.join(secured_parts)

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
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
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
    
    # Create yara_rules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS yara_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            full_path TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add full_path column if it doesn't exist (for existing databases)
    cursor.execute('''
        PRAGMA table_info(yara_rules)
    ''')
    columns = [column[1] for column in cursor.fetchall()]
    if 'full_path' not in columns:
        cursor.execute('''
            ALTER TABLE yara_rules ADD COLUMN full_path TEXT DEFAULT ''
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

def add_yara_rule_to_db(filename, full_path):
    """Add a YARA rule to the database"""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO yara_rules (filename, full_path)
        VALUES (?, ?)
    ''', (filename, full_path))
    
    rule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return rule_id

def get_yara_rule_from_db(rule_id):
    """Get a YARA rule by ID from database"""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, full_path, created_at
        FROM yara_rules
        WHERE id = ?
    ''', (rule_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'id': result[0],
            'filename': result[1],
            'full_path': result[2],
            'created_at': result[3]
        }
    return None

def delete_yara_rule_from_db(rule_id):
    """Delete a YARA rule from database"""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        DELETE FROM yara_rules
        WHERE id = ?
    ''', (rule_id,))
    
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_all_yara_rules_from_db():
    """Get all YARA rules from database"""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, full_path, created_at
        FROM yara_rules
        ORDER BY filename
    ''')
    
    results = cursor.fetchall()
    conn.close()
    
    return [{
        'id': row[0],
        'filename': row[1],
        'full_path': row[2],
        'created_at': row[3]
    } for row in results]

def authenticate_user(username, password):
    """Authenticate user against database"""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
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
    
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
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
    
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
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
        
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
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
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
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
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yaraman.db')
    conn = sqlite3.connect(db_path)
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
    """Get list of available YARA rules from database"""
    rules = []
    db_rules = get_all_yara_rules_from_db()
    yara_folder = app.config['YARA_RULES_FOLDER']
    
    for db_rule in db_rules:
        # Use full_path for file operations
        filepath = os.path.join(yara_folder, db_rule['full_path']) if db_rule['full_path'] else os.path.join(yara_folder, db_rule['filename'])
        
        try:
            if os.path.exists(filepath):
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
                    'id': db_rule['id'],
                    'filename': db_rule['filename'],
                    'full_path': db_rule['full_path'],
                    'display_name': db_rule['filename'],  # Use filename as display name (just the filename, no path)
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'rule_names': rule_names,
                    'rule_count': len(rule_names)
                })
            else:
                # File exists in DB but not on filesystem
                rules.append({
                    'id': db_rule['id'],
                    'filename': db_rule['filename'],
                    'full_path': db_rule['full_path'],
                    'display_name': db_rule['filename'],
                    'size': 0,
                    'modified': '',
                    'rule_names': [],
                    'rule_count': 0,
                    'error': 'File not found on filesystem'
                })
        except Exception as e:
            rules.append({
                'id': db_rule['id'],
                'filename': db_rule['filename'],
                'full_path': db_rule['full_path'],
                'display_name': db_rule['filename'],
                'size': 0,
                'modified': '',
                'rule_names': [],
                'rule_count': 0,
                'error': str(e)
            })
    
    return sorted(rules, key=lambda x: x['display_name'])

def compile_yara_rules():
    """Compile all YARA rules for scanning"""
    yara_folder = app.config['YARA_RULES_FOLDER']
    
    if not os.path.exists(yara_folder):
        return None
    
    compilation_errors = []
    db_rules = get_all_yara_rules_from_db()
    
    # Build a dictionary of filepaths with proper namespace handling
    all_filepaths = {}
    old_cwd = os.getcwd()
    
    try:
        # Don't change working directory yet - first validate paths with absolute paths
        print(f"Processing {len(db_rules)} rules from database...")
        
        for i, db_rule in enumerate(db_rules):
            # Use full_path for file operations
            if db_rule['full_path']:
                relative_filepath = db_rule['full_path']
            else:
                relative_filepath = db_rule['filename']
            
            # Full absolute path to the file
            full_filepath = os.path.join(yara_folder, relative_filepath)
            
            if os.path.exists(full_filepath):
                try:
                    # Test compile individual rule first to validate
                    # Change to the specific directory where the rule is located
                    rule_dir = os.path.dirname(full_filepath)
                    if rule_dir and rule_dir != yara_folder:
                        test_cwd = os.getcwd()
                        os.chdir(rule_dir)
                        # Use just the filename for compilation from its directory
                        yara.compile(filepath=os.path.basename(full_filepath))
                        os.chdir(test_cwd)
                        print(f"Successfully validated rule: {db_rule['filename']}")
                    else:
                        # If rule is in root yara folder, compile with relative path
                        yara.compile(filepath=relative_filepath)
                        print(f"Successfully validated rule: {db_rule['filename']}")
                    
                    # Add to compilation list using relative path from yara_folder
                    namespace = f"rules_{i}"
                    all_filepaths[namespace] = relative_filepath
                    
                except Exception as rule_error:
                    print(f"Error validating YARA rule {db_rule['filename']}: {rule_error}")
                    compilation_errors.append(f"{db_rule['filename']}: {str(rule_error)}")
            else:
                print(f"YARA rule file not found: {full_filepath}")
                compilation_errors.append(f"{db_rule['filename']}: File not found")
        
        if not all_filepaths:
            print("No valid YARA rules found for compilation")
            if compilation_errors:
                print("Compilation errors:")
                for error in compilation_errors:
                    print(f"  - {error}")
            return None
        
        # Final compilation of all valid rules
        # Change to yara rules folder for final compilation to resolve includes
        os.chdir(yara_folder)
        compiled_rules = yara.compile(filepaths=all_filepaths)
        print(f"Successfully compiled {len(all_filepaths)} YARA rule file(s)")
        
        if compilation_errors:
            print("Some rules were skipped:")
            for error in compilation_errors:
                print(f"  - {error}")
        
        return compiled_rules
        
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None
    finally:
        # Restore working directory
        os.chdir(old_cwd)

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

@app.route('/api/yara/rules/<int:rule_id>')
def get_yara_rule(rule_id):
    """API endpoint to get a specific YARA rule content by ID"""
    try:
        # Get rule from database
        db_rule = get_yara_rule_from_db(rule_id)
        if not db_rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Use full_path for file operations
        filepath = os.path.join(app.config['YARA_RULES_FOLDER'], db_rule['full_path']) if db_rule['full_path'] else os.path.join(app.config['YARA_RULES_FOLDER'], db_rule['filename'])
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Rule file not found on filesystem'}), 404
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return jsonify({
            'id': db_rule['id'],
            'filename': db_rule['filename'],
            'full_path': db_rule['full_path'],
            'display_name': db_rule['filename'],
            'content': content
        })
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
                    
                    # First pass: Extract all files to temporary locations
                    extracted_files = []
                    for zip_info in zip_file.infolist():
                        if zip_info.filename.endswith(allowed_extensions) and not zip_info.is_dir():
                            rule_content = zip_file.read(zip_info).decode('utf-8')
                            original_path = zip_info.filename
                            rule_filename = os.path.basename(original_path)
                            rule_full_path = secure_path(original_path)
                            rule_path = os.path.join(yara_folder, rule_full_path)
                            
                            # Create subdirectories if they don't exist
                            rule_dir = os.path.dirname(rule_path)
                            if rule_dir and not os.path.exists(rule_dir):
                                os.makedirs(rule_dir)
                            
                            # Handle filename conflicts
                            counter = 1
                            original_full_path = rule_full_path
                            original_filename = rule_filename
                            while os.path.exists(rule_path):
                                name, ext = os.path.splitext(original_filename)
                                rule_filename = f"{name}_{counter}{ext}"
                                dir_part = os.path.dirname(original_full_path)
                                rule_full_path = os.path.join(dir_part, rule_filename) if dir_part else rule_filename
                                rule_path = os.path.join(yara_folder, rule_full_path)
                                counter += 1
                            
                            # Write file to filesystem first
                            with open(rule_path, 'w', encoding='utf-8') as f:
                                f.write(rule_content)
                            
                            extracted_files.append({
                                'original_path': original_path,
                                'rule_filename': rule_filename,
                                'rule_full_path': rule_full_path,
                                'rule_path': rule_path,
                                'rule_content': rule_content
                            })
                    
                    # Second pass: Validate all extracted files (now includes will work)
                    for file_info in extracted_files:
                        try:
                            # Change to the file's directory for validation (to resolve includes)
                            old_cwd = os.getcwd()
                            rule_dir = os.path.dirname(file_info['rule_path'])
                            if rule_dir:
                                os.chdir(rule_dir)
                            
                            is_valid, error = validate_yara_rule(file_info['rule_content'])
                            
                            if is_valid:
                                # Add to database with filename and full_path
                                rule_id = add_yara_rule_to_db(file_info['rule_filename'], file_info['rule_full_path'])
                                
                                results.append({
                                    'id': rule_id,
                                    'filename': file_info['rule_filename'],
                                    'full_path': file_info['rule_full_path'],
                                    'status': 'success',
                                    'message': 'Rule uploaded successfully'
                                })
                            else:
                                # Remove the file if validation failed
                                if os.path.exists(file_info['rule_path']):
                                    os.remove(file_info['rule_path'])
                                
                                results.append({
                                    'filename': file_info['original_path'],
                                    'status': 'error',
                                    'message': f'Invalid YARA rule: {error}'
                                })
                        except Exception as e:
                            # Remove the file if validation failed
                            if os.path.exists(file_info['rule_path']):
                                os.remove(file_info['rule_path'])
                            
                            results.append({
                                'filename': file_info['original_path'],
                                'status': 'error',
                                'message': f'Validation error: {str(e)}'
                            })
                        finally:
                            # Restore working directory
                            os.chdir(old_cwd)
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
                rule_full_path = rule_filename  # For single files, full_path is same as filename
                rule_path = os.path.join(yara_folder, rule_filename)
                
                # Handle filename conflicts
                counter = 1
                original_filename = rule_filename
                while os.path.exists(rule_path):
                    name, ext = os.path.splitext(original_filename)
                    rule_filename = f"{name}_{counter}{ext}"
                    rule_full_path = rule_filename
                    rule_path = os.path.join(yara_folder, rule_filename)
                    counter += 1
                
                with open(rule_path, 'w', encoding='utf-8') as f:
                    f.write(rule_content)
                
                # Add to database with filename and full_path
                rule_id = add_yara_rule_to_db(rule_filename, rule_full_path)
                
                results.append({
                    'id': rule_id,
                    'filename': rule_filename,
                    'full_path': rule_full_path,
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

@app.route('/api/yara/rules/<int:rule_id>', methods=['DELETE'])
@admin_required
def delete_yara_rule(rule_id):
    """API endpoint to delete a YARA rule by ID"""
    try:
        # Get rule from database
        db_rule = get_yara_rule_from_db(rule_id)
        if not db_rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Use full_path for file operations
        filepath = os.path.join(app.config['YARA_RULES_FOLDER'], db_rule['full_path']) if db_rule['full_path'] else os.path.join(app.config['YARA_RULES_FOLDER'], db_rule['filename'])
        
        # Delete file if it exists
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Delete from database
        deleted = delete_yara_rule_from_db(rule_id)
        if deleted:
            return jsonify({'message': 'Rule deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete rule from database'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/yara/cleanup-orphaned', methods=['POST'])
@admin_required
def cleanup_non_existent_rules():
    """API endpoint to remove all non-existent YARA rules from database"""
    try:
        db_rules = get_all_yara_rules_from_db()
        yara_folder = app.config['YARA_RULES_FOLDER']
        
        removed_count = 0
        removed_rules = []
        
        for db_rule in db_rules:
            # Use full_path for file operations
            filepath = os.path.join(yara_folder, db_rule['full_path']) if db_rule['full_path'] else os.path.join(yara_folder, db_rule['filename'])
            
            # If file doesn't exist, remove from database
            if not os.path.exists(filepath):
                deleted = delete_yara_rule_from_db(db_rule['id'])
                if deleted:
                    removed_count += 1
                    removed_rules.append({
                        'id': db_rule['id'],
                        'filename': db_rule['filename'],
                        'full_path': db_rule['full_path']
                    })
        
        return jsonify({
            'message': f'Successfully removed {removed_count} non-existent rule(s) from database',
            'removed_count': removed_count,
            'removed_rules': removed_rules
        })
    
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