#!/usr/bin/env python3
"""
YaraMan - YARA Rules Manager & File Scanner

A standalone Flask application for managing YARA rules and scanning files.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import json
import zipfile
import yara
import hashlib
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['YARA_RULES_FOLDER'] = 'yara_rules'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

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
    
    for filename in os.listdir(yara_folder):
        if filename.endswith(('.yar', '.yara')):
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
    
    for filename in os.listdir(yara_folder):
        if filename.endswith(('.yar', '.yara')):
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
                                'match_data': instance.matched_data.decode('utf-8', errors='replace')[:100]
                            } for instance in s.instances[:5]  # Limit to first 5 instances
                        ]
                    } for s in match.strings[:10]  # Limit to first 10 strings
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
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None

@app.route('/')
def index():
    """Main page"""
    return send_from_directory('.', 'index.html')

@app.route('/assets/<path:filename>')
def assets(filename):
    """Serve static assets"""
    return send_from_directory('assets', filename)

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
        if not filename.endswith(('.yar', '.yara')):
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
                    for zip_info in zip_file.infolist():
                        if zip_info.filename.endswith(('.yar', '.yara')) and not zip_info.is_dir():
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
        elif file.filename.lower().endswith(('.yar', '.yara')):
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
            return jsonify({'error': 'Invalid file type. Only .yar, .yara, and .zip files are allowed'}), 400
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/yara/rules/<filename>', methods=['DELETE'])
def delete_yara_rule(filename):
    """API endpoint to delete a YARA rule"""
    try:
        if not filename.endswith(('.yar', '.yara')):
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
    """Initialize the application directories"""
    if not os.path.exists(app.config['YARA_RULES_FOLDER']):
        os.makedirs(app.config['YARA_RULES_FOLDER'])
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize on startup
init_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)