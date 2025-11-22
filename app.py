import os
import json
import tempfile
import shutil
import subprocess
from flask import Flask, request, jsonify, send_file
from obin_generator import generate_rust_obfuscation

app = Flask(__name__)

# Settings
USERS_FILE = "db/users.json"
ALLOWED_EXTENSIONS = {"exe"}

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/api/generator", methods=["POST"])
def generator():
    key = request.args.get("key")

    if not key:
        return jsonify({"error": "No key provided"}), 400

    users = load_users()
    if key not in users:
        return jsonify({"error": "Invalid API key"}), 403

    user_id = users[key]["id"]

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

        # Save the uploaded file to a temporary location
        uploaded_exe_path = os.path.join(build_dir, "original.exe")
        file.save(uploaded_exe_path)

        # 1. Obfuscate the user's uploaded file
        with open(uploaded_exe_path, 'rb') as f:
            user_exe_data = f.read()

        key_rs, payload_rs = generate_rust_obfuscation(user_exe_data)

        # 2. Prepare and compile the packer
        temp_packer_path = os.path.join(build_dir, "packer")
        shutil.copytree("templates/packer", temp_packer_path, ignore=shutil.ignore_patterns('target'))

        packer_main_path = os.path.join(temp_packer_path, "src", "main.rs")
        with open(packer_main_path, "r") as f:
            packer_code = f.read()

        packer_code = packer_code.replace("//Secret Key Here - replace", key_rs)
        packer_code = packer_code.replace("//Payload Here - replace", payload_rs)

        with open(packer_main_path, "w") as f:
            f.write(packer_code)

        try:
            subprocess.run(["cargo", "build", "--release"], cwd=temp_packer_path, check=True)
        except subprocess.CalledProcessError as e:
            return jsonify({"error": "Failed to build the packer", "details": str(e)}), 500

        # 3. Save the final executable
        user_exe_dir = f"stubs/{user_id}/exe"
        os.makedirs(user_exe_dir, exist_ok=True)

        final_exe_filename = f"{user_id}.exe"
        final_exe_path = os.path.join(user_exe_dir, final_exe_filename)
        built_packer_path = os.path.join(temp_packer_path, "target/release/output.exe")
        shutil.move(built_packer_path, final_exe_path)

        download_link = f"/api/download/{user_id}/{final_exe_filename}"

        return jsonify({
            "status": "success",
            "message": "File processed, obfuscated, and packed successfully.",
            "download_link": download_link
        })

@app.route("/api/download/<user_id>/<filename>", methods=["GET"])
def download_file(user_id, filename):
    users = load_users()
    # A simple check to see if the user exists.
    # A more robust system would check if the user actually owns this file.
    user_found = any(u['id'] == user_id for u in users.values())

    if not user_found:
        return jsonify({"error": "User not found"}), 404

    file_path = os.path.join("stubs", user_id, "exe", filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(file_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
