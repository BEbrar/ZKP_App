import hashlib
import os
from flask import Flask, request, jsonify, send_from_directory
from server.db import store_user, get_public_key
from server.constants import g, p
from client.proof_generator import generate_proof
from client.cli import user_registration
from server.verifier import verify_proof

app = Flask(__name__)

# Serve the Register Page
@app.route('/register', methods=['GET'])
def serve_register_page():
    return send_from_directory('fe', 'register.html')

# Serve the Login Page
@app.route('/login', methods=['GET'])
def serve_login_page():
    return send_from_directory('fe', 'login.html')

# Endpoint to handle user registration
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    y=user_registration(username,password)
    store_user(username, y)

    # Generate proof for user to copy
    c, s = generate_proof(password, y)
    return jsonify({
        "message": "Registration successful.",
        "challenge_c": hex(c),
        "proof_s": hex(s)
    })

# Endpoint to handle user login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    challenge_c_raw = request.form['challenge_c']
    proof_s_raw = request.form['proof_s']

    print(f"Debug: Received username = {username}, challenge_c = {challenge_c_raw}, proof_s = {proof_s_raw}")
    
    try:
        # Sanitize and convert challenge_c and proof_s to integers
        challenge_c_raw = request.form['challenge_c']
        proof_s_raw = request.form['proof_s']

        challenge_c = int(challenge_c_raw.replace('0x', '', 1), 16)  # Hex to int
        proof_s = int(proof_s_raw.replace('0x', '', 1), 16)

    except ValueError:
        return jsonify({"error": "Invalid proof format"}), 400

    # Fetch public key for the username
    y = get_public_key(username)
    if not y:
        return jsonify({"error": "User not found"}), 404

    # Convert y to integer
    y = int(y)

    # Verify proof
    if verify_proof(challenge_c, proof_s, y):
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"error": "Invalid proof!"}), 401

if __name__ == '__main__':
    app.run(debug=True)