from flask import Flask, render_template, request, jsonify
import hashlib
from PIL import Image
import io
import base64
import requests
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/hash', methods=['POST'])
def generate_hash():
    data = request.json
    text = data.get('text', '')
    result = hashlib.sha256(text.encode()).hexdigest()
    return jsonify({"output": result})

@app.route('/api/steganography/encode', methods=['POST'])
def steganography_encode():
    try:
        file = request.files['file']
        message = request.form['message']
        key = request.form['key']
        
        img = Image.open(file)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Simple encryption of message
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))
        encrypted_msg = fernet.encrypt(message.encode()).decode()
        
        # Hide message in LSB
        binary_msg = ''.join(format(ord(c), '08b') for c in encrypted_msg) + '1111111111111110'  # delimiter
        data = list(img.getdata())
        new_data = []
        msg_index = 0
        
        for pixel in data:
            new_pixel = list(pixel)
            for i in range(3):  # RGB
                if msg_index < len(binary_msg):
                    new_pixel[i] = (pixel[i] & ~1) | int(binary_msg[msg_index])
                    msg_index += 1
            new_data.append(tuple(new_pixel))
        
        img.putdata(new_data)
        
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        img_base64 = base64.b64encode(buf.getvalue()).decode()
        
        return jsonify({"success": True, "image": img_base64})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/steganography/decode', methods=['POST'])
def steganography_decode():
    try:
        file = request.files['file']
        key = request.form['key']
        
        img = Image.open(file)
        data = list(img.getdata())
        binary_msg = ''
        
        for pixel in data:
            for i in range(3):
                binary_msg += str(pixel[i] & 1)
        
        # Find delimiter
        delimiter = '1111111111111110'
        end_index = binary_msg.find(delimiter)
        if end_index == -1:
            return jsonify({"success": False, "error": "No hidden message found"})
        
        binary_msg = binary_msg[:end_index]
        encrypted_msg = ''.join(chr(int(binary_msg[i:i+8], 2)) for i in range(0, len(binary_msg), 8))
        
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))
        message = fernet.decrypt(encrypted_msg.encode()).decode()
        
        return jsonify({"success": True, "message": message})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/url_scan', methods=['POST'])
def url_scan():
    data = request.json
    url = data.get('url', '').lower()
    if not url:
        return jsonify({"error": "URL required"})
    
    score = 0
    results = {}
    
    # SSL Check
    is_https = url.startswith('https://')
    results['ssl'] = 'SECURE' if is_https else 'INSECURE'
    if not is_https:
        score += 50
    
    # Suspicious keywords
    suspicious = ['login', 'verify', 'banking', 'update-account', 'free-gift']
    has_bad_word = any(word in url for word in suspicious)
    results['keywords'] = 'SUSPICIOUS' if has_bad_word else 'CLEAN'
    if has_bad_word:
        score += 40
    
    risk = 'HIGH' if score > 60 else 'MEDIUM' if score > 0 else 'LOW'
    results['risk_score'] = f"{score}% ({risk})"
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
