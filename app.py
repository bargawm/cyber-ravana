from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image, Image as PILImage
import io
import base64
import requests
from cryptography.fernet import Fernet
import os
import socket
import hashlib

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.after_request
def add_header(response):
    response.cache_control.max_age = 300  # 5 minutes cache
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/hash', methods=['POST'])
@limiter.limit("10 per minute")
def generate_hash():
    data = request.json
    text = data.get('text', '')
    result = hashlib.sha256(text.encode()).hexdigest()
    return jsonify({"output": result})

@app.route('/api/steganography/encode', methods=['POST'])
@limiter.limit("5 per minute")
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

@app.route('/api/cryptography/encrypt', methods=['POST'])
def encrypt_text():
    data = request.json
    text = data.get('text', '')
    key = data.get('key', '')
    if not text or not key:
        return jsonify({"error": "Text and key required"})
    
    fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))
    encrypted = fernet.encrypt(text.encode()).decode()
    return jsonify({"result": encrypted})

@app.route('/api/cryptography/decrypt', methods=['POST'])
def decrypt_text():
    data = request.json
    text = data.get('text', '')
    key = data.get('key', '')
    if not text or not key:
        return jsonify({"error": "Text and key required"})
    
    try:
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))
        decrypted = fernet.decrypt(text.encode()).decode()
        return jsonify({"result": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/forensics/metadata', methods=['POST'])
def forensics_metadata():
    file = request.files['file']
    if not file:
        return jsonify({"error": "File required"})
    
    filename = file.filename
    size = len(file.read())
    file.seek(0)  # reset
    
    metadata = {
        "filename": filename,
        "size": size,
        "type": filename.split('.')[-1] if '.' in filename else 'unknown'
    }
    
    # If image, get EXIF
    if metadata['type'].lower() in ['jpg', 'jpeg', 'png', 'tiff']:
        try:
            img = PILImage.open(file)
            exif = img._getexif()
            if exif:
                metadata['exif'] = str(exif)
        except:
            pass
    
    return jsonify(metadata)

@app.route('/api/url_scan', methods=['POST'])
def url_scan():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "URL required"})
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        ssl_secure = 'SECURE' if response.url.startswith('https') else 'INSECURE'
        
        # Check for suspicious content
        suspicious = ['password', 'login', 'bank', 'credit']
        keywords = 'CLEAN'
        if any(word in response.text.lower() for word in suspicious):
            keywords = 'SUSPICIOUS'
        
        risk_score = 'LOW RISK' if ssl_secure == 'SECURE' and keywords == 'CLEAN' else 'HIGH RISK'
        
        return jsonify({"ssl": ssl_secure, "keywords": keywords, "risk_score": risk_score})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/vulnerability/scan', methods=['POST'])
def vulnerability_scan():
    data = request.json
    target = data.get('target', '')
    if not target:
        return jsonify({"error": "Target required"})
    
    results = []
    try:
        # Simple port scan for common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                results.append(f"Port {port}: OPEN")
            else:
                results.append(f"Port {port}: CLOSED")
            sock.close()
    except Exception as e:
        results.append(f"Error: {str(e)}")
    
    return jsonify({"results": results})

@app.route('/api/password/strength', methods=['POST'])
def password_strength():
    data = request.json
    password = data.get('password', '')
    if not password:
        return jsonify({"error": "Password required"})
    
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    
    strength = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][score]
    return jsonify({"strength": strength})

@app.route('/api/malware/analyze', methods=['POST'])
def malware_analyze():
    file = request.files['file']
    if not file:
        return jsonify({"error": "File required"})
    
    content = file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Simple check against known bad hashes (placeholder)
    bad_hashes = ['badhash1', 'badhash2']  # In real, use a database
    if file_hash in bad_hashes:
        result = "MALICIOUS"
    else:
        result = "CLEAN"
    
    return jsonify({"hash": file_hash, "result": result})

@app.route('/api/osint/search', methods=['POST'])
def osint_search():
    data = request.json
    query = data.get('query', '')
    if not query:
        return jsonify({"error": "Query required"})
    
    try:
        # Simple IP lookup
        response = requests.get(f'http://ip-api.com/json/{query}', timeout=10)
        info = response.json()
        return jsonify({"results": str(info)})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
