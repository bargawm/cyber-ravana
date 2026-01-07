from flask import Flask, render_template, request, jsonify

app = Flask(_name_)

@app.route('/')
def index():
    # This serves your existing frontend
    return render_template('index.html')

@app.route('/api/hash', methods=['POST'])
def generate_hash():
    # Example: A logic "brick" for a Hashing Tool
    data = request.json
    text = data.get('text', '')
    # Your python logic here
    import hashlib
    result = hashlib.sha256(text.encode()).hexdigest()
    return jsonify({"output": result})

if _name_ == '_main_':
    app.run(debug=True)
