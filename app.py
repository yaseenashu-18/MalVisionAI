from flask import Flask, render_template, request, session, redirect, url_for, send_file, make_response
import datetime, os, hashlib, math, joblib, io
import pandas as pd
import numpy as np
from flask_pymongo import PyMongo
from authlib.integrations.flask_client import OAuth
from bson.objectid import ObjectId
from dotenv import load_dotenv

load_dotenv() # Load environment variables

app = Flask(__name__)
app.secret_key = "super_secret_static_key_for_dev_session_persistence"  # Static key for stability

# --- CONFIGURATION ---
# Use a local DB fallback if no URI provided
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/malvision")
app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET")
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

# --- INIT EXTENSIONS ---
mongo = PyMongo(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={'scope': 'openid email profile'}
)

# Load ML Model
try:
    model = joblib.load("malware_model.pkl")
    print("AI Model Loaded Successfully")
except:
    print("Error: Model not found. Since this is a demo, we will proceed without it for now.")
    model = None

# --- ML HELPER FUNCTIONS ---
def calculate_entropy(text):
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

def extract_features(text, size_mb):
    length = len(text)
    entropy = calculate_entropy(text)
    num_chars = sum(c.isdigit() for c in text)
    spec_chars = sum(not c.isalnum() for c in text)
    keywords = ["virus", "malware", "botnet", "trojan", "worm", "spyware", "phishing", "evil", "attack", "hack", "eicar"]
    has_keyword = 1 if any(k in text.lower() for k in keywords) else 0
    return np.array([[length, entropy, num_chars, spec_chars, has_keyword, size_mb]])

def get_file_metadata(file):
    file.seek(0)
    content = file.read()
    file_size = len(content)
    file_hash = hashlib.sha256(content).hexdigest()
    file.seek(0)
    
    if file_size < 1024: size_str = f"{file_size} B"
    elif file_size < 1024 * 1024: size_str = f"{file_size/1024:.2f} KB"
    else: size_str = f"{file_size/(1024*1024):.2f} MB"
        
    return {"name": file.filename, "size": size_str, "type": file.content_type, "hash": file_hash}

def detect_malware(text, size_mb=0):
    if model:
        # Create DataFrame with correct feature names to match training
        features_data = extract_features(text, size_mb)
        features_df = pd.DataFrame(features_data, columns=["length", "entropy", "num_chars", "spec_chars", "has_keyword", "size"])
        
        prediction = model.predict(features_df)[0]
        return "Malicious" if prediction == 1 else "Safe"
    return "Safe"

def detect_file(filename, size_bytes):
    return detect_malware(filename, size_bytes / (1024 * 1024))

def detect_url(url):
    return detect_malware(url, 0)

# --- ROUTES ---

@app.route("/")
def dashboard():
    return render_template("dashboard.html", user=session.get('user'))

@app.route("/scan", methods=["GET", "POST"])
def scan_page():
    result = None
    file_info = None
    
    if request.method == "POST":
        scan_data = {
            "time": datetime.datetime.now(),
            "user_id": session.get('user', {}).get('email')  # Link to user if logged in
        }

        if "file" in request.files:
            file = request.files["file"]
            if file.filename != "":
                file_info = get_file_metadata(file)
                file.seek(0, 2)
                size_bytes = file.tell()
                file.seek(0)
                
                result = detect_file(file.filename, size_bytes)
                
                scan_data.update({
                    "file": file.filename,
                    "result": result,
                    "type": "file"
                })

        elif "url" in request.form:
            url = request.form["url"]
            result = detect_url(url)
            file_info = {"name": url, "size": "N/A", "type": "URL", "hash": "N/A"}
            
            scan_data.update({
                "file": url,
                "result": result,
                "type": "url"
            })

        if result:
            # Save to MongoDB
            mongo.db.scans.insert_one(scan_data)
            
            # Save to Session for Download Report
            session['last_scan'] = {
                "file": scan_data['file'],
                "result": scan_data['result'],
                "time": str(scan_data['time']),
                "meta": file_info
            }

    return render_template("scan.html", result=result, file_info=file_info, user=session.get('user'))

@app.route("/history")
def history():
    # Fetch from MongoDB
    scans = list(mongo.db.scans.find().sort("time", -1).limit(50))
    return render_template("history.html", scans=scans, user=session.get('user'))

@app.route("/about")
def about():
    return render_template("about.html", user=session.get('user'))

# --- AUTH ROUTES ---

@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    
    if user_info:
        # Upsert User in MongoDB
        mongo.db.users.update_one(
            {"email": user_info['email']},
            {"$set": {
                "name": user_info['name'],
                "picture": user_info['picture'],
                "last_login": datetime.datetime.now()
            }},
            upsert=True
        )
        session['user'] = user_info
        
    return redirect(url_for('download_report')) # Auto-redirect to download

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('dashboard'))

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    # Fetch user's personal history
    user_scans = list(mongo.db.scans.find({"user_id": user_email}).sort("time", -1).limit(20))
    
    return render_template("profile.html", user_info=session['user'], scans=user_scans, user=session.get('user'))

@app.route('/download_report')
def download_report():
    if 'user' not in session:
        # If not logged in, redirect to login
        # In a real app, maybe show a "Login Required" page, but we auto-redirect here
        return redirect(url_for('login'))
    
    if 'last_scan' not in session:
        # Instead of 404, maybe redirect to profile or dashboard
        return redirect(url_for('dashboard'))

    # Generate Report
    scan = session['last_scan']
    report_content = f"""
    MALVISION AI - THREAT DETECTION REPORT
    --------------------------------------
    Date: {scan['time']}
    User: {session['user']['name']} ({session['user']['email']})
    
    Target: {scan['file']}
    Result: {scan['result'].upper()}
    
    Metadata:
    {scan['meta']}
    
    --------------------------------------
    Generated by MalVisionAI
    """
    
    buffer = io.BytesIO()
    buffer.write(report_content.encode('utf-8'))
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"report_{scan['result']}_{int(datetime.datetime.now().timestamp())}.txt",
        mimetype='text/plain'
    )

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
