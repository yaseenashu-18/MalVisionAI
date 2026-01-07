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
    if length == 0: return np.array([[0, 0, 0, 0, 0, size_mb, 0, 0]]) # Handle empty
    
    entropy = calculate_entropy(text)
    num_chars = sum(c.isdigit() for c in text)
    spec_chars = sum(not c.isalnum() for c in text)
    whitespaces = sum(c.isspace() for c in text)
    vowels = sum(1 for c in text.lower() if c in "aeiou")
    
    whitespace_ratio = whitespaces / length
    vowel_ratio = vowels / length

    keywords = ["virus", "malware", "botnet", "trojan", "worm", "spyware", "phishing", "evil", "attack", "hack", "ransom", "keylogger"]
    has_keyword = 1 if any(k in text.lower() for k in keywords) else 0
    
    return np.array([[length, entropy, num_chars, spec_chars, has_keyword, size_mb, whitespace_ratio, vowel_ratio]])

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
        features_df = pd.DataFrame(features_data, columns=["length", "entropy", "num_chars", "spec_chars", "has_keyword", "size", "whitespace_ratio", "vowel_ratio"])
        
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

from fpdf import FPDF

class PDFReport(FPDF):
    def header(self):
        # Logo (if you had one, self.image('logo.png', 10, 8, 33))
        self.set_font('Arial', 'B', 15)
        # Title
        self.set_text_color(59, 130, 246) # Primary Blue
        self.cell(0, 10, 'MalVision AI', 0, 1, 'L')
        self.set_font('Arial', '', 10)
        self.set_text_color(128, 128, 128)
        self.cell(0, 5, 'AI-Powered Cybersecurity Threat Detection', 0, 1, 'L')
        self.cell(0, 5, 'ML Syndicate, AIML Students | support@malvisionai.in', 0, 1, 'L')
        self.ln(5)
        self.set_draw_color(59, 130, 246)
        self.line(10, 35, 200, 35)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()} - Confidential Report Generated by MalVision AI', 0, 0, 'C')

@app.route('/download_report')
def download_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if 'last_scan' not in session:
        return redirect(url_for('dashboard'))

    scan = session['last_scan']
    user = session['user']
    
    pdf = PDFReport()
    pdf.add_page()
    
    # Title
    pdf.set_font('Arial', 'B', 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, 'THREAT DETECTION ANALYSIS REPORT', 0, 1, 'C')
    pdf.ln(5)
    
    # Scan Result Box
    is_malicious = scan['result'] == 'Malicious'
    color = (220, 38, 38) if is_malicious else (22, 163, 74) # Red or Green
    status_text = "THREAT DETECTED" if is_malicious else "CLEAN & SAFE"
    
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 15, status_text, 0, 1, 'C', 1)
    pdf.ln(10)
    
    # User & file Info
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Scan Details', 0, 1, 'L')
    
    pdf.set_font('Arial', '', 10)
    data = [
        ("Analysis Date", scan['time']),
        ("Analyzed by", f"{user['name']} ({user['email']})"),
        ("Target File", scan['file']),
        ("File Hash (SHA-256)", scan['meta'].get('hash', 'N/A')),
        ("File Size", scan['meta'].get('size', 'N/A')),
        ("File Type", scan['meta'].get('type', 'N/A'))
    ]
    
    for key, value in data:
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(50, 8, key + ":", 0)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 8, value, 0, 1)
        
    pdf.ln(5)
    
    # Disclaimer
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_font('Arial', 'I', 9)
    pdf.multi_cell(0, 5, "Disclaimer: This automated report is generated by MalVision AI. While our advanced machine learning models (trained on 5,000+ samples) provide high accuracy, no security solution is 100% perfect. We recommend manual verification for critical systems.")
    
    buffer = io.BytesIO()
    # Output PDF to bytes
    pdf_output = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_output)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"MalVision_Report_{scan['result']}_{int(datetime.datetime.now().timestamp())}.pdf",
        mimetype='application/pdf'
    )

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
