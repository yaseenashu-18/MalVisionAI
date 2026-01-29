from flask import Flask, render_template, request, session, redirect, url_for, send_file, make_response, flash
import datetime, os, hashlib, math, joblib, io, secrets
import pandas as pd
import numpy as np
from flask_pymongo import PyMongo
from authlib.integrations.flask_client import OAuth
from bson.objectid import ObjectId
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import re

def clean_username(email):
    # Get everything before @, lowercase it, remove all non-alphanumeric chars
    raw = email.split('@')[0].lower()
    return re.sub(r'[^a-z0-9]', '', raw)

load_dotenv() # Load environment variables

app = Flask(__name__)
app.secret_key = "super_secret_static_key_for_dev_session_persistence"  # Static key for stability

# Allow OAuth over HTTP for local dev
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# --- CONFIGURATION ---
# Use a local DB fallback if no URI provided
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/malvision")
app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET")
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

# Email Config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Profile Upload Config
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads', 'profiles')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- INIT EXTENSIONS ---
mongo = PyMongo(app)
oauth = OAuth(app)
mail = Mail(app)

# --- Database Initialization (Startup) ---
with app.app_context():
    try:
        # Create unique index on email to prevent duplicates
        mongo.db.users.create_index("email", unique=True)
        print(" [INFO] Database: Unique index on 'email' verified/created.")
    except Exception as e:
        print(f" [WARNING] Database Index Error: {e}")
# ----------------------------------------

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={'scope': 'openid email profile'}
)

# ... (Rest of code)



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
    features_data = {}
    if model:
        # Create DataFrame with correct feature names to match training
        f = extract_features(text, size_mb)
        features_df = pd.DataFrame(f, columns=["length", "entropy", "num_chars", "spec_chars", "has_keyword", "size", "whitespace_ratio", "vowel_ratio"])
        
        prediction = model.predict(features_df)[0]
        result = "Malicious" if prediction == 1 else "Safe"
        
        # Save raw features for reporting
        features_data = {
            "Entropy": round(f[0][1], 2),
            "Non-Alphanumeric Ratio": round((f[0][3]/f[0][0])*100, 1) if f[0][0] > 0 else 0,
            "Key-Threat-Score": f[0][4],
            "Complexity-Index": f[0][0]
        }
        return result, features_data
    return "Safe", features_data

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
                
                result, diagnostics = detect_file(file.filename, size_bytes)
                
                scan_data.update({
                    "file": file.filename,
                    "result": result,
                    "type": "file",
                    "meta": file_info,
                    "diagnostics": diagnostics
                })

        elif "url" in request.form:
            url = request.form["url"]
            result, diagnostics = detect_url(url)
            file_info = {"name": url, "size": "N/A", "type": "URL", "hash": "N/A"}
            
            scan_data.update({
                "file": url,
                "result": result,
                "type": "url",
                "meta": file_info,
                "diagnostics": diagnostics
            })

        if result:
            # Save to MongoDB
            inserted_scan = mongo.db.scans.insert_one(scan_data)
            
            # Save to Session for Download Report (Linked to DB record)
            session['last_scan'] = {
                "id": str(inserted_scan.inserted_id),
                "file": scan_data['file'],
                "result": scan_data['result'],
                "time": str(scan_data['time']),
                "meta": file_info
            }

    # Clear session if starting new scan
    if request.args.get('new'):
        session.pop('last_scan', None)

    # GET Request: Check if we have a previous scan to show (e.g. returning from login)
    if request.method == "GET" and "last_scan" in session:
        last = session["last_scan"]
        result = last.get("result")
        file_info = last.get("meta")

    return render_template("scan.html", result=result, file_info=file_info, user=session.get('user'))

@app.route("/history")
def history():
    # History is now handled client-side (sessionStorage) for anonymity
    return render_template("history.html", scans=[], user=session.get('user'))

@app.route("/about")
def about():
    return render_template("about.html", user=session.get('user'))

# --- AUTH ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password')

        user = mongo.db.users.find_one({"email": email})

        if user and user.get("password_hash") and check_password_hash(user["password_hash"], password):
            # Ensure user has a username (for legacy accounts)
            username = user.get('username')
            if not username:
                username = clean_username(user['email'])
                mongo.db.users.update_one({"_id": user['_id']}, {"$set": {"username": username}})
            
            # Login successful
            session['user'] = {
                "name": user["name"],
                "email": user["email"],
                "username": username,
                "picture": user.get("picture", "https://cdn-icons-png.flaticon.com/512/1077/1077114.png")
            }
            # Redirect to previous page if set, else dashboard
            # Smart Redirect: Explicit intent > Recent Scan context > Dashboard
            return_to = session.pop('return_to', None)
            if not return_to and 'last_scan' in session:
                return_to = 'scan_page'
            
            target = return_to if return_to else 'dashboard'
            try:
                dest = url_for(target)
            except:
                dest = url_for('dashboard')
            return redirect(dest)
        else:
            flash("Invalid email or password", "error")

    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password')

        if not name or not email or not password:
             flash("All fields are required", "error")
             return render_template("signup.html")

        # Check if user exists
        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            flash("User already exists with this email", "error")
        else:
            # Create new user
            hashed_password = generate_password_hash(password)
            username = clean_username(email)
            mongo.db.users.insert_one({
                "name": name,
                "email": email,
                "username": username,
                "password_hash": hashed_password,
                "created_at": datetime.datetime.now(),
                "picture": "https://cdn-icons-png.flaticon.com/512/1077/1077114.png"
            })
            flash("Account created! Please log in.", "success")
            return redirect(url_for('login'))

    return render_template("signup.html")

@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    try:
        token = google.authorize_access_token()
        print(f"GOOGLE TOKEN RECEIVED: {token}") # Debug print
        
        user_info = token.get('userinfo')
        print(f"USER INFO EXTRACTED: {user_info}") # Debug print

        if not user_info:
            # Fallback: try to fetch userinfo endpoint manually if not in token
            user_info = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
            print(f"USER INFO FETCHED MANUAL: {user_info}")

        if user_info:
            email = user_info['email'].lower().strip()
            username = clean_username(email)
            # Upsert User in MongoDB
            mongo.db.users.update_one(
                {"email": email},
                {"$set": {
                    "name": user_info['name'],
                    "email": email,
                    "username": username,
                    "picture": user_info['picture'],
                    "last_login": datetime.datetime.now()
                }},
                upsert=True
            )
            # Update session
            user_info['email'] = email
            user_info['username'] = username
            session['user'] = user_info
            print("SESSION USER SET SUCCESSFULLY")
            
            # Redirect to previous page if set, else dashboard
            # Smart Redirect: Explicit intent > Recent Scan context > Dashboard
            return_to = session.pop('return_to', None)
            if not return_to and 'last_scan' in session:
                return_to = 'scan_page'
            
            target = return_to if return_to else 'dashboard'
            try:
                dest = url_for(target)
            except:
                dest = url_for('dashboard')
            return redirect(dest)
        else:
            print("NO USER INFO FOUND")
            return redirect(url_for('dashboard'))
    except Exception as e:
        print(f"AUTH ERROR: {e}")
        flash(f"Authentication failed: {str(e)}", "error")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('dashboard'))

@app.route('/profile')
def profile_redirect():
    if 'user' in session:
        # Get clean username even if session has old one
        username = clean_username(session['user']['email'])
        return redirect(url_for('profile', username=username))
    return redirect(url_for('login'))

@app.route('/profile/<username>')
def profile(username):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Try to fetch user data by username
    user_db = mongo.db.users.find_one({"username": username})
    
    # Fallback: If not found by username, try cleaning the session user's email
    # This fixes issues for users who were logged in BEFORE the username cleanup
    if not user_db and clean_username(session['user']['email']) == username:
        user_db = mongo.db.users.find_one({"email": session['user']['email']})
        if user_db:
            # Update the DB to the new clean username format
            mongo.db.users.update_one({"_id": user_db['_id']}, {"$set": {"username": username}})
            # Also update session
            session['user']['username'] = username
            session.modified = True
            
    if not user_db:
        flash("User profile not found.", "error")
        return redirect(url_for('dashboard'))
        
    # Fetch user's personal history
    user_scans = list(mongo.db.scans.find({"user_id": user_db['email']}).sort("time", -1).limit(20))
    
    return render_template("profile.html", user_info=user_db, scans=user_scans, user=session.get('user'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    new_name = request.form.get('name')
    new_pic_url = request.form.get('picture_url')
    file = request.files.get('picture_file')
    
    update_data = {}
    if new_name:
        update_data['name'] = new_name
        # Update session name if present
        if 'user' in session:
            session['user']['name'] = new_name
        
    if file and file.filename != '':
        filename = secure_filename(f"{hashlib.md5(user_email.encode()).hexdigest()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        # Use web-accessible path
        update_data['picture'] = f"/static/uploads/profiles/{filename}"
        if 'user' in session:
            session['user']['picture'] = update_data['picture']
    elif new_pic_url:
        update_data['picture'] = new_pic_url
        if 'user' in session:
            session['user']['picture'] = new_pic_url

    if update_data:
        mongo.db.users.update_one({"email": user_email}, {"$set": update_data})
        flash("Profile updated successfully!", "success")
    
    return redirect(url_for('profile'))

import threading

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            print(" [BACKGROUND] Email sent successfully.")
        except Exception as e:
            print(f" [BACKGROUND] EMAIL ERROR: {e}")

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        print(f"\n [DEBUG] Forgot Password REQUEST for: '{email}'") 
        
        user = mongo.db.users.find_one({"email": email})
        if user:
            print(f" [DEBUG] SUCCESS: User found in DB (ID: {user.get('_id')})")
            
            # Generate a secure token
            token = secrets.token_urlsafe(32)
            mongo.db.users.update_one(
                {"email": email},
                {"$set": {
                    "reset_token": token,
                    "reset_token_expires": datetime.datetime.now() + datetime.timedelta(hours=1)
                }}
            )
            
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # --- ALWAYS PRINT LINK ---
            print("="*60)
            print(f" [DEBUG] LINK GENERATED: {reset_link}")
            print("="*60)
            # -------------------------
            
            # Send Email Synchronously (Blocking) so we know if it fails
            try:
                print(f" [DEBUG] Attempting to send email to {email}...")
                msg = Message(
                    subject="Password Reset Request - MalVisionAI",
                    recipients=[email],
                    body=f"Click the link to reset your password: {reset_link}\n\nIf you did not request this, please ignore this email."
                )
                mail.send(msg)
                print(f" [DEBUG] EMAIL SENT SUCCESSFULLY to {email}")
                flash(f"Reset link sent to {email}", "success")
            except Exception as e:
                print(f" [ERROR] EMAIL FAILED: {e}")
                flash(f"Error sending email. Please use the link printed in the terminal.", "error")

        else:
            print(f" [DEBUG] FAILURE: User '{email}' does NOT exist in the database.")
            # We still show success to the user (security best practice), but we know in logs it failed.
            flash("If an account exists, a reset link has been sent.", "success") 
            
        return redirect(url_for('login'))
        
    return render_template("forgot_password.html")

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # In a real app, you would send this to the admin email
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        # Log it for now
        print(f"CONTACT FORM: From {name} ({email}): {message}")
        flash("Message sent! We'll get back to you shortly.", "success")
        return redirect(url_for('contact'))
        
    return render_template("contact.html")

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = mongo.db.users.find_one({
        "reset_token": token,
        "reset_token_expires": {"$gt": datetime.datetime.now()}
    })
    
    if not user:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
             flash("Passwords do not match.", "error")
        else:
            hashed_password = generate_password_hash(password)
            mongo.db.users.update_one(
                {"_id": user['_id']},
                {"$set": {"password_hash": hashed_password}, "$unset": {"reset_token": "", "reset_token_expires": ""}}
            )
            flash("Password updated successfully! Please log in.", "success")
            return redirect(url_for('login'))

    return render_template("reset_password.html")

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

@app.route('/download_report_history/<scan_id>')
def download_report_history(scan_id):
    if 'user' not in session:
        flash("Please log in to download reports.", "info")
        return redirect(url_for('login'))
    
    scan = mongo.db.scans.find_one({"_id": ObjectId(scan_id), "user_id": session['user']['email']})
    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for('profile'))

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
    
    # Extract meta safely
    meta = scan.get('meta', {})
    scan_time = scan['time'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(scan['time'], 'strftime') else str(scan['time'])
    
    data = [
        ("Analysis Date", scan_time),
        ("Analyzed for", f"{user['name']} ({user['email']})"),
        ("Target File", scan['file']),
        ("File Hash (SHA-256)", meta.get('hash', 'N/A')),
        ("File Size", meta.get('size', 'N/A')),
        ("File Type", meta.get('type', 'N/A'))
    ]
    
    for key, value in data:
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(50, 8, key + ":", 0)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 8, value, 0, 1)
        
    pdf.ln(5)

    # Diagnostic Features Section
    diagnostics = scan.get('diagnostics', {})
    if diagnostics:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'AI Diagnostic Indicators', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        for key, val in diagnostics.items():
            pdf.set_font('Arial', 'B', 10)
            pdf.cell(50, 8, key + ":", 0)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 8, str(val), 0, 1)
        pdf.ln(5)
    
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    pdf.set_font('Arial', 'I', 9)
    pdf.multi_cell(0, 5, "Disclaimer: This automated report is generated by MalVision AI. While our advanced machine learning models (trained on 5,000+ samples) provide high accuracy, no security solution is 100% perfect. We recommend manual verification for critical systems.")
    
    buffer = io.BytesIO()
    pdf_output = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_output)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"MalVision_Report_{scan['result']}_{int(datetime.datetime.now().timestamp())}.pdf",
        mimetype='application/pdf'
    )

@app.route('/download_report')
def download_report():
    if 'last_scan' in session and 'id' in session['last_scan']:
        return redirect(url_for('download_report_history', scan_id=session['last_scan']['id']))
    
    flash("No recent scan found to download.", "error")
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
