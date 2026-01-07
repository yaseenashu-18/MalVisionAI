import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import random
import string
import math

# 1. Feature Extraction Logic (Must match app.py)
def calculate_entropy(text):
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def extract_features(text, size_mb):
    # Features:
    # 1. Length
    # 2. Entropy (Randomness)
    # 3. Numeric Characters Count
    # 4. Special Characters Count
    # 5. Suspicious Keyword Presence (0 or 1)
    # 6. File Size (MB)
    
    length = len(text)
    entropy = calculate_entropy(text)
    num_chars = sum(c.isdigit() for c in text)
    spec_chars = sum(not c.isalnum() for c in text)
    
    keywords = ["virus", "malware", "botnet", "trojan", "worm", "spyware", "phishing", "evil", "attack", "hack"]
    has_keyword = 1 if any(k in text.lower() for k in keywords) else 0

    return [length, entropy, num_chars, spec_chars, has_keyword, size_mb]

# 2. Generate Synthetic Dataset
print("Generating synthetic dataset...")
data = []
labels = []

# Safe samples (Normal URLs/Files)
safe_examples = [
    "google.com", "facebook.com", "youtube.com", "amazon.com", "wikipedia.org",
    "index.html", "about_us.pdf", "report_final.docx", "styles.css", "main.js",
    "jquery.min.js", "bootstrap.css", "profile.jpg", "logo.png", "home.php",
    "my_vacation_photos_2023.zip", "project_proposal_draft_v2.docx",
    "invoice_january_2025.pdf", "setup_wizard.exe", "installer_v1.0.exe",
    "backup_data_archive.tar.gz", "family_video_birthday.mp4",
    "game_setup_installer.msi", "notes_math_class.txt"
]

# Malicious samples (High entropy, random strings, suspicious words)
malicious_examples = [
    "virus_installer.exe", "trojan_horse.bat", "malware_attack.sh",
    "http://suspicious-site.com/login.php?cmd=hack", "b4ad829cd02.exe",
    "x83j29d8.dll", "free-money-now.com/virus", "update_critical_virus.js",
    "eicar_test_file.txt", "evil_script.py", "botnet_setup.bin"
]

# Generate random variations
for _ in range(1000):
    # Safe
    base = random.choice(safe_examples)
    variation = base
    if random.random() > 0.5:
        variation = base + "".join(random.choices(string.ascii_letters + string.digits + "_-", k=random.randint(1, 15)))
    
    # Safe files can be extremely varied in size (0.01MB to 1000MB)
    size = random.uniform(0.01, 100.0) 
    
    data.append(extract_features(variation, size))
    labels.append(0) # 0 = Safe

    # Malicious
    base = random.choice(malicious_examples)
    variation = base + "".join(random.choices(string.ascii_letters + string.digits + "!@#$", k=random.randint(5, 10)))
    
    # Malicious scripts often small, but installers can be big.
    # We'll make them varied too, so size isn't the ONLY factor, but helps.
    size = random.uniform(0.01, 50.0) 

    data.append(extract_features(variation, size))
    labels.append(1) # 1 = Malicious

# Create DataFrame
df = pd.DataFrame(data, columns=["length", "entropy", "num_chars", "spec_chars", "has_keyword", "size"])
df['label'] = labels

# 3. Train Model
print("Training Random Forest Model...")
X = df.drop(columns=["label"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# 5. Save Model
joblib.dump(model, "malware_model.pkl")
print("Model saved as 'malware_model.pkl'")
