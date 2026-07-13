from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import joblib
import re
import sqlite3
from datetime import datetime
from markupsafe import escape

MODEL_PATH = 'model.pkl'
DB_PATH = 'predictions.db'

app = Flask(__name__)
CORS(app, resources={r"/predict": {"origins": "*"}})

# Initialize database with columns migration
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_text TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check table structure for updates
    c.execute("PRAGMA table_info(predictions)")
    columns = [col[1] for col in c.fetchall()]
    
    if 'model_used' not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN model_used TEXT DEFAULT 'nb'")
    if 'sender' not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN sender TEXT DEFAULT 'Unknown'")
    if 'risk_score' not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN risk_score INTEGER DEFAULT 0")
    if 'has_url' not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN has_url BOOLEAN DEFAULT 0")
    if 'attachment_risk' not in columns:
        c.execute("ALTER TABLE predictions ADD COLUMN attachment_risk TEXT DEFAULT 'None'")
        
    conn.commit()
    conn.close()

init_db()

# Store prediction in database
def store_prediction(email_text, prediction, confidence, model_used, sender, risk_score, has_url, attachment_risk):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO predictions (email_text, prediction, confidence, model_used, sender, risk_score, has_url, attachment_risk, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (email_text, prediction, confidence, model_used, sender, risk_score, has_url, attachment_risk, datetime.now()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error storing prediction: {e}")

# Fetch latest predictions
def get_prediction_history(limit=10):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT id, email_text, prediction, confidence, model_used, sender, risk_score, has_url, attachment_risk, timestamp
            FROM predictions
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"Error fetching history: {e}")
        return []

# Statistics tracking
stats = {
    'total_checked': 0,
    'phishing_count': 0,
    'safe_count': 0
}

def load_stats_from_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM predictions")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM predictions WHERE prediction = 'Phishing'")
        phishing = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM predictions WHERE prediction = 'Safe'")
        safe = c.fetchone()[0]
        conn.close()
        stats['total_checked'] = total
        stats['phishing_count'] = phishing
        stats['safe_count'] = safe
    except Exception as e:
        print(f"Error loading stats: {e}")

load_stats_from_db()

def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        return None
    try:
        obj = joblib.load(path)
        # Check if new multi-model output
        if isinstance(obj, dict) and 'models' in obj:
            return obj
        # Fallback for older model schema
        if isinstance(obj, dict):
            return {
                'models': {'nb': obj.get('pipeline')},
                'metrics': {},
                'label_encoder': obj.get('label_encoder')
            }
        return {
            'models': {'nb': obj},
            'metrics': {},
            'label_encoder': None
        }
    except Exception:
        return None

model_data = load_model()
models = model_data['models'] if model_data else {}
metrics = model_data['metrics'] if model_data else {}
label_encoder = model_data['label_encoder'] if model_data else None

@app.route('/', methods=['GET'])
def index():
    return render_template(
        'index.html',
        total_checked=stats['total_checked'],
        phishing_count=stats['phishing_count'],
        safe_count=stats['safe_count']
    )

def interpret_label(predicted, label_encoder=None):
    try:
        if label_encoder is not None:
            decoded = label_encoder.inverse_transform([predicted])[0]
            ds = str(decoded).lower()
            if 'phish' in ds or ds in ('1', 'true', 'yes', 'phishing'):
                return 'Phishing'
            return 'Safe'
        else:
            return 'Phishing' if int(predicted) == 1 else 'Safe'
    except Exception:
        return 'Phishing' if int(predicted) == 1 else 'Safe'

# Suspicious words fallbacks
# Note: 'password' and 'login' excluded - they appear in legitimate transactional emails (Netflix, banks)
SUSPICIOUS_TERMS = ['urgent', 'verify', 'click here', 'free', 'winner', 'account suspended', 'claim', 'refund', 'security alert', 'update card', 'act now', 'limited time']

# Metadata parser for Sender reputation, Attachment risks, and URL threats
def parse_email_metadata(text):
    # 1. Parse sender
    sender_match = re.search(r'(?:from|sender):\s*([^\n\r]+)', text, re.IGNORECASE)
    sender = sender_match.group(1).strip() if sender_match else 'Unknown Sender'
    
    # Extract email domain
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender)
    email = email_match.group(0) if email_match else ''
    
    domain_spoof = False
    is_verified_brand = False
    if email:
        domain = email.split('@')[1].lower()
        brands = ['paypal', 'netflix', 'google', 'gmail', 'microsoft', 'outlook', 'apple', 'amazon', 'facebook']
        official_domains = {
            'paypal': ['paypal.com', 'paypal.co.uk'],
            'netflix': ['netflix.com'],
            'google': ['google.com'],
            'gmail': ['gmail.com'],
            'microsoft': ['microsoft.com', 'microsoftonline.com'],
            'outlook': ['outlook.com', 'hotmail.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'amazon.in'],
            'facebook': ['facebook.com']
        }
        
        # Check standard replacements
        lookalikes = ['paypa1', 'nettflix', 'micr0soft', 'faceb00k', 'secur-update', 'amzn']
        if any(l in domain for l in lookalikes):
            domain_spoof = True
        else:
            for brand in brands:
                if brand in domain:
                    is_official = False
                    for official in official_domains.get(brand, []):
                        if domain == official or domain.endswith('.' + official):
                            is_official = True
                            break
                    if not is_official:
                        domain_spoof = True
                        break
                    else:
                        is_verified_brand = True
            
    # 1b. Check DKIM signed-by domain for secondary trust verification
    dkim_match = re.search(r'signed-by:\s*([^\n\r]+)', text, re.IGNORECASE)
    dkim_domain = dkim_match.group(1).strip().lower() if dkim_match else ''
    is_dkim_signed = False
    if dkim_domain and not is_verified_brand:
        # Check if DKIM signing domain is from a known official brand subdomain
        for brand in ['paypal', 'netflix', 'google', 'microsoft', 'apple', 'amazon', 'facebook']:
            official_roots = {
                'paypal': 'paypal.com', 'netflix': 'netflix.com', 'google': 'google.com',
                'microsoft': 'microsoft.com', 'apple': 'apple.com',
                'amazon': 'amazon.com', 'facebook': 'facebook.com'
            }
            root = official_roots.get(brand, '')
            if root and (dkim_domain == root or dkim_domain.endswith('.' + root)):
                is_dkim_signed = True
                is_verified_brand = True  # DKIM confirms legitimacy
                domain_spoof = False
                break

    # 2. Check attachments
    attachment_match = re.search(r'attachment:\s*([\w\.-]+\.\w+)', text, re.IGNORECASE)
    attachment = attachment_match.group(1) if attachment_match else 'None'
    
    attachment_risk = 'None'
    if attachment != 'None':
        ext = attachment.split('.')[-1].lower()
        dangerous = ['exe', 'bat', 'scr', 'vbs', 'js', 'cmd', 'ps1', 'lnk', 'zip', 'rar']
        if ext in dangerous:
            attachment_risk = 'High Risk'
        else:
            attachment_risk = 'Low Risk'
            
    # 3. Check URLs
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    has_url = len(urls) > 0
    
    suspicious_url = False
    for url in urls:
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            suspicious_url = True
        if len(url) > 75:
            suspicious_url = True
            
    return {
        'sender': sender,
        'email': email,
        'domain_spoof': domain_spoof,
        'is_verified_brand': is_verified_brand,
        'is_dkim_signed': is_dkim_signed,
        'dkim_domain': dkim_domain,
        'attachment': attachment,
        'attachment_risk': attachment_risk,
        'has_url': has_url,
        'url_count': len(urls),
        'suspicious_url': suspicious_url
    }

# Explainable AI (XAI) feature importance computation
def explain_prediction(pipeline, text, model_name='nb'):
    try:
        vectorizer = pipeline.named_steps['tfidf']
        clf = pipeline.named_steps['clf']
        
        feature_names = vectorizer.get_feature_names_out()
        X_tfidf = vectorizer.transform([text])
        
        feature_index = X_tfidf.nonzero()[1]
        tfidf_values = X_tfidf.data
        
        words_weights = []
        
        if model_name == 'nb':
            log_prob_diff = clf.feature_log_prob_[1] - clf.feature_log_prob_[0]
            for idx, val in zip(feature_index, tfidf_values):
                word = feature_names[idx]
                weight = float(log_prob_diff[idx] * val)
                words_weights.append({'word': word, 'weight': weight})
                
        elif model_name == 'lr':
            coef = clf.coef_[0]
            for idx, val in zip(feature_index, tfidf_values):
                word = feature_names[idx]
                weight = float(coef[idx] * val)
                words_weights.append({'word': word, 'weight': weight})
                
        else: # Random Forest fallback
            importances = clf.feature_importances_
            for idx, val in zip(feature_index, tfidf_values):
                word = feature_names[idx]
                is_suspicious = any(term in word.lower() for term in SUSPICIOUS_TERMS)
                direction = 1.0 if is_suspicious else -0.5
                weight = float(importances[idx] * val * direction)
                words_weights.append({'word': word, 'weight': weight})
                
        # Sort by absolute weight value descending
        words_weights.sort(key=lambda x: abs(x['weight']), reverse=True)
        return words_weights[:15]
    except Exception as e:
        print(f"XAI calculation failed: {e}")
        return []

def analyze_text_rules(text):
    if not text:
        return {'found': [], 'score': 0, 'level': 'Low Risk', 'recommended_action': 'No action required'}
        
    text_lower = text.lower()
    counts = {}
    for term in SUSPICIOUS_TERMS:
        pattern = re.compile(re.escape(term.lower()))
        cnt = len(pattern.findall(text_lower))
        if cnt:
            counts[term] = cnt

    raw_score = sum(min(cnt, 3) for cnt in counts.values())
    max_possible = 3 * len(SUSPICIOUS_TERMS)
    score = int((raw_score / max_possible) * 100) if max_possible > 0 else 0

    if score <= 30:
        level = 'Low Risk'
    elif score <= 70:
        level = 'Medium Risk'
    else:
        level = 'High Risk'

    if score >= 80:
        action = 'Delete Email Immediately'
    elif score >= 50:
        action = 'Mark as Spam & Delete'
    elif score >= 30:
        action = 'Verify Sender Identity'
    else:
        action = 'No action required'

    return {
        'found': list(counts.keys()),
        'score': score,
        'level': level,
        'recommended_action': action
    }

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Accept both JSON and form payloads
        if request.is_json:
            payload = request.get_json()
            text = payload.get('email_text', '')
            model_name = payload.get('model', 'nb')
        else:
            text = request.form.get('email_text', '')
            model_name = request.form.get('model', 'nb')

        if not text or not text.strip():
            msg = 'No email content provided.'
            return jsonify({'error': msg}), 400

        pipeline = models.get(model_name)
        if pipeline is None:
            # Fallback to first available model
            if models:
                model_name = list(models.keys())[0]
                pipeline = models[model_name]
            else:
                return jsonify({'error': 'No trained models available. Run train_model.py.'}), 500

        # Run Prediction
        pred = pipeline.predict([text])[0]
        confidence = None
        try:
            probs = pipeline.predict_proba([text])[0]
            confidence = float(max(probs))
        except Exception:
            confidence = None

        label = interpret_label(pred, label_encoder)
        
        # Calculate Risk and Explainable AI weights
        rules_analysis = analyze_text_rules(text)
        metadata = parse_email_metadata(text)
        xai_weights = explain_prediction(pipeline, text, model_name)

        # Verified official brand domain override (SPF/DKIM alignment simulation)
        # Fires when SPF sender domain OR DKIM signed-by domain is verified as legitimate
        if metadata['is_verified_brand'] and not metadata['domain_spoof']:
            label = 'Safe'
            confidence = max(confidence or 0.0, 0.97)  # Keep original confidence if already high

        # Update stats
        stats['total_checked'] += 1
        if label == 'Phishing':
            stats['phishing_count'] += 1
        else:
            stats['safe_count'] += 1

        # Store prediction in DB
        store_prediction(
            text, label, confidence, model_name,
            metadata['sender'], rules_analysis['score'],
            metadata['has_url'], metadata['attachment_risk']
        )

        return jsonify({
            'prediction': label,
            'confidence': confidence,
            'model_used': model_name,
            'sender': metadata['sender'],
            'domain_spoof': metadata['domain_spoof'],
            'is_verified_brand': metadata['is_verified_brand'],
            'is_dkim_signed': metadata['is_dkim_signed'],
            'dkim_domain': metadata['dkim_domain'],
            'attachment': metadata['attachment'],
            'attachment_risk': metadata['attachment_risk'],
            'has_url': metadata['has_url'],
            'url_count': metadata['url_count'],
            'suspicious_url': metadata['suspicious_url'],
            'risk_score': rules_analysis['score'],
            'risk_level': rules_analysis['level'],
            'recommended_action': rules_analysis['recommended_action'],
            'xai_weights': xai_weights,
            'total_checked': stats['total_checked'],
            'phishing_count': stats['phishing_count'],
            'safe_count': stats['safe_count']
        })

    except Exception as exc:
        print(f"Error in prediction route: {exc}")
        return jsonify({'error': str(exc)}), 500

@app.route('/metrics', methods=['GET'])
def get_metrics():
    # Return metrics stored in model.pkl
    return jsonify({
        'metrics': metrics,
        'available_models': list(models.keys())
    })

@app.route('/history', methods=['GET'])
def history():
    predictions = get_prediction_history(10)
    return jsonify({'predictions': predictions})

if __name__ == '__main__':
    app.run(debug=True)

