import os, secrets, string, json
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

db   = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ANTHROPIC_API_KEY      = os.getenv('ANTHROPIC_API_KEY')
STRIPE_SECRET_KEY      = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')

# ── PLAN LIMITS ──────────────────────────────────────────────────
PLAN_LIMITS = {
    'free':         {'cases': 10,  'users': 1,  'api': False, 'reports': False, 'training': True},
    'professional': {'cases': 500, 'users': 10, 'api': True,  'reports': True,  'training': True},
    'enterprise':   {'cases': -1,  'users': -1, 'api': True,  'reports': True,  'training': True},
}

# ── MODELS ───────────────────────────────────────────────────────
class Organisation(db.Model):
    __tablename__ = 'organisations'
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(200), nullable=False)
    sector        = db.Column(db.String(100))
    country       = db.Column(db.String(100))
    plan          = db.Column(db.String(50), default='free')
    api_key       = db.Column(db.String(100), unique=True)
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    users         = db.relationship('User', backref='organisation', lazy=True)
    cases         = db.relationship('FraudCase', backref='organisation', lazy=True)
    reports       = db.relationship('ComplianceReport', backref='organisation', lazy=True)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id                    = db.Column(db.Integer, primary_key=True)
    email                 = db.Column(db.String(200), unique=True, nullable=False)
    password_hash         = db.Column(db.String(256))
    full_name             = db.Column(db.String(200))
    role                  = db.Column(db.String(50), default='analyst')
    org_id                = db.Column(db.Integer, db.ForeignKey('organisations.id'))
    is_verified           = db.Column(db.Boolean, default=False)
    force_password_change = db.Column(db.Boolean, default=False)
    otp_code              = db.Column(db.String(10))
    otp_expires_at        = db.Column(db.DateTime)
    last_login            = db.Column(db.DateTime)
    created_at            = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FraudCase(db.Model):
    __tablename__ = 'fraud_cases'
    id              = db.Column(db.Integer, primary_key=True)
    org_id          = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False)
    submitted_by    = db.Column(db.Integer, db.ForeignKey('users.id'))
    case_ref        = db.Column(db.String(50), unique=True)
    indicator_type  = db.Column(db.String(50))   # account, phone, ip, email, bvn, card
    indicator_value = db.Column(db.String(200))
    fraud_type      = db.Column(db.String(100))  # phishing, account_takeover, etc
    severity        = db.Column(db.String(20), default='medium')  # low/medium/high/critical
    status          = db.Column(db.String(50), default='open')    # open/investigating/resolved/false_positive
    description     = db.Column(db.Text)
    amount_lost     = db.Column(db.Float)
    currency        = db.Column(db.String(10), default='NGN')
    ai_score        = db.Column(db.Float)
    ai_reasoning    = db.Column(db.Text)
    ai_scored_at    = db.Column(db.DateTime)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    submitter       = db.relationship('User', foreign_keys=[submitted_by])
    alerts          = db.relationship('ThreatAlert', backref='case', lazy=True)

class ThreatAlert(db.Model):
    __tablename__ = 'threat_alerts'
    id         = db.Column(db.Integer, primary_key=True)
    case_id    = db.Column(db.Integer, db.ForeignKey('fraud_cases.id'))
    alert_type = db.Column(db.String(50))
    channel    = db.Column(db.String(50))
    sent_to    = db.Column(db.String(200))
    sent_at    = db.Column(db.DateTime, default=datetime.utcnow)
    status     = db.Column(db.String(20), default='sent')

class RiskScore(db.Model):
    __tablename__ = 'risk_scores'
    id            = db.Column(db.Integer, primary_key=True)
    case_id       = db.Column(db.Integer, db.ForeignKey('fraud_cases.id'))
    score         = db.Column(db.Float)
    risk_level    = db.Column(db.String(20))
    reasoning     = db.Column(db.Text)
    indicators    = db.Column(db.Text)
    model_version = db.Column(db.String(50))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

class ComplianceReport(db.Model):
    __tablename__ = 'compliance_reports'
    id           = db.Column(db.Integer, primary_key=True)
    org_id       = db.Column(db.Integer, db.ForeignKey('organisations.id'))
    report_type  = db.Column(db.String(100))
    period_start = db.Column(db.Date)
    period_end   = db.Column(db.Date)
    file_path    = db.Column(db.String(300))
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    generator    = db.relationship('User', foreign_keys=[generated_by])

class TrainingModule(db.Model):
    __tablename__ = 'training_modules'
    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(200))
    description = db.Column(db.Text)
    category    = db.Column(db.String(100))
    difficulty  = db.Column(db.String(20))
    content     = db.Column(db.Text)
    duration    = db.Column(db.Integer)  # minutes
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    progress    = db.relationship('TrainingProgress', backref='module', lazy=True)

class TrainingProgress(db.Model):
    __tablename__ = 'training_progress'
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'))
    module_id    = db.Column(db.Integer, db.ForeignKey('training_modules.id'))
    completed    = db.Column(db.Boolean, default=False)
    score        = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime)
    started_at   = db.Column(db.DateTime, default=datetime.utcnow)
    user         = db.relationship('User', foreign_keys=[user_id])

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    org_id     = db.Column(db.Integer)
    user_id    = db.Column(db.Integer)
    action     = db.Column(db.String(100))
    detail     = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class WebhookConfig(db.Model):
    __tablename__ = 'webhook_configs'
    id          = db.Column(db.Integer, primary_key=True)
    org_id      = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False)
    platform    = db.Column(db.String(20), nullable=False)  # slack or teams
    webhook_url = db.Column(db.String(500), nullable=False)
    name        = db.Column(db.String(100))
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class ThreatScan(db.Model):
    __tablename__ = 'threat_scans'
    id              = db.Column(db.Integer, primary_key=True)
    org_id          = db.Column(db.Integer, db.ForeignKey('organisations.id'), nullable=False)
    case_id         = db.Column(db.Integer, db.ForeignKey('fraud_cases.id'), nullable=True)
    indicator_type  = db.Column(db.String(50))
    indicator_value = db.Column(db.String(200))
    overall_risk    = db.Column(db.String(20))
    sources_checked = db.Column(db.Integer)
    raw_results     = db.Column(db.Text)
    scanned_at      = db.Column(db.DateTime, default=datetime.utcnow)
    scanned_by      = db.Column(db.Integer, db.ForeignKey('users.id'))

# ── HELPERS ──────────────────────────────────────────────────────
def log_audit(org_id, user_id, action, detail=''):
    try:
        entry = AuditLog(org_id=org_id, user_id=user_id, action=action, detail=detail,
                         ip_address=request.remote_addr)
        db.session.add(entry)
        db.session.commit()
    except:
        pass

def generate_case_ref():
    chars = string.ascii_uppercase + string.digits
    return 'DIQ-' + ''.join(secrets.choice(chars) for _ in range(8))

def generate_api_key(org_id, org_name):
    slug = org_name[:8].upper().replace(' ', '')
    return f"diq_{org_id}_{slug}_{secrets.token_hex(8)}"

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

def plan_required(feature):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            org = current_user.organisation
            limits = PLAN_LIMITS.get(org.plan, PLAN_LIMITS['free'])
            if not limits.get(feature):
                flash(f'This feature requires a higher plan. Please upgrade.', 'warning')
                return redirect(url_for('billing'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def send_otp_email(user):
    try:
        otp = ''.join(secrets.choice(string.digits) for _ in range(6))
        user.otp_code = otp
        user.otp_expires_at = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
        msg = Message('Verify your DefenceIQ account', recipients=[user.email])
        msg.html = render_template('email/otp.html', user=user, otp=otp)
        mail.send(msg)
    except Exception as e:
        print(f"Email error: {e}")

# ── AI RISK SCORING ───────────────────────────────────────────────
def ai_score_case(case):
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        prompt = f"""You are a fraud intelligence analyst for African financial institutions.
Analyse this fraud indicator and provide a risk assessment.

Indicator Type: {case.indicator_type}
Indicator Value: {case.indicator_value}
Fraud Type: {case.fraud_type}
Severity: {case.severity}
Description: {case.description or 'Not provided'}
Amount Lost: {case.amount_lost or 'Unknown'} {case.currency}

Respond ONLY with valid JSON in this exact format:
{{
  "score": <number 0-100>,
  "risk_level": "<low|medium|high|critical>",
  "reasoning": "<2-3 sentence explanation>",
  "indicators": ["<key indicator 1>", "<key indicator 2>", "<key indicator 3>"],
  "recommended_actions": ["<action 1>", "<action 2>"]
}}"""
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        result = json.loads(response.content[0].text)
        case.ai_score    = result.get('score')
        case.ai_reasoning = result.get('reasoning')
        case.ai_scored_at = datetime.utcnow()
        risk = RiskScore(
            case_id=case.id,
            score=result.get('score'),
            risk_level=result.get('risk_level'),
            reasoning=result.get('reasoning'),
            indicators=json.dumps(result.get('indicators', [])),
            model_version='claude-sonnet-4'
        )
        db.session.add(risk)
        db.session.commit()
        return result
    except Exception as e:
        print(f"AI scoring error: {e}")
        return None

# ── ROUTES: PUBLIC ────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════
# REST API v1 — DefenceIQ
# Auth: Bearer token via X-API-Key header
# Base: /api/v1/
# ═══════════════════════════════════════════════════════════════════

def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key','')
        if not key:
            return jsonify({'error':'Missing X-API-Key header','code':401}), 401
        org = Organisation.query.filter_by(api_key=key).first()
        if not org:
            return jsonify({'error':'Invalid API key','code':401}), 401
        request.api_org = org
        return f(*args, **kwargs)
    return decorated

@app.route('/api/v1', methods=['GET'])
def api_index():
    return jsonify({
        'name': 'DefenceIQ API',
        'version': '1.0',
        'docs': 'https://defenceiq.io/api/docs',
        'endpoints': [
            'POST /api/v1/screen/sanctions',
            'POST /api/v1/screen/adverse-media',
            'POST /api/v1/screen/ip',
            'POST /api/v1/screen/full',
            'GET  /api/v1/cases',
            'POST /api/v1/cases',
            'GET  /api/v1/cases/<ref>',
            'GET  /api/v1/aml/transactions',
            'POST /api/v1/aml/screen',
            'GET  /api/v1/kyc/profiles',
            'GET  /api/v1/health',
        ]
    })

@app.route('/api/v1/health', methods=['GET'])
def api_health():
    return jsonify({'status':'ok','service':'DefenceIQ','timestamp':datetime.utcnow().isoformat()})

# ── Screen: Sanctions ────────────────────────────────────────────────
@app.route('/api/v1/screen/sanctions', methods=['POST'])
@require_api_key
def api_screen_sanctions():
    data = request.get_json(silent=True) or {}
    name = data.get('name','').strip()
    if not name:
        return jsonify({'error':'name is required'}), 400
    threshold = int(data.get('threshold', 82))
    try:
        from sanctions_checker import screen_name
        result = screen_name(name, threshold=threshold)
        return jsonify({
            'query': name,
            'is_match': result.get('is_match', False),
            'risk_level': result.get('risk_level','clean'),
            'match_score': result.get('match_score', 0),
            'matched_name': result.get('matched_name'),
            'matched_list': result.get('matched_list'),
            'total_checked': result.get('total_checked', 0),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Screen: Adverse Media ────────────────────────────────────────────
@app.route('/api/v1/screen/adverse-media', methods=['POST'])
@require_api_key
def api_screen_adverse_media():
    data = request.get_json(silent=True) or {}
    query = data.get('query','').strip()
    if not query:
        return jsonify({'error':'query is required'}), 400
    try:
        from adverse_media import screen_adverse_media
        keys = {'anthropic': os.getenv('ANTHROPIC_API_KEY'), 'newsapi': os.getenv('NEWSAPI_KEY','')}
        result = screen_adverse_media(query, keys)
        return jsonify({
            'query': query,
            'overall_risk': result.get('overall_risk'),
            'risk_score': result.get('risk_score'),
            'total_articles': result.get('total_articles', 0),
            'sources_hit': result.get('sources_hit', 0),
            'articles': result.get('articles', [])[:5],
            'ai_summary': result.get('ai_assessment', {}).get('summary') if result.get('ai_assessment') else None,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Screen: IP Reputation ────────────────────────────────────────────
@app.route('/api/v1/screen/ip', methods=['POST'])
@require_api_key
def api_screen_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip','').strip()
    if not ip:
        return jsonify({'error':'ip is required'}), 400
    try:
        import requests as _req, os as _os
        abuseipdb_key = _os.getenv('ABUSEIPDB_API_KEY','')
        ip_result = {'overall_risk':'unknown','risk_score':0,'is_tor':False,'is_vpn':False,'abuse_score':0,'country':None,'asn':None}
        if abuseipdb_key:
            try:
                r = _req.get('https://api.abuseipdb.com/api/v2/check',
                    headers={'Key': abuseipdb_key, 'Accept': 'application/json'},
                    params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=8)
                if r.status_code == 200:
                    d = r.json().get('data', {})
                    score = d.get('abuseConfidenceScore', 0)
                    ip_result = {
                        'overall_risk': 'critical' if score>=75 else 'high' if score>=50 else 'medium' if score>=25 else 'low' if score>0 else 'clean',
                        'risk_score': score, 'abuse_score': score,
                        'is_tor': d.get('isTor', False),
                        'is_vpn': False,
                        'country': d.get('countryCode'),
                        'asn': d.get('domain')
                    }
            except Exception:
                pass
        return jsonify({
            'ip': ip,
            'risk_level': ip_result.get('overall_risk','unknown'),
            'risk_score': ip_result.get('risk_score', 0),
            'is_tor': ip_result.get('is_tor', False),
            'is_vpn': ip_result.get('is_vpn', False),
            'abuse_score': ip_result.get('abuse_score', 0),
            'country': ip_result.get('country'),
            'asn': ip_result.get('asn'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Screen: Full (sanctions + adverse media) ─────────────────────────
@app.route('/api/v1/screen/full', methods=['POST'])
@require_api_key
def api_screen_full():
    data  = request.get_json(silent=True) or {}
    name  = data.get('name','').strip()
    email = data.get('email','').strip()
    ip    = data.get('ip','').strip()
    if not name:
        return jsonify({'error':'name is required'}), 400
    results = {'query': {'name': name, 'email': email, 'ip': ip}, 'timestamp': datetime.utcnow().isoformat()}
    try:
        from sanctions_checker import screen_name as _screen_name
        results['sanctions'] = _screen_name(name)
    except Exception as e:
        results['sanctions'] = {'error': str(e)}
    try:
        from adverse_media import screen_adverse_media
        keys = {'anthropic': os.getenv('ANTHROPIC_API_KEY')}
        am   = screen_adverse_media(name, keys)
        results['adverse_media'] = {
            'overall_risk': am.get('overall_risk'),
            'risk_score': am.get('risk_score'),
            'total_articles': am.get('total_articles',0)
        }
    except Exception as e:
        results['adverse_media'] = {'error': str(e)}
    if ip:
        try:
            import requests as _req2, os as _os2
            abuseipdb_key = _os2.getenv('ABUSEIPDB_API_KEY','')
            ipr = {'overall_risk':'unknown','is_tor':False,'is_vpn':False,'abuse_score':0}
            if abuseipdb_key:
                try:
                    _r = _req2.get('https://api.abuseipdb.com/api/v2/check',
                        headers={'Key': abuseipdb_key, 'Accept': 'application/json'},
                        params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=8)
                    if _r.status_code == 200:
                        _d = _r.json().get('data', {})
                        _s = _d.get('abuseConfidenceScore', 0)
                        ipr = {'overall_risk': 'critical' if _s>=75 else 'high' if _s>=50 else 'medium' if _s>=25 else 'low' if _s>0 else 'clean',
                               'is_tor': _d.get('isTor', False), 'is_vpn': False, 'abuse_score': _s}
                except Exception:
                    pass
            results['ip_reputation'] = {
                'risk_level': ipr.get('overall_risk'),
                'is_tor': ipr.get('is_tor', False),
                'is_vpn': ipr.get('is_vpn', False),
                'abuse_score': ipr.get('abuse_score', 0)
            }
        except Exception as e:
            results['ip_reputation'] = {'error': str(e)}
    # Overall risk rollup
    risk_order = ['critical','high','medium','low','clean']
    all_risks  = []
    for section in ['sanctions','adverse_media','ip_reputation']:
        if section in results and 'overall_risk' in results[section]:
            all_risks.append(results[section]['overall_risk'])
        elif section in results and 'risk_level' in results[section]:
            all_risks.append(results[section]['risk_level'])
    results['overall_risk'] = min(all_risks, key=lambda x: risk_order.index(x) if x in risk_order else 99, default='unknown')
    return jsonify(results)

# ── Cases ────────────────────────────────────────────────────────────
@app.route('/api/v1/cases', methods=['GET'])
@require_api_key
def api_cases_list():
    org    = request.api_org
    limit  = min(int(request.args.get('limit', 20)), 100)
    offset = int(request.args.get('offset', 0))
    risk   = request.args.get('risk_level')
    from sqlalchemy import text as sqlt
    filters = "WHERE org_id=:o"
    params  = {'o': org.id}
    if risk:
        filters += " AND risk_level=:r"
        params['r'] = risk
    total = db.session.execute(sqlt(f"SELECT COUNT(*) FROM fraud_cases {filters}"), params).scalar() or 0
    rows  = db.session.execute(sqlt(
        f"SELECT id,case_ref,indicator_type,indicator_value,fraud_type,severity,status,amount_lost,currency,created_at FROM fraud_cases {filters} ORDER BY created_at DESC LIMIT :lim OFFSET :off"
    ), {**params, 'lim': limit, 'off': offset}).fetchall()
    return jsonify({
        'total': total, 'limit': limit, 'offset': offset,
        'cases': [{
            'id': r.id, 'case_ref': r.case_ref,
            'indicator_type': r.indicator_type,
            'indicator_value': r.indicator_value,
            'fraud_type': r.fraud_type,
            'severity': r.severity,
            'status': r.status,
            'amount_lost': float(r.amount_lost) if r.amount_lost else None,
            'currency': r.currency,
            'created_at': str(r.created_at)
        } for r in rows]
    })

@app.route('/api/v1/cases', methods=['POST'])
@require_api_key
def api_cases_create():
    org  = request.api_org
    data = request.get_json(silent=True) or {}
    if not data.get('subject_name') or not data.get('fraud_type'):
        return jsonify({'error':'subject_name and fraud_type are required'}), 400
    try:
        import random, string
        ref  = 'DQ-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        case = FraudCase(
            org_id          = org.id,
            case_ref        = ref,
            indicator_type  = data.get('indicator_type','name'),
            indicator_value = data['subject_name'],
            fraud_type      = data['fraud_type'],
            severity        = data.get('risk_level','medium'),
            status          = 'open',
            description     = data.get('description',''),
            submitted_by    = 1
        )
        db.session.add(case)
        db.session.commit()
        return jsonify({'id': case.id, 'case_ref': case.case_ref, 'status': 'created'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/cases/<string:ref>', methods=['GET'])
@require_api_key
def api_cases_get(ref):
    org  = request.api_org
    case = FraudCase.query.filter_by(org_id=org.id, case_ref=ref).first()
    if not case:
        return jsonify({'error':'Case not found'}), 404
    from sqlalchemy import text as sqlt
    row = db.session.execute(sqlt(
        "SELECT id,case_ref,indicator_type,indicator_value,fraud_type,severity,status,description,amount_lost,currency,created_at FROM fraud_cases WHERE org_id=:o AND case_ref=:r"
    ), {'o': org.id, 'r': ref}).fetchone()
    if not row:
        return jsonify({'error':'Case not found'}), 404
    return jsonify({
        'id': row.id, 'case_ref': row.case_ref,
        'indicator_type': row.indicator_type,
        'indicator_value': row.indicator_value,
        'fraud_type': row.fraud_type,
        'severity': row.severity,
        'status': row.status,
        'description': row.description,
        'amount_lost': float(row.amount_lost) if row.amount_lost else None,
        'currency': row.currency,
        'created_at': str(row.created_at)
    })

# ── AML ──────────────────────────────────────────────────────────────
@app.route('/api/v1/aml/transactions', methods=['GET'])
@require_api_key
def api_aml_list():
    org   = request.api_org
    limit = min(int(request.args.get('limit', 20)), 100)
    risk  = request.args.get('risk_level')
    from sqlalchemy import text as sqlt
    filters = "WHERE org_id=:o"
    params  = {'o': org.id}
    if risk:
        filters += " AND risk_level=:r"
        params['r'] = risk
    rows = db.session.execute(sqlt(
        f"SELECT id,txn_ref,sender_name,receiver_name,amount,currency,risk_level,risk_score,reviewed,sar_filed,created_at FROM aml_transactions {filters} ORDER BY created_at DESC LIMIT :lim"
    ), {**params, 'lim': limit}).fetchall()
    return jsonify({'total': len(rows), 'transactions': [{
        'id': r.id, 'txn_ref': r.txn_ref,
        'sender_name': r.sender_name, 'receiver_name': r.receiver_name,
        'amount': float(r.amount) if r.amount else None,
        'currency': r.currency or 'GBP',
        'risk_level': r.risk_level, 'risk_score': r.risk_score,
        'reviewed': r.reviewed, 'sar_filed': r.sar_filed,
        'created_at': str(r.created_at)
    } for r in rows]})

@app.route('/api/v1/aml/screen', methods=['POST'])
@require_api_key
def api_aml_screen():
    org  = request.api_org
    data = request.get_json(silent=True) or {}
    required = ['sender_name','receiver_name','amount','currency']
    missing  = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
    try:
        from aml_engine import screen_transaction
        txn_data = {
            'sender_name':      data['sender_name'],
            'receiver_name':    data['receiver_name'],
            'amount':           float(data['amount']),
            'currency':         data['currency'],
            'sender_country':   data.get('sender_country',''),
            'receiver_country': data.get('receiver_country',''),
            'payment_method':   data.get('payment_method','bank_transfer'),
            'narrative':        data.get('narrative','')
        }
        result = screen_transaction(txn_data, org.id)
        return jsonify({
            'risk_level':  result.get('risk_level','unknown'),
            'risk_score':  result.get('risk_score', 0),
            'flags':       result.get('flags', []),
            'flag_count':  len(result.get('flags',[])),
            'timestamp':   datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── KYC ─────────────────────────────────────────────────────────────
@app.route('/api/v1/kyc/profiles', methods=['GET'])
@require_api_key
def api_kyc_list():
    org   = request.api_org
    limit = min(int(request.args.get('limit', 20)), 100)
    risk  = request.args.get('risk_rating')
    from sqlalchemy import text as sqlt
    filters = "WHERE org_id=:o"
    params  = {'o': org.id}
    if risk:
        filters += " AND risk_rating=:r"
        params['r'] = risk
    rows = db.session.execute(sqlt(
        f"SELECT id,profile_ref,full_name,risk_rating,kyc_status,pep_status,sanctions_hit,created_at FROM kyc_profiles {filters} ORDER BY created_at DESC LIMIT :lim"
    ), {**params, 'lim': limit}).fetchall()
    return jsonify({'total': len(rows), 'profiles': [{
        'id': r.id, 'profile_ref': r.profile_ref,
        'full_name': r.full_name,
        'risk_rating': r.risk_rating,
        'kyc_status': r.kyc_status,
        'pep_status': r.pep_status,
        'sanctions_hit': r.sanctions_hit,
        'created_at': str(r.created_at)
    } for r in rows]})

@app.route('/')
def index():
    return render_template('index.html', stripe_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        name     = request.form.get('full_name', '').strip()
        org_name = request.form.get('org_name', '').strip()
        country  = request.form.get('country', '').strip()
        sector   = request.form.get('sector', '').strip()
        plan     = request.form.get('plan', 'free')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('register'))

        org = Organisation(name=org_name, sector=sector, country=country, plan='free')
        db.session.add(org)
        db.session.flush()
        org.api_key = generate_api_key(org.id, org_name)

        user = User(email=email, full_name=name, role='admin', org_id=org.id, is_verified=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        send_otp_email(user)
        flash('Account created! Please check your email for a verification code.', 'success')
        return redirect(url_for('verify_email', user_id=user.id))
    return render_template('register.html', stripe_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/verify-email/<int:user_id>', methods=['GET', 'POST'])
def verify_email(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if user.otp_code == otp and user.otp_expires_at > datetime.utcnow():
            user.is_verified  = True
            user.otp_code     = None
            user.otp_expires_at = None
            db.session.commit()
            login_user(user)
            flash('Email verified! Welcome to DefenceIQ.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.', 'error')
    return render_template('verify_email.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user     = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email first.', 'warning')
                return redirect(url_for('verify_email', user_id=user.id))
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_audit(user.org_id, user.id, 'LOGIN', f'Login from {request.remote_addr}')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit(current_user.org_id, current_user.id, 'LOGOUT')
    logout_user()
    return redirect(url_for('index'))

# ── ROUTES: DASHBOARD ─────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    org   = current_user.organisation
    cases = FraudCase.query.filter_by(org_id=org.id).order_by(FraudCase.created_at.desc()).limit(10).all()
    stats = {
        'total_cases':      FraudCase.query.filter_by(org_id=org.id).count(),
        'open_cases':       FraudCase.query.filter_by(org_id=org.id, status='open').count(),
        'critical_cases':   FraudCase.query.filter_by(org_id=org.id, severity='critical').count(),
        'resolved_cases':   FraudCase.query.filter_by(org_id=org.id, status='resolved').count(),
        'total_members':    User.query.filter_by(org_id=org.id).count(),
        'modules_available':TrainingModule.query.filter_by(is_active=True).count(),
    }
    return render_template('dashboard.html', org=org, cases=cases, stats=stats)

# ── ROUTES: FRAUD CASES ───────────────────────────────────────────
@app.route('/cases')
@login_required
def cases():
    org    = current_user.organisation
    status = request.args.get('status', '')
    severity = request.args.get('severity', '')
    q      = FraudCase.query.filter_by(org_id=org.id)
    if status:
        q = q.filter_by(status=status)
    if severity:
        q = q.filter_by(severity=severity)
    all_cases = q.order_by(FraudCase.created_at.desc()).all()
    return render_template('cases.html', cases=all_cases, org=org)


def find_duplicate_cases(org_id, indicator_type, indicator_value, exclude_case_id=None):
    """Return existing cases for the same org with matching indicator type+value."""
    q = FraudCase.query.filter(
        FraudCase.org_id == org_id,
        FraudCase.indicator_type  == indicator_type,
        db.func.lower(FraudCase.indicator_value) == indicator_value.lower().strip()
    )
    if exclude_case_id:
        q = q.filter(FraudCase.id != exclude_case_id)
    return q.order_by(FraudCase.created_at.desc()).all()

@app.route('/cases/new', methods=['GET', 'POST'])
@login_required
def new_case():
    org    = current_user.organisation
    limits = PLAN_LIMITS.get(org.plan, PLAN_LIMITS['free'])
    if limits['cases'] != -1:
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
        monthly_count = FraudCase.query.filter(
            FraudCase.org_id == org.id,
            FraudCase.created_at >= month_start
        ).count()
        if monthly_count >= limits['cases']:
            flash(f'Monthly case limit ({limits["cases"]}) reached. Please upgrade your plan.', 'warning')
            return redirect(url_for('cases'))
    # Pre-flight duplicate check (GET + POST preview)
    dup_preview = []
    pre_type  = request.form.get('indicator_type',  request.args.get('indicator_type', ''))
    pre_value = request.form.get('indicator_value', request.args.get('indicator_value', '')).strip()
    if pre_type and pre_value:
        dup_preview = find_duplicate_cases(org.id, pre_type, pre_value)

    if request.method == 'POST':
        indicator_type  = request.form.get('indicator_type')
        indicator_value = request.form.get('indicator_value', '').strip()

        # Duplicate detection — warn but allow unless ?force=0 not set
        duplicates = find_duplicate_cases(org.id, indicator_type, indicator_value)
        confirm    = request.form.get('confirm_duplicate') == '1'

        if duplicates and not confirm:
            # Re-render form with duplicate warning — analyst must confirm to proceed
            flash(f'Duplicate indicator detected — {len(duplicates)} existing case(s) already use this indicator. Review below or confirm to submit anyway.', 'warning')
            return render_template('new_case.html', org=org,
                                   duplicates=duplicates,
                                   prefill=request.form,
                                   show_confirm=True)

        case = FraudCase(
            org_id          = org.id,
            submitted_by    = current_user.id,
            case_ref        = generate_case_ref(),
            indicator_type  = indicator_type,
            indicator_value = indicator_value,
            fraud_type      = request.form.get('fraud_type'),
            severity        = request.form.get('severity', 'medium'),
            description     = request.form.get('description', '').strip(),
            amount_lost     = float(request.form.get('amount_lost') or 0) or None,
            currency        = request.form.get('currency', 'NGN'),
            status          = 'open'
        )
        db.session.add(case)
        db.session.commit()
        log_audit(org.id, current_user.id, 'CASE_CREATED',
                  f'Case {case.case_ref}' + (' (duplicate confirmed)' if confirm and duplicates else ''))
        if org.plan in ['professional', 'enterprise'] and ANTHROPIC_API_KEY:
            ai_score_case(case)
        flash(f'Case {case.case_ref} submitted successfully.', 'success')
        return redirect(url_for('case_detail', case_id=case.id))
    return render_template('new_case.html', org=org, duplicates=dup_preview, prefill={}, show_confirm=False)


@app.route('/cases/duplicates')
@login_required
def case_duplicates():
    org = current_user.organisation
    # Find all indicator_type+value combos that appear more than once in this org
    from sqlalchemy import func
    dupes = db.session.query(
        FraudCase.indicator_type,
        FraudCase.indicator_value,
        func.count(FraudCase.id).label('count')
    ).filter(
        FraudCase.org_id == org.id
    ).group_by(
        FraudCase.indicator_type,
        db.func.lower(FraudCase.indicator_value)
    ).having(
        func.count(FraudCase.id) > 1
    ).order_by(
        func.count(FraudCase.id).desc()
    ).all()

    # For each duplicate group, fetch the actual cases
    grouped = []
    for d in dupes:
        cases = FraudCase.query.filter(
            FraudCase.org_id == org.id,
            FraudCase.indicator_type == d.indicator_type,
            db.func.lower(FraudCase.indicator_value) == d.indicator_value.lower()
        ).order_by(FraudCase.created_at.desc()).all()
        grouped.append({
            'indicator_type':  d.indicator_type,
            'indicator_value': d.indicator_value,
            'count':           d.count,
            'cases':           cases
        })

    log_audit(org.id, current_user.id, 'VIEW_DUPLICATES', f'{len(grouped)} duplicate groups viewed')
    return render_template('case_duplicates.html', org=org, grouped=grouped)

@app.route('/cases/<int:case_id>')
@login_required
def case_detail(case_id):
    case = FraudCase.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    risk = RiskScore.query.filter_by(case_id=case_id).order_by(RiskScore.created_at.desc()).first()
    return render_template('case_detail.html', case=case, risk=risk)

@app.route('/cases/<int:case_id>/score', methods=['POST'])
@login_required
def score_case(case_id):
    case = FraudCase.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    org  = current_user.organisation
    if not PLAN_LIMITS.get(org.plan, {}).get('api', False) and org.plan == 'free':
        return jsonify({'error': 'AI scoring requires Professional plan or above'}), 403
    result = ai_score_case(case)
    if result:
        return jsonify(result)
    return jsonify({'error': 'Scoring failed'}), 500

@app.route('/cases/<int:case_id>/update', methods=['POST'])
@login_required
def update_case(case_id):
    case = FraudCase.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    case.status   = request.form.get('status', case.status)
    case.severity = request.form.get('severity', case.severity)
    db.session.commit()
    log_audit(current_user.org_id, current_user.id, 'CASE_UPDATED', f'Case {case.case_ref}')
    flash('Case updated.', 'success')
    return redirect(url_for('case_detail', case_id=case_id))

# ── ROUTES: REPORTS ───────────────────────────────────────────────
@app.route('/reports')
@login_required
def reports():
    org     = current_user.organisation
    all_reports = ComplianceReport.query.filter_by(org_id=org.id).order_by(ComplianceReport.generated_at.desc()).all()
    return render_template('reports.html', org=org, reports=all_reports)

@app.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    org = current_user.organisation
    if not PLAN_LIMITS.get(org.plan, {}).get('reports'):
        flash('Compliance reports require Professional plan or above.', 'warning')
        return redirect(url_for('reports'))
    report_type  = request.form.get('report_type', 'CBN Monthly')
    period_start = datetime.strptime(request.form.get('period_start'), '%Y-%m-%d').date()
    period_end   = datetime.strptime(request.form.get('period_end'), '%Y-%m-%d').date()
    try:
        from pdf_reports import generate_fraud_report
        from datetime import datetime as dt
        cases = FraudCase.query.filter(
            FraudCase.org_id == org.id,
            FraudCase.created_at >= period_start,
            FraudCase.created_at <= period_end
        ).all()
        filename = f"defenceiq_{org.id}_{dt.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
        output_path = os.path.join('/var/www/defenceiq/static/reports', filename)
        generate_fraud_report(org, cases, report_type, period_start, period_end, output_path)
        file_path = f'/static/reports/{filename}'
    except Exception as e:
        file_path = None
        flash(f'PDF generation error: {str(e)}', 'error')
        return redirect(url_for('reports'))
    report = ComplianceReport(
        org_id=org.id, report_type=report_type,
        period_start=period_start, period_end=period_end,
        generated_by=current_user.id, file_path=file_path
    )
    db.session.add(report)
    db.session.commit()
    log_audit(org.id, current_user.id, 'REPORT_GENERATED', report_type)
    flash(f'{report_type} generated successfully — {len(cases)} cases included.', 'success')
    return redirect(url_for('reports'))

@app.route('/reports/<int:report_id>/download')
@login_required
def download_report(report_id):
    report = ComplianceReport.query.filter_by(id=report_id, org_id=current_user.organisation.id).first_or_404()
    if not report.file_path:
        flash('PDF file not available for this report.', 'error')
        return redirect(url_for('reports'))
    from flask import send_file
    full_path = '/var/www/defenceiq' + report.file_path
    if not os.path.exists(full_path):
        flash('PDF file not found on server.', 'error')
        return redirect(url_for('reports'))
    return send_file(full_path, as_attachment=True,
        download_name=f"DefenceIQ_{report.report_type.replace(' ','_')}_{report.period_start}.pdf")

# ── ROUTES: TRAINING ──────────────────────────────────────────────
@app.route('/training')
@login_required
def training():
    modules  = TrainingModule.query.filter_by(is_active=True).all()
    progress = {p.module_id: p for p in TrainingProgress.query.filter_by(user_id=current_user.id).all()}
    return render_template('training.html', modules=modules, progress=progress)

@app.route('/training/<int:module_id>')
@login_required
def training_module(module_id):
    module = TrainingModule.query.get_or_404(module_id)
    prog   = TrainingProgress.query.filter_by(user_id=current_user.id, module_id=module_id).first()
    if not prog:
        prog = TrainingProgress(user_id=current_user.id, module_id=module_id)
        db.session.add(prog)
        db.session.commit()
    return render_template('training_module.html', module=module, progress=prog)

@app.route('/training/<int:module_id>/complete', methods=['POST'])
@login_required
def complete_module(module_id):
    prog = TrainingProgress.query.filter_by(user_id=current_user.id, module_id=module_id).first_or_404()
    score = int(request.form.get('score', 0))
    prog.completed    = True
    prog.score        = score
    prog.completed_at = datetime.utcnow()
    db.session.commit()
    log_audit(current_user.org_id, current_user.id, 'TRAINING_COMPLETED', f'Module {module_id} score {score}%')
    flash(f'Module completed! You scored {score}%.', 'success')
    return redirect(url_for('training'))

# ── ROUTES: SETTINGS ──────────────────────────────────────────────
@app.route('/settings/team')
@login_required
@role_required('admin')
def team_settings():
    members = User.query.filter_by(org_id=current_user.org_id).all()
    return render_template('team_settings.html', members=members, org=current_user.organisation)

@app.route('/settings/team/invite', methods=['POST'])
@login_required
@role_required('admin')
def invite_member():
    email     = request.form.get('email', '').strip().lower()
    role      = request.form.get('role', 'analyst')
    org       = current_user.organisation
    limits    = PLAN_LIMITS.get(org.plan, PLAN_LIMITS['free'])
    if limits['users'] != -1:
        count = User.query.filter_by(org_id=org.id).count()
        if count >= limits['users']:
            flash(f'User limit reached for your plan. Please upgrade.', 'warning')
            return redirect(url_for('team_settings'))
    if User.query.filter_by(email=email).first():
        flash('This email is already registered.', 'error')
        return redirect(url_for('team_settings'))
    temp_pass = secrets.token_urlsafe(12)
    user = User(email=email, full_name=email.split('@')[0], role=role,
                org_id=org.id, is_verified=False, force_password_change=True)
    user.set_password(temp_pass)
    db.session.add(user)
    db.session.commit()
    try:
        msg = Message('You have been invited to DefenceIQ', recipients=[email])
        msg.html = render_template('email/invite.html', email=email, temp_pass=temp_pass,
                                   org=org, inviter=current_user)
        mail.send(msg)
    except Exception as e:
        print(f"Invite email error: {e}")
    log_audit(org.id, current_user.id, 'MEMBER_INVITED', email)
    flash(f'Invitation sent to {email}.', 'success')
    return redirect(url_for('team_settings'))

@app.route('/settings/api')
@login_required
@role_required('admin')
def api_settings():
    org = current_user.organisation
    return render_template('api_settings.html', org=org)

@app.route('/settings/webhooks', methods=['GET', 'POST'])
@login_required
def webhook_settings():
    org = current_user.organisation
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            platform = request.form.get('platform')
            webhook_url = request.form.get('webhook_url', '').strip()
            name = request.form.get('name', '').strip()
            if webhook_url:
                wh = WebhookConfig(org_id=org.id, platform=platform,
                    webhook_url=webhook_url, name=name or f'{platform.title()} Webhook')
                db.session.add(wh)
                db.session.commit()
                log_audit(org.id, current_user.id, 'WEBHOOK_ADDED', platform)
                flash(f'{platform.title()} webhook added successfully.', 'success')
        elif action == 'delete':
            wh_id = request.form.get('webhook_id')
            wh = WebhookConfig.query.filter_by(id=wh_id, org_id=org.id).first()
            if wh:
                db.session.delete(wh)
                db.session.commit()
                flash('Webhook removed.', 'success')
        elif action == 'test':
            wh_id = request.form.get('webhook_id')
            wh = WebhookConfig.query.filter_by(id=wh_id, org_id=org.id).first()
            if wh:
                from app import FraudCase
                test_case = type('obj', (object,), {
                    'id': 0, 'case_ref': 'DIQ-TEST0001', 'fraud_type': 'Test Alert',
                    'severity': 'medium', 'indicator_type': 'phone',
                    'indicator_value': '08000000000', 'amount_lost': 100000,
                    'currency': 'NGN', 'ai_score': 55
                })()
                if wh.platform == 'slack':
                    ok = send_slack_alert(wh.webhook_url, test_case, org)
                else:
                    ok = send_teams_alert(wh.webhook_url, test_case, org)
                flash('Test alert sent!' if ok else 'Test failed — check webhook URL.', 'success' if ok else 'error')
        return redirect(url_for('webhook_settings'))
    webhooks = WebhookConfig.query.filter_by(org_id=org.id).all()
    return render_template('webhook_settings.html', org=org, webhooks=webhooks)

@app.route('/threat-intel')
@login_required
def threat_intel():
    org = current_user.organisation
    scans = ThreatScan.query.filter_by(org_id=org.id).order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('threat_intel.html', org=org, scans=scans)

@app.route('/threat-intel/scan', methods=['POST'])
@login_required
def run_threat_scan():
    org = current_user.organisation
    indicator_type  = request.form.get('indicator_type')
    indicator_value = request.form.get('indicator_value', '').strip()
    case_id         = request.form.get('case_id')
    if not indicator_value:
        flash('Please enter an indicator value to scan.', 'error')
        return redirect(url_for('threat_intel'))
    try:
        from darkweb_monitor import scan_indicator
        api_keys = {
            'abuseipdb':  os.getenv('ABUSEIPDB_API_KEY'),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'emailrep':   os.getenv('EMAILREP_API_KEY'),
        }
        scan_result = scan_indicator(indicator_type, indicator_value, api_keys)
        scan = ThreatScan(
            org_id          = org.id,
            case_id         = int(case_id) if case_id else None,
            indicator_type  = indicator_type,
            indicator_value = indicator_value,
            overall_risk    = scan_result.get('overall_risk'),
            sources_checked = scan_result.get('sources_checked'),
            raw_results     = json.dumps(scan_result.get('results', [])),
            scanned_by      = current_user.id
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'THREAT_SCAN', f'{indicator_type}:{indicator_value}')
        flash(f'Scan complete — Overall risk: {scan_result.get("overall_risk").upper()}', 'success')
    except Exception as e:
        flash(f'Scan error: {str(e)}', 'error')
    return redirect(url_for('threat_intel'))

@app.route('/threat-intel/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=current_user.org_id).first_or_404()
    results = json.loads(scan.raw_results) if scan.raw_results else []
    return render_template('scan_detail.html', scan=scan, results=results)


@app.route('/dark-web')
@login_required
def dark_web():
    org = current_user.organisation
    scans = ThreatScan.query.filter_by(org_id=org.id, scan_type='dark_web').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    latest_scan = scans[0] if scans else None
    log_audit(org.id, current_user.id, 'VIEW_DARK_WEB', '')
    return render_template('dark_web.html', scans=scans, latest_scan=latest_scan)

@app.route('/dark-web/scan', methods=['POST'])
@login_required
def dark_web_scan_run():
    org = current_user.organisation
    indicator_type  = request.form.get('indicator_type', '').strip()
    indicator_value = request.form.get('indicator_value', '').strip()
    case_id         = request.form.get('case_id', '').strip()
    if not indicator_value:
        flash('Please enter an indicator value.', 'error')
        return redirect(url_for('dark_web'))
    try:
        from darkweb_monitor import dark_web_scan
        api_keys = {
            'abuseipdb':  os.getenv('ABUSEIPDB_API_KEY'),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'emailrep':   os.getenv('EMAILREP_API_KEY'),
        }
        result = dark_web_scan(indicator_type, indicator_value, api_keys)
        scan = ThreatScan(
            org_id          = org.id,
            case_id         = int(case_id) if case_id and case_id.isdigit() else None,
            indicator_type  = indicator_type,
            indicator_value = indicator_value,
            overall_risk    = result.get('overall_risk'),
            sources_checked = result.get('sources_checked'),
            raw_results     = json.dumps(result),
            scanned_by      = current_user.id,
            scan_type       = 'dark_web'
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'DARK_WEB_SCAN', f'{indicator_type}:{indicator_value}')
        flash(f'Dark web scan complete — Risk: {result.get("overall_risk","unknown").upper()}', 'success')
    except Exception as e:
        flash(f'Scan error: {str(e)}', 'error')
    return redirect(url_for('dark_web'))

@app.route('/dark-web/<int:scan_id>')
@login_required
def dark_web_scan_detail(scan_id):
    org = current_user.organisation
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=org.id).first_or_404()
    raw = json.loads(scan.raw_results) if scan.raw_results else {}
    return render_template('scan_detail.html', scan=scan, raw=raw)


@app.route('/ip-reputation')
@login_required
def ip_reputation():
    org = current_user.organisation
    scans = ThreatScan.query.filter_by(org_id=org.id, scan_type='ip_reputation').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('ip_reputation.html', scans=scans, result=None, last_ip=None)

@app.route('/ip-reputation/scan', methods=['POST'])
@login_required
def ip_reputation_scan():
    org = current_user.organisation
    ip_address = request.form.get('ip_address', '').strip()
    case_id    = request.form.get('case_id', '').strip()
    if not ip_address:
        flash('Please enter an IP address.', 'error')
        return redirect(url_for('ip_reputation'))
    try:
        from darkweb_monitor import full_ip_reputation
        api_keys = {'abuseipdb': os.getenv('ABUSEIPDB_API_KEY')}
        result = full_ip_reputation(ip_address, api_keys)
        scan = ThreatScan(
            org_id          = org.id,
            case_id         = int(case_id) if case_id and case_id.isdigit() else None,
            indicator_type  = 'ip',
            indicator_value = ip_address,
            overall_risk    = result.get('overall_risk'),
            sources_checked = result.get('sources_checked'),
            raw_results     = json.dumps(result),
            scanned_by      = current_user.id,
            scan_type       = 'ip_reputation'
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'IP_REPUTATION_SCAN', ip_address)
        scans = ThreatScan.query.filter_by(org_id=org.id, scan_type='ip_reputation').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
        return render_template('ip_reputation.html', scans=scans, result=result, last_ip=ip_address)
    except Exception as e:
        flash(f'Scan error: {str(e)}', 'error')
        return redirect(url_for('ip_reputation'))

@app.route('/ip-reputation/<int:scan_id>')
@login_required
def ip_reputation_detail(scan_id):
    org = current_user.organisation
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=org.id).first_or_404()
    raw = json.loads(scan.raw_results) if scan.raw_results else {}
    scans = ThreatScan.query.filter_by(org_id=org.id, scan_type='ip_reputation').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('ip_reputation.html', scans=scans, result=raw, last_ip=scan.indicator_value)









@app.route('/network')
@login_required
def network():
    org = current_user.organisation
    from network_links import get_network_stats
    stats = get_network_stats(org.id, db.session)
    return render_template('network.html', result=None, last_query=None, stats=stats)

@app.route('/network/search', methods=['POST'])
@login_required
def network_search():
    org   = current_user.organisation
    query = request.form.get('query','').strip()
    if not query:
        return redirect(url_for('network'))
    from network_links import build_entity_network, get_network_stats
    result = build_entity_network(query, org.id, db.session)
    log_audit(org.id, current_user.id, 'NETWORK_SEARCH', query)
    stats  = get_network_stats(org.id, db.session)
    return render_template('network.html', result=result, last_query=query, stats=stats)


@app.route('/cases/<int:case_id>/sar/generate', methods=['GET','POST'])
@login_required
def sar_generate(case_id):
    org  = current_user.organisation
    case = FraudCase.query.filter_by(id=case_id, org_id=org.id).first_or_404()
    sar  = None

    if request.method == 'POST':
        try:
            from sar_generator import generate_sar_narrative

            # Build case dict
            case_data = {
                'case_ref':       case.case_ref,
                'subject_name':   case.subject_name,
                'subject_email':  getattr(case,'subject_email',''),
                'subject_ip':     getattr(case,'subject_ip',''),
                'fraud_type':     case.fraud_type,
                'amount_involved':str(getattr(case,'amount_involved','') or ''),
                'risk_level':     case.risk_level or 'unknown',
                'status':         case.status,
                'description':    getattr(case,'description',''),
                'created_at':     case.created_at.strftime('%d %b %Y') if case.created_at else ''
            }

            # Pull latest intelligence for this case
            intel = {}
            latest_scan = ThreatScan.query.filter_by(
                org_id=org.id, case_id=case_id
            ).order_by(ThreatScan.scanned_at.desc()).first()
            if latest_scan and latest_scan.raw_results:
                intel['latest_scan'] = json.loads(latest_scan.raw_results)

            # AML flags
            aml_txns = AMLTransaction.query.filter_by(
                org_id=org.id, case_id=case_id
            ).order_by(AMLTransaction.created_at.desc()).limit(3).all()
            if aml_txns:
                all_flags = []
                for t in aml_txns:
                    if t.flags:
                        flags_data = json.loads(t.flags) if isinstance(t.flags, str) else t.flags
                        all_flags.extend([f.get('rule','') for f in flags_data if isinstance(f,dict)])
                if all_flags:
                    intel['aml_flags'] = list(set(all_flags))[:6]

            # KYC
            kyc = KYCProfile.query.filter_by(org_id=org.id).filter(
                KYCProfile.email == case.subject_email
            ).first() if getattr(case,'subject_email',None) else None
            if kyc:
                intel['kyc'] = {
                    'pep_status': kyc.pep_status,
                    'sanctions_hit': kyc.sanctions_hit,
                    'risk_rating': kyc.risk_rating,
                    'dd_level': getattr(kyc,'dd_level','Standard')
                }

            sar = generate_sar_narrative(case_data, intel)
            log_audit(org.id, current_user.id, 'SAR_GENERATED', case.case_ref)

        except Exception as e:
            sar = {'success': False, 'error': str(e)}

    return render_template('sar_generate.html', case=case, sar=sar)

@app.route('/adverse-media')
@login_required
def adverse_media():
    org = current_user.organisation
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='adverse_media').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    total   = len(history)
    hits    = sum(1 for h in history if h.overall_risk not in ('clean', None))
    critical= sum(1 for h in history if h.overall_risk == 'critical')
    stats   = type('S',(),{'total':total,'hits':hits,'critical':critical})()
    return render_template('adverse_media.html', history=history, result=None, last_query=None, stats=stats)

@app.route('/adverse-media/screen', methods=['POST'])
@login_required
def adverse_media_screen():
    org   = current_user.organisation
    query = request.form.get('query','').strip()
    case_id = request.form.get('case_id','').strip()
    if not query:
        flash('Please enter a name to screen.', 'error')
        return redirect(url_for('adverse_media'))
    try:
        from adverse_media import screen_adverse_media
        keys = {
            'anthropic': os.getenv('ANTHROPIC_API_KEY'),
            'newsapi':   os.getenv('NEWSAPI_KEY','')
        }
        result = screen_adverse_media(query, keys)
        scan = ThreatScan(
            org_id          = org.id,
            case_id         = int(case_id) if case_id and case_id.isdigit() else None,
            indicator_type  = 'name',
            indicator_value = query,
            overall_risk    = result.get('overall_risk'),
            sources_checked = result.get('sources_checked', 3),
            raw_results     = json.dumps(result),
            scanned_by      = current_user.id,
            scan_type       = 'adverse_media'
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'ADVERSE_MEDIA_SCREEN', query)
        history = ThreatScan.query.filter_by(org_id=org.id, scan_type='adverse_media').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
        total   = len(history)
        hits    = sum(1 for h in history if h.overall_risk not in ('clean', None))
        critical= sum(1 for h in history if h.overall_risk == 'critical')
        stats   = type('S',(),{'total':total,'hits':hits,'critical':critical})()
        return render_template('adverse_media.html', history=history, result=result, last_query=query, stats=stats)
    except Exception as e:
        flash(f'Screening error: {str(e)}', 'error')
        return redirect(url_for('adverse_media'))

@app.route('/adverse-media/<int:scan_id>')
@login_required
def adverse_media_detail(scan_id):
    org  = current_user.organisation
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=org.id).first_or_404()
    raw  = json.loads(scan.raw_results) if scan.raw_results else {}
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='adverse_media').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    total   = len(history)
    hits    = sum(1 for h in history if h.overall_risk not in ('clean', None))
    critical= sum(1 for h in history if h.overall_risk == 'critical')
    stats   = type('S',(),{'total':total,'hits':hits,'critical':critical})()
    return render_template('adverse_media.html', history=history, result=raw, last_query=scan.indicator_value, stats=stats)

@app.route('/device-fingerprints')
@login_required
def device_fingerprints():
    org = current_user.organisation
    from device_fingerprint import get_device_stats
    from sqlalchemy import text
    f = request.args.get('filter', '')
    where = 'WHERE org_id=:o'
    if f: where += f" AND risk_level=:f"
    params = {'o': org.id, 'f': f} if f else {'o': org.id}
    rows = db.session.execute(text(
        f'SELECT * FROM device_fingerprints {where} ORDER BY created_at DESC LIMIT 200'
    ), params).fetchall()
    fingerprints = [type('F',(),dict(r._mapping))() for r in rows]
    stats = get_device_stats(org.id, db.session)
    return render_template('device_fingerprints.html', fingerprints=fingerprints, stats=stats, current_filter=f)

@app.route('/device-fingerprints/<int:fp_id>')
@login_required
def device_fingerprint_detail(fp_id):
    org = current_user.organisation
    from sqlalchemy import text
    import json as _json
    row = db.session.execute(text(
        'SELECT * FROM device_fingerprints WHERE id=:id AND org_id=:o'
    ), {'id': fp_id, 'o': org.id}).fetchone()
    if not row: abort(404)
    fp = type('F',(),dict(row._mapping))()
    flags = _json.loads(fp.flags) if isinstance(fp.flags, str) else (fp.flags or [])
    return render_template('device_fingerprint_detail.html', fp=fp, flags=flags)

@app.route('/api/fingerprint', methods=['POST'])
@login_required
def api_fingerprint():
    """Receives fingerprint data from the JS collector."""
    import json as _json
    from device_fingerprint import analyse_fingerprint, compute_fingerprint_hash
    from sqlalchemy import text
    org = current_user.organisation
    data = request.get_json(silent=True) or {}
    user_agent = request.headers.get('User-Agent', '')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    result = analyse_fingerprint(data, user_agent=user_agent)
    try:
        db.session.execute(text("""
            INSERT INTO device_fingerprints
            (org_id, user_id, fingerprint_hash, user_agent, screen_resolution,
             color_depth, timezone, platform, language, canvas_hash, webgl_vendor,
             plugins_count, fonts_count, touch_support, webdriver,
             ip_address, risk_score, risk_level, flags)
            VALUES (:org_id,:uid,:hash,:ua,:res,:cd,:tz,:plat,:lang,:canvas,:webgl,
                    :plugins,:fonts,:touch,:wd,:ip,:rs,:rl,:flags::jsonb)
        """), {
            'org_id': org.id, 'uid': current_user.id,
            'hash': result['fingerprint_hash'],
            'ua': user_agent[:500],
            'res': data.get('screen_resolution',''),
            'cd': data.get('color_depth'),
            'tz': data.get('timezone',''),
            'plat': data.get('platform',''),
            'lang': data.get('language',''),
            'canvas': data.get('canvas_hash',''),
            'webgl': data.get('webgl_vendor',''),
            'plugins': data.get('plugins_count'),
            'fonts': data.get('fonts_count'),
            'touch': bool(data.get('touch_support', False)),
            'wd': bool(data.get('webdriver', False)),
            'ip': ip,
            'rs': result['risk_score'],
            'rl': result['risk_level'],
            'flags': _json.dumps(result['flags']),
        })
        db.session.commit()
        if result['risk_level'] in ('critical', 'high'):
            log_audit(org.id, current_user.id, 'DEVICE_RISK_FLAGGED', result['fingerprint_hash'])
    except Exception as e:
        db.session.rollback()
    return json.dumps({'status': 'ok', 'risk': result['risk_level']}), 200, {'Content-Type': 'application/json'}

@app.route('/kyc')
@login_required
def kyc():
    org = current_user.organisation
    from kyc_engine import get_kyc_stats, get_completion_pct
    from sqlalchemy import text
    f = request.args.get('filter','')
    where = 'WHERE org_id=:o'
    params = {'o': org.id}
    if f == 'pending':   where += " AND kyc_status='pending'"
    elif f == 'approved': where += " AND kyc_status='approved'"
    elif f == 'enhanced': where += " AND due_diligence='enhanced'"
    rows = db.session.execute(text(f'SELECT * FROM kyc_profiles {where} ORDER BY created_at DESC LIMIT 100'), params).fetchall()
    profiles = [type('P',(),dict(r._mapping))() for r in rows]
    completion = {p.id: get_completion_pct(p.id, db.session) for p in profiles}
    stats = get_kyc_stats(org.id, db.session)
    return render_template('kyc.html', profiles=profiles, completion=completion, stats=stats, current_filter=f)

@app.route('/kyc/add', methods=['GET','POST'])
@login_required
def kyc_add():
    org = current_user.organisation
    if request.method == 'POST':
        try:
            from kyc_engine import calculate_risk_score, get_document_checklist
            from sqlalchemy import text
            import uuid as _uuid
            profile_data = {
                'nationality':           request.form.get('nationality','').strip(),
                'country_of_residence':  request.form.get('country_of_residence','').strip(),
                'pep_status':            bool(request.form.get('pep_status')),
                'sanctions_hit':         bool(request.form.get('sanctions_hit')),
                'customer_type':         request.form.get('customer_type','individual'),
            }
            risk = calculate_risk_score(profile_data)
            ref  = f'KYC-{_uuid.uuid4().hex[:8].upper()}'
            dob  = request.form.get('date_of_birth') or None
            row  = db.session.execute(text("""
                INSERT INTO kyc_profiles
                (org_id,created_by,profile_ref,full_name,date_of_birth,nationality,
                 country_of_residence,id_number,email,phone,address,customer_type,
                 due_diligence,risk_rating,risk_score,pep_status,sanctions_hit,notes,review_due)
                VALUES (:org_id,:by,:ref,:name,:dob,:nat,:cor,:idn,:email,:phone,:addr,
                        :ctype,:dd,:rr,:rs,:pep,:sanc,:notes,:review)
                RETURNING id
            """), {
                'org_id': org.id, 'by': current_user.id, 'ref': ref,
                'name':  request.form.get('full_name','').strip(),
                'dob':   dob,
                'nat':   profile_data['nationality'],
                'cor':   profile_data['country_of_residence'],
                'idn':   request.form.get('id_number','').strip(),
                'email': request.form.get('email','').strip(),
                'phone': request.form.get('phone','').strip(),
                'addr':  request.form.get('address','').strip(),
                'ctype': profile_data['customer_type'],
                'dd':    risk['due_diligence'],
                'rr':    risk['risk_rating'],
                'rs':    risk['risk_score'],
                'pep':   profile_data['pep_status'],
                'sanc':  profile_data['sanctions_hit'],
                'notes': request.form.get('notes','').strip(),
                'review':risk['review_due'],
            })
            profile_id = row.fetchone()[0]
            # Create document checklist
            docs = get_document_checklist(profile_data['customer_type'], risk['due_diligence'])
            for doc_type, doc_label, required in docs:
                db.session.execute(text("""
                    INSERT INTO kyc_documents (profile_id,org_id,doc_type,doc_label,status)
                    VALUES (:pid,:oid,:dt,:dl,:st)
                """), {'pid': profile_id, 'oid': org.id, 'dt': doc_type,
                       'dl': doc_label, 'st': 'required'})
            db.session.commit()
            log_audit(org.id, current_user.id, 'KYC_PROFILE_CREATED', ref)
            flash(f'KYC profile created: {risk["risk_rating"].upper()} risk, {risk["due_diligence"].upper()} DD, {len(docs)} documents required', 'success')
            return redirect(url_for('kyc_detail', profile_id=profile_id))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    return render_template('kyc_add.html')

@app.route('/kyc/<int:profile_id>')
@login_required
def kyc_detail(profile_id):
    org = current_user.organisation
    from kyc_engine import get_completion_pct
    from sqlalchemy import text
    row = db.session.execute(text('SELECT * FROM kyc_profiles WHERE id=:id AND org_id=:o'), {'id':profile_id,'o':org.id}).fetchone()
    if not row: abort(404)
    profile = type('P',(),dict(row._mapping))()
    doc_rows = db.session.execute(text('SELECT * FROM kyc_documents WHERE profile_id=:pid ORDER BY id'), {'pid':profile_id}).fetchall()
    documents = [type('D',(),dict(r._mapping))() for r in doc_rows]
    completion_pct = get_completion_pct(profile_id, db.session)
    return render_template('kyc_detail.html', profile=profile, documents=documents, completion_pct=completion_pct)

@app.route('/kyc/<int:profile_id>/approve', methods=['POST'])
@login_required
def kyc_approve(profile_id):
    org = current_user.organisation
    from sqlalchemy import text
    db.session.execute(text("""
        UPDATE kyc_profiles SET kyc_status='approved', approved_by=:by, approved_at=NOW(), updated_at=NOW()
        WHERE id=:id AND org_id=:o
    """), {'id':profile_id,'o':org.id,'by':current_user.id})
    db.session.commit()
    log_audit(org.id, current_user.id, 'KYC_APPROVED', str(profile_id))
    flash('KYC profile approved.', 'success')
    return redirect(url_for('kyc_detail', profile_id=profile_id))

@app.route('/kyc/<int:profile_id>/reject', methods=['POST'])
@login_required
def kyc_reject(profile_id):
    org = current_user.organisation
    from sqlalchemy import text
    db.session.execute(text("""
        UPDATE kyc_profiles SET kyc_status='rejected', rejected_at=NOW(), updated_at=NOW()
        WHERE id=:id AND org_id=:o
    """), {'id':profile_id,'o':org.id})
    db.session.commit()
    log_audit(org.id, current_user.id, 'KYC_REJECTED', str(profile_id))
    flash('KYC profile rejected.', 'error')
    return redirect(url_for('kyc_detail', profile_id=profile_id))

@app.route('/kyc/<int:profile_id>/doc/<int:doc_id>/update', methods=['POST'])
@login_required
def kyc_doc_update(profile_id, doc_id):
    org = current_user.organisation
    from sqlalchemy import text
    status = request.form.get('status','uploaded')
    extra  = ', verified_at=NOW(), verified_by=:by' if status=='verified' else ''
    db.session.execute(text(f"""
        UPDATE kyc_documents SET status=:st, uploaded_at=COALESCE(uploaded_at,NOW()){extra}
        WHERE id=:did AND profile_id=:pid AND org_id=:oid
    """), {'st':status,'did':doc_id,'pid':profile_id,'oid':org.id,'by':current_user.id})
    db.session.commit()
    return redirect(url_for('kyc_detail', profile_id=profile_id))

@app.route('/aml')
@login_required
def aml():
    org = current_user.organisation
    from aml_engine import get_aml_stats
    from sqlalchemy import text
    f = request.args.get('filter','')
    q = db.session.execute(text(
        "SELECT * FROM aml_transactions WHERE org_id=:o " +
        ("AND risk_level=:f " if f else "") +
        ("AND reviewed=FALSE AND risk_level NOT IN ('clean','low') " if f=='pending' else "") +
        "ORDER BY created_at DESC LIMIT 100"
    ), {'o': org.id, 'f': f} if f and f!='pending' else {'o': org.id}).fetchall()
    from sqlalchemy.engine.row import Row
    transactions = [type('T', (), dict(r._mapping))() for r in q]
    stats = get_aml_stats(org.id, db.session)
    return render_template('aml.html', transactions=transactions, stats=stats, current_filter=f)

@app.route('/aml/add', methods=['GET','POST'])
@login_required
def aml_add():
    org = current_user.organisation
    if request.method == 'POST':
        try:
            from aml_engine import screen_transaction
            from sqlalchemy import text
            import uuid as _uuid
            amt      = float(request.form.get('amount',0))
            amt_gbp  = float(request.form.get('amount_gbp') or amt)
            currency = request.form.get('currency','GBP')
            if currency == 'GBP': amt_gbp = amt
            txn_ref  = request.form.get('txn_ref','').strip() or f'TXN-{_uuid.uuid4().hex[:8].upper()}'
            txn_data = {
                'amount': amt, 'amount_gbp': amt_gbp, 'currency': currency,
                'sender_account':  request.form.get('sender_account','').strip(),
                'sender_country':  request.form.get('sender_country','').strip(),
                'receiver_country':request.form.get('receiver_country','').strip(),
                'txn_type':        request.form.get('txn_type','').strip(),
                'description':     request.form.get('description','').strip(),
            }
            result = screen_transaction(txn_data, org.id, db.session)
            import json as _json
            db.session.execute(text("""
                INSERT INTO aml_transactions
                (org_id,submitted_by,txn_ref,txn_date,amount,currency,amount_gbp,
                 sender_name,sender_account,sender_country,
                 receiver_name,receiver_account,receiver_country,
                 txn_type,description,risk_score,risk_level,flags)
                VALUES (:org_id,:sub,:ref,:date,:amt,:cur,:amt_gbp,
                        :sn,:sa,:sc,:rn,:ra,:rc,:tt,:desc,:rs,:rl,:flags::jsonb)
            """), {
                'org_id': org.id, 'sub': current_user.id,
                'ref': txn_ref,
                'date': request.form.get('txn_date'),
                'amt': amt, 'cur': currency, 'amt_gbp': amt_gbp,
                'sn': request.form.get('sender_name',''),
                'sa': request.form.get('sender_account',''),
                'sc': request.form.get('sender_country',''),
                'rn': request.form.get('receiver_name',''),
                'ra': request.form.get('receiver_account',''),
                'rc': request.form.get('receiver_country',''),
                'tt': request.form.get('txn_type',''),
                'desc': request.form.get('description',''),
                'rs': result['risk_score'],
                'rl': result['risk_level'],
                'flags': _json.dumps(result['flags']),
            })
            db.session.commit()
            log_audit(org.id, current_user.id, 'AML_TXN_ADD', txn_ref)
            flash(f'Transaction screened: {result["risk_level"].upper()} ({result["risk_score"]}/100) — {result["flag_count"]} flag(s)', 'success' if result['risk_score'] < 50 else 'error')
            return redirect(url_for('aml'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    return render_template('aml_add.html')

@app.route('/aml/<int:txn_id>')
@login_required
def aml_detail(txn_id):
    org = current_user.organisation
    from sqlalchemy import text
    import json as _json
    row = db.session.execute(text(
        'SELECT * FROM aml_transactions WHERE id=:id AND org_id=:o'
    ), {'id': txn_id, 'o': org.id}).fetchone()
    if not row: abort(404)
    txn = type('T', (), dict(row._mapping))()
    flags = _json.loads(txn.flags) if isinstance(txn.flags, str) else (txn.flags or [])
    return render_template('aml_detail.html', txn=txn, flags=flags)

@app.route('/aml/<int:txn_id>/review', methods=['POST'])
@login_required
def aml_review(txn_id):
    org = current_user.organisation
    from sqlalchemy import text
    db.session.execute(text(
        'UPDATE aml_transactions SET reviewed=TRUE, updated_at=NOW() WHERE id=:id AND org_id=:o'
    ), {'id': txn_id, 'o': org.id})
    db.session.commit()
    log_audit(org.id, current_user.id, 'AML_REVIEWED', str(txn_id))
    flash('Transaction marked as reviewed.', 'success')
    return redirect(url_for('aml_detail', txn_id=txn_id))

@app.route('/aml/<int:txn_id>/sar', methods=['POST'])
@login_required
def aml_sar(txn_id):
    org = current_user.organisation
    from sqlalchemy import text
    db.session.execute(text(
        'UPDATE aml_transactions SET sar_filed=TRUE, reviewed=TRUE, updated_at=NOW() WHERE id=:id AND org_id=:o'
    ), {'id': txn_id, 'o': org.id})
    db.session.commit()
    log_audit(org.id, current_user.id, 'SAR_FILED', str(txn_id))
    flash('SAR filed. Transaction marked reviewed.', 'success')
    return redirect(url_for('aml_detail', txn_id=txn_id))

@app.route('/behavioural')
@login_required
def behavioural():
    org = current_user.organisation
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='behavioural').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('behavioural.html', history=history, result=None, last_query=None)

@app.route('/behavioural/score', methods=['POST'])
@login_required
def behavioural_score():
    org          = current_user.organisation
    entity_value = request.form.get('entity_value', '').strip()
    if not entity_value:
        flash('Please enter an entity value.', 'error')
        return redirect(url_for('behavioural'))
    try:
        from behavioural_scorer import score_entity
        result = score_entity(entity_value, org.id, db.session, FraudCase, ThreatScan)
        scan = ThreatScan(
            org_id          = org.id,
            indicator_type  = 'entity',
            indicator_value = entity_value,
            overall_risk    = result.get('overall_risk'),
            sources_checked = len(result.get('signals', [])),
            raw_results     = json.dumps(result),
            scanned_by      = current_user.id,
            scan_type       = 'behavioural'
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'BEHAVIOURAL_SCORE', entity_value)
        history = ThreatScan.query.filter_by(org_id=org.id, scan_type='behavioural').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
        return render_template('behavioural.html', history=history, result=result, last_query=entity_value)
    except Exception as e:
        flash(f'Scoring error: {str(e)}', 'error')
        return redirect(url_for('behavioural'))

@app.route('/behavioural/<int:scan_id>')
@login_required
def behavioural_detail(scan_id):
    org  = current_user.organisation
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=org.id).first_or_404()
    raw  = json.loads(scan.raw_results) if scan.raw_results else {}
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='behavioural').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('behavioural.html', history=history, result=raw, last_query=scan.indicator_value)

@app.route('/phishing')
@login_required
def phishing():
    org = current_user.organisation
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='phishing').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('phishing.html', history=history, result=None, last_query=None)

@app.route('/phishing/scan', methods=['POST'])
@login_required
def phishing_scan():
    org     = current_user.organisation
    target  = request.form.get('target', '').strip()
    case_id = request.form.get('case_id', '').strip()
    if not target:
        flash('Please enter a domain to scan.', 'error')
        return redirect(url_for('phishing'))
    try:
        from phishing_checker import full_domain_scan
        api_keys = {'virustotal': os.getenv('VIRUSTOTAL_API_KEY')}
        result = full_domain_scan(target, api_keys)
        scan = ThreatScan(
            org_id          = org.id,
            case_id         = int(case_id) if case_id and case_id.isdigit() else None,
            indicator_type  = 'domain',
            indicator_value = result['domain'],
            overall_risk    = result.get('overall_risk'),
            sources_checked = result.get('sources_checked', 7),
            raw_results     = json.dumps(result),
            scanned_by      = current_user.id,
            scan_type       = 'phishing'
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'PHISHING_SCAN', result['domain'])
        history = ThreatScan.query.filter_by(org_id=org.id, scan_type='phishing').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
        return render_template('phishing.html', history=history, result=result, last_query=target)
    except Exception as e:
        flash(f'Scan error: {str(e)}', 'error')
        return redirect(url_for('phishing'))

@app.route('/phishing/<int:scan_id>')
@login_required
def phishing_detail(scan_id):
    org  = current_user.organisation
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=org.id).first_or_404()
    raw  = json.loads(scan.raw_results) if scan.raw_results else {}
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='phishing').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    return render_template('phishing.html', history=history, result=raw, last_query=scan.indicator_value)

@app.route('/sanctions')
@login_required
def sanctions():
    org = current_user.organisation
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='sanctions').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    from sanctions_checker import get_list_stats
    stats = get_list_stats()
    return render_template('sanctions.html', history=history, result=None, last_query=None, stats=stats)

@app.route('/sanctions/screen', methods=['POST'])
@login_required
def sanctions_screen():
    org        = current_user.organisation
    query_name = request.form.get('query_name', '').strip()
    threshold  = int(request.form.get('threshold', 82))
    case_id    = request.form.get('case_id', '').strip()
    if not query_name:
        flash('Please enter a name to screen.', 'error')
        return redirect(url_for('sanctions'))
    try:
        from sanctions_checker import screen_name, get_list_stats
        result = screen_name(query_name, threshold=threshold)
        scan = ThreatScan(
            org_id          = org.id,
            case_id         = int(case_id) if case_id and case_id.isdigit() else None,
            indicator_type  = 'name',
            indicator_value = query_name,
            overall_risk    = result.get('overall_risk'),
            sources_checked = 2,
            raw_results     = json.dumps(result),
            scanned_by      = current_user.id,
            scan_type       = 'sanctions'
        )
        db.session.add(scan)
        db.session.commit()
        log_audit(org.id, current_user.id, 'SANCTIONS_SCREEN', query_name)
        history = ThreatScan.query.filter_by(org_id=org.id, scan_type='sanctions').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
        stats = get_list_stats()
        return render_template('sanctions.html', history=history, result=result, last_query=query_name, stats=stats)
    except Exception as e:
        flash(f'Screening error: {str(e)}', 'error')
        return redirect(url_for('sanctions'))

@app.route('/sanctions/<int:scan_id>')
@login_required
def sanctions_detail(scan_id):
    org  = current_user.organisation
    scan = ThreatScan.query.filter_by(id=scan_id, org_id=org.id).first_or_404()
    raw  = json.loads(scan.raw_results) if scan.raw_results else {}
    history = ThreatScan.query.filter_by(org_id=org.id, scan_type='sanctions').order_by(ThreatScan.scanned_at.desc()).limit(50).all()
    from sanctions_checker import get_list_stats
    stats = get_list_stats()
    return render_template('sanctions.html', history=history, result=raw, last_query=scan.indicator_value, stats=stats)

@app.route('/billing')
@login_required
def billing():
    org = current_user.organisation
    return render_template('billing.html', org=org, stripe_key=STRIPE_PUBLISHABLE_KEY,
                           plan_limits=PLAN_LIMITS)

# ── ROUTES: API ───────────────────────────────────────────────────
def api_auth():
    key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not key:
        return None
    return Organisation.query.filter_by(api_key=key, is_active=True).first()

@app.route('/api/v1/cases', methods=['GET'])
def api_cases():
    org = api_auth()
    if not org:
        return jsonify({'error': 'Invalid API key'}), 401
    if not PLAN_LIMITS.get(org.plan, {}).get('api'):
        return jsonify({'error': 'API access requires Professional plan'}), 403
    cases = FraudCase.query.filter_by(org_id=org.id).order_by(FraudCase.created_at.desc()).limit(100).all()
    return jsonify([{
        'id': c.id, 'case_ref': c.case_ref, 'indicator_type': c.indicator_type,
        'indicator_value': c.indicator_value, 'fraud_type': c.fraud_type,
        'severity': c.severity, 'status': c.status, 'ai_score': c.ai_score,
        'created_at': c.created_at.isoformat()
    } for c in cases])

@app.route('/api/v1/cases', methods=['POST'])
def api_submit_case():
    org = api_auth()
    if not org:
        return jsonify({'error': 'Invalid API key'}), 401
    if not PLAN_LIMITS.get(org.plan, {}).get('api'):
        return jsonify({'error': 'API access requires Professional plan'}), 403
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    case = FraudCase(
        org_id=org.id, case_ref=generate_case_ref(),
        indicator_type=data.get('indicator_type'),
        indicator_value=data.get('indicator_value'),
        fraud_type=data.get('fraud_type'),
        severity=data.get('severity', 'medium'),
        description=data.get('description'),
        amount_lost=data.get('amount_lost'),
        currency=data.get('currency', 'NGN'),
        status='open'
    )
    db.session.add(case)
    db.session.commit()
    return jsonify({'case_ref': case.case_ref, 'id': case.id}), 201

# ── INIT DB & SEED TRAINING ───────────────────────────────────────
def seed_training_modules():
    if TrainingModule.query.count() > 0:
        return
    modules = [
        {'title': 'Introduction to Financial Fraud in Africa', 'category': 'Fundamentals',
         'difficulty': 'beginner', 'duration': 15,
         'description': 'An overview of the fraud landscape across African financial markets.',
         'content': 'This module covers the key types of financial fraud prevalent in Africa including BVN fraud, SIM swap attacks, phishing, and account takeover schemes. You will learn how to identify early warning signs and understand the regulatory framework for reporting.'},
        {'title': 'BVN & Identity Fraud Detection', 'category': 'Fraud Detection',
         'difficulty': 'intermediate', 'duration': 20,
         'description': 'How to detect and respond to Bank Verification Number fraud.',
         'content': 'Bank Verification Number (BVN) fraud is one of the most common fraud vectors in Nigeria. This module covers verification techniques, red flags in BVN-linked transactions, and the step-by-step process for investigating suspected BVN fraud cases.'},
        {'title': 'Phishing & Social Engineering', 'category': 'Cyber Defence',
         'difficulty': 'beginner', 'duration': 12,
         'description': 'Recognising and responding to phishing attacks targeting financial staff.',
         'content': 'Social engineering remains the number one entry point for fraud in financial institutions. This module teaches staff how to identify phishing emails, vishing calls, and smishing messages specifically targeting African financial institutions.'},
        {'title': 'Incident Response for Fraud Events', 'category': 'Incident Response',
         'difficulty': 'advanced', 'duration': 25,
         'description': 'Step-by-step incident response procedures for fraud events.',
         'content': 'When fraud is detected, the speed and quality of your response determines the outcome. This module covers the DefenceIQ incident response framework: Detect, Contain, Investigate, Report, and Recover. Includes case studies from real African bank fraud incidents.'},
        {'title': 'CBN Fraud Reporting Requirements', 'category': 'Compliance',
         'difficulty': 'intermediate', 'duration': 18,
         'description': 'Understanding your CBN obligations for fraud reporting.',
         'content': 'The Central Bank of Nigeria mandates specific reporting timelines and formats for fraud incidents. This module covers mandatory reporting windows, the e-FASS portal, SAR filing requirements, and how to use DefenceIQ to generate CBN-compliant reports automatically.'},
    ]
    for m in modules:
        db.session.add(TrainingModule(**m))
    db.session.commit()
    print("Training modules seeded.")

with app.app_context():
    db.create_all()
    seed_training_modules()
    print("Database initialised.")

if __name__ == '__main__':
    app.run(debug=False, port=5002)

# ── SLACK & TEAMS WEBHOOKS ────────────────────────────────────────
def send_slack_alert(webhook_url, case, org):
    """Send fraud case alert to Slack"""
    import requests as req
    severity_emoji = {'critical': '🚨', 'high': '⚠️', 'medium': '🔶', 'low': '🔵'}
    color_map = {'critical': '#dc2626', 'high': '#d97706', 'medium': '#f59e0b', 'low': '#2563eb'}
    payload = {
        "attachments": [{
            "color": color_map.get(case.severity, '#2563eb'),
            "blocks": [
                {"type": "header", "text": {"type": "plain_text",
                    "text": f"{severity_emoji.get(case.severity, '🔔')} New Fraud Case — {case.severity.upper()}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Case Ref:*\n`{case.case_ref}`"},
                    {"type": "mrkdwn", "text": f"*Organisation:*\n{org.name}"},
                    {"type": "mrkdwn", "text": f"*Fraud Type:*\n{case.fraud_type or '—'}"},
                    {"type": "mrkdwn", "text": f"*Indicator:*\n{case.indicator_type}: `{case.indicator_value}`"},
                    {"type": "mrkdwn", "text": f"*Financial Impact:*\n{case.currency} {float(case.amount_lost):,.0f}" if case.amount_lost else "*Financial Impact:*\nNot reported"},
                    {"type": "mrkdwn", "text": f"*AI Score:*\n{int(case.ai_score)}/100" if case.ai_score else "*AI Score:*\nPending"},
                ]},
                {"type": "actions", "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "View Case"},
                     "url": f"https://defenceiq.io/cases/{case.id}", "style": "primary"}
                ]}
            ]
        }]
    }
    try:
        r = req.post(webhook_url, json=payload, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f"Slack alert error: {e}")
        return False

def send_teams_alert(webhook_url, case, org):
    """Send fraud case alert to Microsoft Teams"""
    import requests as req
    severity_color = {'critical': 'attention', 'high': 'warning', 'medium': 'warning', 'low': 'accent'}
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": f"🛡️ DefenceIQ — New Fraud Case", "color": "Accent"},
                    {"type": "FactSet", "facts": [
                        {"title": "Case Ref", "value": case.case_ref},
                        {"title": "Organisation", "value": org.name},
                        {"title": "Fraud Type", "value": case.fraud_type or "—"},
                        {"title": "Severity", "value": case.severity.upper()},
                        {"title": "Indicator", "value": f"{case.indicator_type}: {case.indicator_value}"},
                        {"title": "Financial Impact", "value": f"{case.currency} {float(case.amount_lost):,.0f}" if case.amount_lost else "Not reported"},
                    ]},
                ],
                "actions": [{"type": "Action.OpenUrl", "title": "View Case",
                    "url": f"https://defenceiq.io/cases/{case.id}"}]
            }
        }]
    }
    try:
        r = req.post(webhook_url, json=payload, timeout=5)
        return r.status_code in [200, 202]
    except Exception as e:
        print(f"Teams alert error: {e}")
        return False

def send_webhook_alerts(case, org):
    """Dispatch alerts to all configured webhooks for an org"""
    from app import WebhookConfig
    webhooks = WebhookConfig.query.filter_by(org_id=org.id, is_active=True).all()
    for wh in webhooks:
        if wh.platform == 'slack':
            send_slack_alert(wh.webhook_url, case, org)
        elif wh.platform == 'teams':
            send_teams_alert(wh.webhook_url, case, org)
