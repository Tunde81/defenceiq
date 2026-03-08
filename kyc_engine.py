"""
KYC Engine — DefenceIQ
Risk classification, document checklist generation, EDD triggers.
"""
from datetime import datetime, timedelta

# Document requirements by due diligence level
STANDARD_DOCS = [
    ('passport_or_id',    'Passport or Government-issued ID',    True),
    ('proof_of_address',  'Proof of Address (utility/bank, <3mo)', True),
    ('selfie_id',         'Selfie with ID Document',              False),
]
ENHANCED_DOCS = STANDARD_DOCS + [
    ('source_of_funds',   'Source of Funds Declaration',          True),
    ('source_of_wealth',  'Source of Wealth Evidence',            True),
    ('bank_statement',    'Bank Statement (3 months)',             True),
    ('pep_declaration',   'PEP Self-Declaration Form',            True),
]
BUSINESS_DOCS = [
    ('cert_incorporation','Certificate of Incorporation',         True),
    ('memorandum',        'Memorandum & Articles of Association', True),
    ('director_list',     'List of Directors',                    True),
    ('shareholder_reg',   'Shareholder Register (25%+ owners)',   True),
    ('proof_of_address',  'Registered Office Proof of Address',   True),
    ('bank_statement',    'Business Bank Statement (3 months)',   True),
    ('passport_directors','Passport/ID for each Director',        True),
    ('source_of_funds',   'Source of Funds / Business Purpose',  True),
]

HIGH_RISK_COUNTRIES = {
    'Iran','Iraq','North Korea','Syria','Yemen','Libya','Somalia','Sudan',
    'Myanmar','Haiti','Pakistan','Russia','Belarus','Cuba','Venezuela','Afghanistan',
}
MEDIUM_RISK_COUNTRIES = {
    'Nigeria','Ukraine','Turkey','UAE','Egypt','Ghana','Kenya',
    'Bangladesh','Cambodia','Vietnam','Panama','Cayman Islands',
}

def get_document_checklist(customer_type, due_diligence):
    if customer_type == 'business':
        return BUSINESS_DOCS
    if due_diligence == 'enhanced':
        return ENHANCED_DOCS
    return STANDARD_DOCS

def calculate_risk_score(profile):
    score = 0
    flags = []

    # Nationality / country risk
    nat = (profile.get('nationality') or '').strip()
    cor = (profile.get('country_of_residence') or '').strip()
    if nat in HIGH_RISK_COUNTRIES or cor in HIGH_RISK_COUNTRIES:
        score += 35
        flags.append(f'High-risk country: {nat or cor}')
    elif nat in MEDIUM_RISK_COUNTRIES or cor in MEDIUM_RISK_COUNTRIES:
        score += 20
        flags.append(f'Medium-risk country: {nat or cor}')

    # PEP
    if profile.get('pep_status'):
        score += 30
        flags.append('Politically Exposed Person (PEP)')

    # Sanctions hit
    if profile.get('sanctions_hit'):
        score += 50
        flags.append('Sanctions list match')

    # Business type
    if profile.get('customer_type') == 'business':
        score += 5
        flags.append('Business entity (higher complexity)')

    score = min(score, 100)

    if score >= 50 or profile.get('pep_status') or profile.get('sanctions_hit'):
        due_diligence = 'enhanced'
        risk_rating = 'high' if score >= 50 else 'medium'
    elif score >= 25:
        due_diligence = 'standard'
        risk_rating = 'medium'
    else:
        due_diligence = 'standard'
        risk_rating = 'low'

    return {
        'risk_score': score,
        'risk_rating': risk_rating,
        'due_diligence': due_diligence,
        'flags': flags,
        'review_due': (datetime.utcnow() + timedelta(days=365 if risk_rating=='low' else 180 if risk_rating=='medium' else 90)).strftime('%Y-%m-%d')
    }

def get_kyc_stats(org_id, db_session):
    try:
        from sqlalchemy import text
        r = db_session.execute(text('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN kyc_status='approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN kyc_status='pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN kyc_status='rejected' THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN due_diligence='enhanced' THEN 1 ELSE 0 END) as edd,
                SUM(CASE WHEN pep_status=TRUE THEN 1 ELSE 0 END) as peps,
                SUM(CASE WHEN sanctions_hit=TRUE THEN 1 ELSE 0 END) as sanctions
            FROM kyc_profiles WHERE org_id=:o
        '''), {'o': org_id}).fetchone()
        return dict(total=int(r[0] or 0), approved=int(r[1] or 0),
                    pending=int(r[2] or 0), rejected=int(r[3] or 0),
                    edd=int(r[4] or 0), peps=int(r[5] or 0), sanctions=int(r[6] or 0))
    except:
        return dict(total=0,approved=0,pending=0,rejected=0,edd=0,peps=0,sanctions=0)

def get_completion_pct(profile_id, db_session):
    try:
        from sqlalchemy import text
        r = db_session.execute(text('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status IN ('uploaded','verified') THEN 1 ELSE 0 END) as done
            FROM kyc_documents WHERE profile_id=:pid
        '''), {'pid': profile_id}).fetchone()
        total = int(r[0] or 0)
        done  = int(r[1] or 0)
        return round((done/total)*100) if total else 0
    except:
        return 0
