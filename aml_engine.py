"""
AML Transaction Monitoring Engine — DefenceIQ
Rule-based screening: structuring, velocity, jurisdiction, round amounts, etc.
"""
from datetime import datetime, timedelta
from decimal import Decimal
import re

# ── High-risk jurisdictions (FATF grey/black list + common fraud origins) ──
HIGH_RISK_COUNTRIES = {
    'Iran','Iraq','North Korea','Syria','Yemen','Libya','Somalia','Sudan',
    'Myanmar','Haiti','Pakistan','Nigeria','Russia','Belarus','Cuba',
    'Venezuela','Afghanistan','Mali','Burkina Faso','Niger',
}
MEDIUM_RISK_COUNTRIES = {
    'Ukraine','Turkey','UAE','Egypt','Ghana','Kenya','Ethiopia',
    'Bangladesh','Cambodia','Vietnam','Panama','Cayman Islands',
    'British Virgin Islands','Jersey','Guernsey','Isle of Man',
}

# ── Structuring thresholds ────────────────────────────────────────
CTR_THRESHOLD   = 10000   # Cash Transaction Report threshold (GBP)
STRUCT_WINDOW   = 3       # Days to look back for structuring
STRUCT_MIN      = 2       # Minimum transactions to flag structuring
VELOCITY_WINDOW = 7       # Days for velocity check
VELOCITY_MAX    = 5       # Max transactions before velocity flag
ROUND_AMOUNTS   = {1000, 2000, 2500, 3000, 4000, 5000, 7500, 10000,
                   15000, 20000, 25000, 50000, 100000}

def _to_float(v):
    try:
        return float(v or 0)
    except:
        return 0.0

def _risk_level(score):
    if score >= 75: return 'critical'
    if score >= 50: return 'high'
    if score >= 25: return 'medium'
    if score > 0:   return 'low'
    return 'clean'

def screen_transaction(txn, org_id, db_session):
    """
    Screen a single transaction dict against AML rules.
    Returns: {risk_score, risk_level, flags}
    """
    flags  = []
    score  = 0
    amount = _to_float(txn.get('amount_gbp') or txn.get('amount'))

    # ── Rule 1: CTR threshold breach ─────────────────────────────
    if amount >= CTR_THRESHOLD:
        flags.append({
            'rule': 'CTR_THRESHOLD',
            'severity': 'high',
            'detail': f'Transaction of £{amount:,.0f} meets/exceeds £{CTR_THRESHOLD:,} CTR threshold',
            'score': 25
        })
        score += 25

    # ── Rule 2: Just-below threshold (structuring indicator) ──────
    if 8000 <= amount < CTR_THRESHOLD:
        flags.append({
            'rule': 'JUST_BELOW_THRESHOLD',
            'severity': 'high',
            'detail': f'£{amount:,.0f} — just below £{CTR_THRESHOLD:,} reporting threshold (structuring indicator)',
            'score': 30
        })
        score += 30

    # ── Rule 3: Round amount ──────────────────────────────────────
    if amount in ROUND_AMOUNTS or (amount > 500 and amount % 500 == 0):
        flags.append({
            'rule': 'ROUND_AMOUNT',
            'severity': 'low',
            'detail': f'Suspiciously round amount: £{amount:,.0f}',
            'score': 8
        })
        score += 8

    # ── Rule 4: High-risk sender country ─────────────────────────
    sender_country = (txn.get('sender_country') or '').strip()
    if sender_country in HIGH_RISK_COUNTRIES:
        flags.append({
            'rule': 'HIGH_RISK_SENDER_COUNTRY',
            'severity': 'critical',
            'detail': f'Sender country "{sender_country}" is on FATF high-risk list',
            'score': 40
        })
        score += 40
    elif sender_country in MEDIUM_RISK_COUNTRIES:
        flags.append({
            'rule': 'MEDIUM_RISK_SENDER_COUNTRY',
            'severity': 'medium',
            'detail': f'Sender country "{sender_country}" is elevated risk jurisdiction',
            'score': 20
        })
        score += 20

    # ── Rule 5: High-risk receiver country ───────────────────────
    receiver_country = (txn.get('receiver_country') or '').strip()
    if receiver_country in HIGH_RISK_COUNTRIES:
        flags.append({
            'rule': 'HIGH_RISK_RECEIVER_COUNTRY',
            'severity': 'critical',
            'detail': f'Receiver country "{receiver_country}" is on FATF high-risk list',
            'score': 40
        })
        score += 40
    elif receiver_country in MEDIUM_RISK_COUNTRIES:
        flags.append({
            'rule': 'MEDIUM_RISK_RECEIVER_COUNTRY',
            'severity': 'medium',
            'detail': f'Receiver country "{receiver_country}" is elevated risk jurisdiction',
            'score': 20
        })
        score += 20

    # ── Rule 6: Cross-border (sender ≠ receiver country) ─────────
    if sender_country and receiver_country and sender_country != receiver_country:
        flags.append({
            'rule': 'CROSS_BORDER',
            'severity': 'low',
            'detail': f'Cross-border transfer: {sender_country} → {receiver_country}',
            'score': 5
        })
        score += 5

    # ── Rule 7: Velocity check (past transactions) ────────────────
    try:
        from sqlalchemy import text
        cutoff = (datetime.utcnow() - timedelta(days=VELOCITY_WINDOW)).strftime('%Y-%m-%d')
        sender_acc = txn.get('sender_account', '')
        if sender_acc:
            count = db_session.execute(text('''
                SELECT COUNT(*) FROM aml_transactions
                WHERE org_id = :org_id
                AND sender_account = :acc
                AND txn_date >= :cutoff
            '''), {'org_id': org_id, 'acc': sender_acc, 'cutoff': cutoff}).scalar() or 0
            if count >= VELOCITY_MAX:
                vel_score = min(count * 5, 25)
                flags.append({
                    'rule': 'HIGH_VELOCITY',
                    'severity': 'high',
                    'detail': f'{count} transactions from same sender in {VELOCITY_WINDOW} days',
                    'score': vel_score
                })
                score += vel_score
    except:
        pass

    # ── Rule 8: Structuring detection ────────────────────────────
    try:
        from sqlalchemy import text
        cutoff = (datetime.utcnow() - timedelta(days=STRUCT_WINDOW)).strftime('%Y-%m-%d')
        sender_acc = txn.get('sender_account', '')
        if sender_acc:
            recent = db_session.execute(text('''
                SELECT COALESCE(SUM(amount_gbp),0), COUNT(*)
                FROM aml_transactions
                WHERE org_id = :org_id
                AND sender_account = :acc
                AND txn_date >= :cutoff
            '''), {'org_id': org_id, 'acc': sender_acc, 'cutoff': cutoff}).fetchone()
            total_recent = float(recent[0] or 0) + amount
            count_recent = int(recent[1] or 0) + 1
            if total_recent >= CTR_THRESHOLD and count_recent >= STRUCT_WINDOW:
                flags.append({
                    'rule': 'STRUCTURING',
                    'severity': 'critical',
                    'detail': f'Potential structuring: £{total_recent:,.0f} across {count_recent} txns in {STRUCT_WINDOW} days (total exceeds £{CTR_THRESHOLD:,})',
                    'score': 45
                })
                score += 45
    except:
        pass

    # ── Rule 9: Unusual transaction type ─────────────────────────
    txn_type = (txn.get('txn_type') or '').lower()
    if txn_type in ('cash', 'crypto', 'hawala', 'money order'):
        flags.append({
            'rule': 'HIGH_RISK_TXN_TYPE',
            'severity': 'high',
            'detail': f'High-risk transaction type: {txn_type.title()}',
            'score': 20
        })
        score += 20

    # ── Rule 10: Mismatched description ──────────────────────────
    desc = (txn.get('description') or '').lower()
    suspicious_kw = ['loan','gift','donation','investment','charity','refund',
                     'winnings','lottery','inheritance','business opportunity']
    matched_kw = [k for k in suspicious_kw if k in desc]
    if matched_kw:
        flags.append({
            'rule': 'SUSPICIOUS_DESCRIPTION',
            'severity': 'medium',
            'detail': f'Description contains suspicious keywords: {", ".join(matched_kw)}',
            'score': 15
        })
        score += 15

    score = min(score, 100)
    return {
        'risk_score': score,
        'risk_level': _risk_level(score),
        'flags': flags,
        'flag_count': len(flags)
    }

def get_aml_stats(org_id, db_session):
    """Dashboard stats for AML monitoring"""
    try:
        from sqlalchemy import text
        rows = db_session.execute(text('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN risk_level IN ('critical','high') THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN sar_filed = TRUE THEN 1 ELSE 0 END) as sar_count,
                SUM(CASE WHEN reviewed = FALSE AND risk_level != 'clean' THEN 1 ELSE 0 END) as pending_review,
                COALESCE(SUM(amount_gbp),0) as total_value
            FROM aml_transactions WHERE org_id = :org_id
        '''), {'org_id': org_id}).fetchone()
        return {
            'total': int(rows[0] or 0),
            'high_risk': int(rows[1] or 0),
            'sar_count': int(rows[2] or 0),
            'pending_review': int(rows[3] or 0),
            'total_value': float(rows[4] or 0)
        }
    except:
        return {'total':0,'high_risk':0,'sar_count':0,'pending_review':0,'total_value':0}
