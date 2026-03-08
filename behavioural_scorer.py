"""
Behavioural Risk Scoring — DefenceIQ
Analyses entities across case history to build risk profiles.
No external APIs — pure in-house pattern intelligence.
"""
from datetime import datetime, timedelta
from collections import defaultdict
import json, re

def _normalise(val):
    return val.lower().strip() if val else ''

def _risk_level(score):
    if score >= 75: return 'critical'
    if score >= 50: return 'high'
    if score >= 25: return 'medium'
    if score > 0:   return 'low'
    return 'clean'

def _severity_weight(s):
    return {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(s, 1)

def score_entity(entity_value, org_id, db_session, FraudCase, ThreatScan):
    """
    Score an entity (email, IP, phone, name, domain) based on:
    1. Case frequency — how many times seen
    2. Severity pattern — escalating severity?
    3. Fraud type diversity — multiple fraud types = organised?
    4. Recency — recent activity weighted higher
    5. Financial exposure — total amount lost
    6. Status pattern — how many confirmed vs pending
    7. Threat intel hits — appeared in dark web / IP / phishing scans
    8. Velocity — multiple cases in short window
    """
    val = _normalise(entity_value)
    now = datetime.utcnow()

    # Pull all matching cases for this org
    all_cases = FraudCase.query.filter_by(org_id=org_id).all()
    matches = [c for c in all_cases if _normalise(c.indicator_value) == val
               or val in _normalise(c.description or '')
               or val in _normalise(c.indicator_value)]

    # Pull threat scan history
    all_scans = ThreatScan.query.filter_by(org_id=org_id).filter(
        ThreatScan.indicator_value.ilike(f'%{val}%')
    ).all() if ThreatScan else []

    signals = []
    score = 0

    # ── Signal 1: Case frequency ─────────────────────────────────
    case_count = len(matches)
    if case_count == 0:
        freq_score = 0
        signals.append({'label': 'Case History', 'value': 'No prior cases', 'impact': 0, 'status': 'clean'})
    elif case_count == 1:
        freq_score = 15
        signals.append({'label': 'Case History', 'value': '1 case on record', 'impact': 15, 'status': 'low'})
    elif case_count <= 3:
        freq_score = 30
        signals.append({'label': 'Case History', 'value': f'{case_count} cases on record', 'impact': 30, 'status': 'medium'})
    else:
        freq_score = min(20 + case_count * 5, 50)
        signals.append({'label': 'Case History', 'value': f'{case_count} cases — repeat entity', 'impact': freq_score, 'status': 'high'})
    score += freq_score

    if not matches:
        return {
            'entity': entity_value,
            'overall_risk': 'clean',
            'risk_score': 0,
            'signals': signals,
            'case_count': 0,
            'cases': [],
            'summary': 'No history found for this entity.',
            'scanned_at': now.isoformat()
        }

    # ── Signal 2: Severity pattern ───────────────────────────────
    severities = [c.severity for c in matches if c.severity]
    if severities:
        max_sev = max(severities, key=_severity_weight)
        avg_weight = sum(_severity_weight(s) for s in severities) / len(severities)
        sev_score = int(avg_weight * 8)
        signals.append({'label': 'Severity Pattern', 'value': f'Max: {max_sev}, avg weight: {avg_weight:.1f}', 'impact': sev_score, 'status': max_sev})
        score += sev_score

    # ── Signal 3: Fraud type diversity ───────────────────────────
    fraud_types = list(set(c.fraud_type for c in matches if c.fraud_type))
    if len(fraud_types) > 1:
        div_score = min(len(fraud_types) * 8, 25)
        signals.append({'label': 'Fraud Type Diversity', 'value': f'{len(fraud_types)} types: {", ".join(fraud_types[:3])}', 'impact': div_score, 'status': 'high'})
        score += div_score
    elif fraud_types:
        signals.append({'label': 'Fraud Type', 'value': fraud_types[0], 'impact': 0, 'status': 'info'})

    # ── Signal 4: Recency ────────────────────────────────────────
    recent_30  = [c for c in matches if c.created_at >= now - timedelta(days=30)]
    recent_90  = [c for c in matches if c.created_at >= now - timedelta(days=90)]
    if recent_30:
        rec_score = min(len(recent_30) * 12, 30)
        signals.append({'label': 'Recent Activity', 'value': f'{len(recent_30)} case(s) in last 30 days', 'impact': rec_score, 'status': 'critical'})
        score += rec_score
    elif recent_90:
        rec_score = min(len(recent_90) * 6, 15)
        signals.append({'label': 'Recent Activity', 'value': f'{len(recent_90)} case(s) in last 90 days', 'impact': rec_score, 'status': 'medium'})
        score += rec_score
    else:
        signals.append({'label': 'Recent Activity', 'value': 'No recent activity (90+ days)', 'impact': 0, 'status': 'clean'})

    # ── Signal 5: Financial exposure ─────────────────────────────
    amounts = [float(c.amount_lost) for c in matches if c.amount_lost]
    if amounts:
        total = sum(amounts)
        if total >= 50000:
            fin_score = 25
        elif total >= 10000:
            fin_score = 15
        elif total >= 1000:
            fin_score = 8
        else:
            fin_score = 3
        signals.append({'label': 'Financial Exposure', 'value': f'£{total:,.0f} total across {len(amounts)} case(s)', 'impact': fin_score, 'status': 'high' if total >= 10000 else 'medium'})
        score += fin_score
    else:
        signals.append({'label': 'Financial Exposure', 'value': 'No financial data recorded', 'impact': 0, 'status': 'info'})

    # ── Signal 6: Case status pattern ───────────────────────────
    confirmed = [c for c in matches if c.status in ('confirmed', 'closed')]
    pending   = [c for c in matches if c.status == 'pending']
    if confirmed:
        conf_score = min(len(confirmed) * 10, 20)
        signals.append({'label': 'Confirmed Cases', 'value': f'{len(confirmed)} confirmed fraud case(s)', 'impact': conf_score, 'status': 'critical'})
        score += conf_score

    # ── Signal 7: Threat intel hits ──────────────────────────────
    high_risk_scans = [s for s in all_scans if s.overall_risk in ('critical', 'high')]
    if high_risk_scans:
        ti_score = min(len(high_risk_scans) * 15, 30)
        scan_types = list(set(s.scan_type for s in high_risk_scans))
        signals.append({'label': 'Threat Intel Hits', 'value': f'{len(high_risk_scans)} high-risk scan(s): {", ".join(scan_types)}', 'impact': ti_score, 'status': 'critical'})
        score += ti_score
    elif all_scans:
        signals.append({'label': 'Threat Intel', 'value': f'{len(all_scans)} scan(s) — no high-risk results', 'impact': 0, 'status': 'clean'})

    # ── Signal 8: Velocity ───────────────────────────────────────
    if case_count >= 2:
        dates = sorted([c.created_at for c in matches])
        if len(dates) >= 2:
            span_days = max((dates[-1] - dates[0]).days, 1)
            velocity = case_count / (span_days / 30)  # cases per month
            if velocity >= 3:
                vel_score = 20
                signals.append({'label': 'Velocity', 'value': f'{velocity:.1f} cases/month — high frequency', 'impact': vel_score, 'status': 'critical'})
                score += vel_score
            elif velocity >= 1:
                vel_score = 10
                signals.append({'label': 'Velocity', 'value': f'{velocity:.1f} cases/month', 'impact': vel_score, 'status': 'medium'})
                score += vel_score

    score = min(score, 100)
    risk = _risk_level(score)

    # Build summary
    summaries = {
        'critical': f'CRITICAL RISK — {case_count} cases, multiple fraud types, recent high-severity activity. Recommend immediate escalation.',
        'high':     f'HIGH RISK — {case_count} case(s) with significant financial exposure or confirmed fraud history.',
        'medium':   f'MEDIUM RISK — {case_count} case(s) on record. Monitor closely.',
        'low':      f'LOW RISK — {case_count} case(s) on record. No immediate concern.',
        'clean':    'No risk signals detected for this entity.'
    }

    return {
        'entity': entity_value,
        'overall_risk': risk,
        'risk_score': score,
        'signals': signals,
        'case_count': case_count,
        'fraud_types': fraud_types,
        'total_exposure': sum(float(c.amount_lost) for c in matches if c.amount_lost),
        'cases': [{'id': c.id, 'ref': c.case_ref, 'type': c.fraud_type,
                   'severity': c.severity, 'status': c.status,
                   'amount': float(c.amount_lost) if c.amount_lost else 0,
                   'date': c.created_at.strftime('%d %b %Y')} for c in matches[:10]],
        'summary': summaries.get(risk, ''),
        'scanned_at': now.isoformat()
    }
