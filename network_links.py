"""
Network & Entity Link Analysis — DefenceIQ
Finds hidden connections between cases, KYC profiles, AML transactions,
sanctions hits, device fingerprints, and threat scans using shared indicators.
No external APIs needed — pure in-database intelligence.
"""
from sqlalchemy import text
from datetime import datetime


def build_entity_network(query, org_id, session):
    """
    Given a search term (name, email, IP, domain, device hash),
    find all related entities and connections across the platform.
    """
    q = query.strip().lower()
    nodes = {}
    edges = []

    def add_node(node_id, label, node_type, risk='clean', meta=None):
        if node_id not in nodes:
            nodes[node_id] = {
                'id': node_id, 'label': label, 'type': node_type,
                'risk': risk, 'meta': meta or {}
            }

    def add_edge(source, target, relationship):
        edge = {'source': source, 'target': target, 'label': relationship}
        if edge not in edges:
            edges.append(edge)

    # ── Search fraud cases ───────────────────────────────────────────
    cases = session.execute(text("""
        SELECT id, case_ref, subject_name, subject_email, subject_ip,
               fraud_type, status, risk_level
        FROM fraud_cases
        WHERE org_id=:o AND (
            LOWER(subject_name) LIKE :q OR
            LOWER(subject_email) LIKE :q OR
            LOWER(subject_ip) LIKE :q OR
            LOWER(case_ref) LIKE :q
        ) LIMIT 20
    """), {'o': org_id, 'q': f'%{q}%'}).fetchall()

    for c in cases:
        nid = f'case_{c.id}'
        add_node(nid, c.case_ref, 'case', c.risk_level or 'clean',
                 {'subject': c.subject_name, 'type': c.fraud_type, 'status': c.status})

        # Find other cases sharing same email or IP
        if c.subject_email:
            related = session.execute(text("""
                SELECT id, case_ref, risk_level FROM fraud_cases
                WHERE org_id=:o AND id!=:cid AND LOWER(subject_email)=:e LIMIT 5
            """), {'o': org_id, 'cid': c.id, 'e': c.subject_email.lower()}).fetchall()
            for r in related:
                add_node(f'case_{r.id}', r.case_ref, 'case', r.risk_level or 'clean')
                add_edge(nid, f'case_{r.id}', 'shared email')

        if c.subject_ip:
            related = session.execute(text("""
                SELECT id, case_ref, risk_level FROM fraud_cases
                WHERE org_id=:o AND id!=:cid AND subject_ip=:ip LIMIT 5
            """), {'o': org_id, 'cid': c.id, 'ip': c.subject_ip}).fetchall()
            for r in related:
                add_node(f'case_{r.id}', r.case_ref, 'case', r.risk_level or 'clean')
                add_edge(nid, f'case_{r.id}', 'shared IP')

    # ── Search KYC profiles ──────────────────────────────────────────
    kyc_rows = session.execute(text("""
        SELECT id, profile_ref, full_name, email, nationality,
               risk_rating, kyc_status, pep_status, sanctions_hit
        FROM kyc_profiles
        WHERE org_id=:o AND (
            LOWER(full_name) LIKE :q OR
            LOWER(email) LIKE :q OR
            LOWER(profile_ref) LIKE :q
        ) LIMIT 20
    """), {'o': org_id, 'q': f'%{q}%'}).fetchall()

    for k in kyc_rows:
        nid = f'kyc_{k.id}'
        flags = []
        if k.pep_status: flags.append('PEP')
        if k.sanctions_hit: flags.append('SANCTIONS')
        add_node(nid, k.profile_ref, 'kyc', k.risk_rating or 'clean',
                 {'name': k.full_name, 'status': k.kyc_status, 'flags': flags})

        # Link KYC to matching fraud cases
        if k.email:
            related_cases = session.execute(text("""
                SELECT id, case_ref, risk_level FROM fraud_cases
                WHERE org_id=:o AND LOWER(subject_email)=:e LIMIT 5
            """), {'o': org_id, 'e': k.email.lower()}).fetchall()
            for rc in related_cases:
                add_node(f'case_{rc.id}', rc.case_ref, 'case', rc.risk_level or 'clean')
                add_edge(nid, f'case_{rc.id}', 'shared email')

    # ── Search AML transactions ──────────────────────────────────────
    txns = session.execute(text("""
        SELECT id, txn_ref, sender_name, receiver_name,
               sender_account, receiver_account, risk_level, risk_score
        FROM aml_transactions
        WHERE org_id=:o AND (
            LOWER(sender_name) LIKE :q OR
            LOWER(receiver_name) LIKE :q OR
            LOWER(txn_ref) LIKE :q OR
            LOWER(sender_account) LIKE :q OR
            LOWER(receiver_account) LIKE :q
        ) LIMIT 20
    """), {'o': org_id, 'q': f'%{q}%'}).fetchall()

    for t in txns:
        nid = f'txn_{t.id}'
        add_node(nid, t.txn_ref, 'transaction', t.risk_level or 'clean',
                 {'sender': t.sender_name, 'receiver': t.receiver_name, 'score': t.risk_score})

        # Link transactions sharing sender/receiver with other transactions
        if t.sender_account:
            related = session.execute(text("""
                SELECT id, txn_ref, risk_level FROM aml_transactions
                WHERE org_id=:o AND id!=:tid AND (
                    sender_account=:acc OR receiver_account=:acc
                ) LIMIT 5
            """), {'o': org_id, 'tid': t.id, 'acc': t.sender_account}).fetchall()
            for r in related:
                add_node(f'txn_{r.id}', r.txn_ref, 'transaction', r.risk_level or 'clean')
                add_edge(nid, f'txn_{r.id}', 'shared account')

    # ── Search threat scans ──────────────────────────────────────────
    scans = session.execute(text("""
        SELECT id, indicator_type, indicator_value, overall_risk, scan_type
        FROM threat_scans
        WHERE org_id=:o AND LOWER(indicator_value) LIKE :q
        LIMIT 20
    """), {'o': org_id, 'q': f'%{q}%'}).fetchall()

    for s in scans:
        nid = f'scan_{s.id}'
        label = f"{s.scan_type or s.indicator_type}: {s.indicator_value[:20]}"
        add_node(nid, label, 'threat_scan', s.overall_risk or 'clean',
                 {'type': s.indicator_type, 'scan_type': s.scan_type})

        # Link scan to fraud cases with same indicator
        related_cases = session.execute(text("""
            SELECT id, case_ref, risk_level FROM fraud_cases
            WHERE org_id=:o AND (
                LOWER(subject_email)=:v OR
                LOWER(subject_ip)=:v OR
                LOWER(subject_name) LIKE :vl
            ) LIMIT 5
        """), {'o': org_id, 'v': s.indicator_value.lower(), 'vl': f'%{s.indicator_value.lower()}%'}).fetchall()
        for rc in related_cases:
            add_node(f'case_{rc.id}', rc.case_ref, 'case', rc.risk_level or 'clean')
            add_edge(nid, f'case_{rc.id}', 'indicator match')

    # ── Search device fingerprints ───────────────────────────────────
    devices = session.execute(text("""
        SELECT id, fingerprint_hash, ip_address, risk_level, risk_score
        FROM device_fingerprints
        WHERE org_id=:o AND (
            fingerprint_hash LIKE :q OR
            ip_address LIKE :q
        ) LIMIT 10
    """), {'o': org_id, 'q': f'%{q}%'}).fetchall()

    for d in devices:
        nid = f'device_{d.id}'
        add_node(nid, f'Device {d.fingerprint_hash}', 'device', d.risk_level or 'clean',
                 {'ip': d.ip_address, 'score': d.risk_score})

        # Same device hash across multiple users = mule signal
        if d.fingerprint_hash:
            shared = session.execute(text("""
                SELECT id, fingerprint_hash, risk_level FROM device_fingerprints
                WHERE org_id=:o AND id!=:did AND fingerprint_hash=:h LIMIT 5
            """), {'o': org_id, 'did': d.id, 'h': d.fingerprint_hash}).fetchall()
            for sd in shared:
                add_node(f'device_{sd.id}', f'Device {sd.fingerprint_hash}', 'device', sd.risk_level or 'clean')
                add_edge(nid, f'device_{sd.id}', 'same device')

    # ── Compute network risk score ───────────────────────────────────
    risk_weights = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'clean': 0}
    if nodes:
        avg_risk = sum(risk_weights.get(n['risk'], 0) for n in nodes.values()) / len(nodes)
        connection_bonus = min(len(edges) * 5, 25)
        network_score = min(int(avg_risk + connection_bonus), 100)
    else:
        network_score = 0

    if network_score >= 75: network_risk = 'critical'
    elif network_score >= 50: network_risk = 'high'
    elif network_score >= 25: network_risk = 'medium'
    elif network_score > 0: network_risk = 'low'
    else: network_risk = 'clean'

    return {
        'query': query,
        'nodes': list(nodes.values()),
        'edges': edges,
        'node_count': len(nodes),
        'edge_count': len(edges),
        'network_score': network_score,
        'network_risk': network_risk,
        'analysed_at': datetime.utcnow().isoformat()
    }


def get_network_stats(org_id, session):
    """Quick stats for the network page header."""
    cases = session.execute(text(
        "SELECT COUNT(*) FROM fraud_cases WHERE org_id=:o"), {'o': org_id}).scalar() or 0
    kyc   = session.execute(text(
        "SELECT COUNT(*) FROM kyc_profiles WHERE org_id=:o"), {'o': org_id}).scalar() or 0
    txns  = session.execute(text(
        "SELECT COUNT(*) FROM aml_transactions WHERE org_id=:o"), {'o': org_id}).scalar() or 0
    scans = session.execute(text(
        "SELECT COUNT(*) FROM threat_scans WHERE org_id=:o"), {'o': org_id}).scalar() or 0
    return type('S', (), {
        'cases': cases, 'kyc': kyc,
        'transactions': txns, 'scans': scans,
        'total': cases + kyc + txns + scans
    })()
