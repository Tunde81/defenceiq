"""
Phishing & Domain Alert Checker — DefenceIQ
Sources: VirusTotal, URLScan.io, URLhaus, PhishTank, OpenPhish, crt.sh, typosquatting
"""
import requests, re, itertools, base64
from difflib import SequenceMatcher
from datetime import datetime

HEADERS = {'User-Agent': 'DefenceIQ/1.0'}

def _clean_domain(target):
    """Strip protocol/path, return bare domain"""
    d = target.lower().strip()
    d = re.sub(r'^https?://', '', d)
    d = re.sub(r'^www\.', '', d)
    d = d.split('/')[0].split('?')[0].split('#')[0]
    return d

def _risk_level(score):
    if score >= 75: return 'critical'
    if score >= 50: return 'high'
    if score >= 25: return 'medium'
    if score > 0:   return 'low'
    return 'clean'

# ── Source 1: VirusTotal ──────────────────────────────────────────
def check_vt_domain(domain, api_key=None):
    if not api_key:
        return {'source': 'VirusTotal', 'found': False, 'detail': 'No API key configured'}
    try:
        r = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers={**HEADERS, 'x-apikey': api_key}, timeout=10)
        if r.status_code == 200:
            data = r.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            found = malicious > 0 or suspicious > 0
            cats = data.get('categories', {})
            return {
                'source': 'VirusTotal',
                'found': found,
                'malicious_engines': malicious,
                'suspicious_engines': suspicious,
                'total_engines': total,
                'categories': list(cats.values())[:3],
                'reputation': data.get('reputation', 0),
                'detail': f'{malicious} malicious, {suspicious} suspicious out of {total} engines' if found else f'Clean ({total} engines checked)',
                'score_contrib': min(malicious * 8 + suspicious * 4, 60)
            }
        return {'source': 'VirusTotal', 'found': False, 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'VirusTotal', 'found': False, 'error': str(e)}

# ── Source 2: URLScan.io ──────────────────────────────────────────
def check_urlscan(domain):
    try:
        r = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5',
            headers=HEADERS, timeout=10)
        if r.status_code == 200:
            results = r.json().get('results', [])
            malicious = [x for x in results if x.get('verdicts', {}).get('overall', {}).get('malicious')]
            found = len(malicious) > 0
            latest = results[0] if results else {}
            return {
                'source': 'URLScan.io',
                'found': found,
                'total_scans': len(results),
                'malicious_scans': len(malicious),
                'latest_scan': latest.get('task', {}).get('time', ''),
                'screenshot': latest.get('screenshot', ''),
                'detail': f'{len(malicious)} malicious out of {len(results)} scans' if found else f'{len(results)} scans — no malicious verdicts',
                'score_contrib': min(len(malicious) * 15, 40)
            }
        return {'source': 'URLScan.io', 'found': False, 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'URLScan.io', 'found': False, 'error': str(e)}

# ── Source 3: URLhaus ─────────────────────────────────────────────
def check_urlhaus_domain(domain):
    try:
        r = requests.post('https://urlhaus-api.abuse.ch/v1/host/',
            json={'host': domain}, headers={**HEADERS,'Content-Type':'application/json'}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            status = data.get('query_status', '')
            found = status in ['is_host', 'blacklisted']
            urls = data.get('urls', [])
            active = [u for u in urls if u.get('url_status') == 'online']
            return {
                'source': 'URLhaus',
                'found': found,
                'url_count': len(urls),
                'active_count': len(active),
                'threat': urls[0].get('threat', '') if urls else '',
                'detail': f'{len(urls)} malicious URLs ({len(active)} active)' if found else 'Not in URLhaus',
                'score_contrib': 35 if found else 0
            }
        return {'source': 'URLhaus', 'found': False, 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'URLhaus', 'found': False, 'error': str(e)}

# ── Source 4: PhishTank ───────────────────────────────────────────
def check_phishtank_domain(domain):
    try:
        import urllib.parse
        url = f'http://{domain}/'
        r = requests.post('https://checkurl.phishtank.com/checkurl/',
            data={'url': url, 'format': 'json'},
            headers={**HEADERS, 'Content-Type': 'application/x-www-form-urlencoded'}, timeout=8)
        if r.status_code == 200:
            data = r.json().get('results', {})
            in_db = data.get('in_database', False)
            verified = data.get('verified', False)
            found = in_db or verified
            return {
                'source': 'PhishTank',
                'found': found,
                'verified_phish': verified,
                'in_database': in_db,
                'detail': 'Verified phishing domain' if verified else ('Found in PhishTank database' if in_db else 'Not in PhishTank'),
                'score_contrib': 50 if verified else (25 if in_db else 0)
            }
        return {'source': 'PhishTank', 'found': False, 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'PhishTank', 'found': False, 'error': str(e)}

# ── Source 5: OpenPhish ───────────────────────────────────────────
def check_openphish_domain(domain):
    try:
        r = requests.get('https://openphish.com/feed.txt', headers=HEADERS, timeout=8)
        if r.status_code == 200:
            found = any(domain in line.lower() for line in r.text.strip().split('\n'))
            return {
                'source': 'OpenPhish',
                'found': found,
                'detail': 'Domain found in OpenPhish active feed' if found else 'Not in OpenPhish feed',
                'score_contrib': 45 if found else 0
            }
        return {'source': 'OpenPhish', 'found': False, 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'OpenPhish', 'found': False, 'error': str(e)}

# ── Source 6: crt.sh (cert transparency) ─────────────────────────
def check_crtsh(domain):
    try:
        r = requests.get(f'https://crt.sh/?q=%.{domain}&output=json&limit=20',
            headers=HEADERS, timeout=10)
        if r.status_code == 200:
            certs = r.json() if r.text.strip().startswith('[') else []
            subdomains = list(set(
                c.get('name_value', '').replace('*.', '') 
                for c in certs 
                if domain in c.get('name_value', '')
            ))[:10]
            # Flag suspicious subdomains
            suspicious_kw = ['login','secure','account','verify','update','banking','payment','signin','confirm','support']
            suspicious = [s for s in subdomains if any(k in s.lower() for k in suspicious_kw)]
            return {
                'source': 'crt.sh',
                'found': len(suspicious) > 0,
                'total_certs': len(certs),
                'subdomains': subdomains[:8],
                'suspicious_subdomains': suspicious,
                'detail': f'{len(suspicious)} suspicious subdomains from {len(certs)} certs' if suspicious else f'{len(certs)} certs found, no suspicious subdomains',
                'score_contrib': min(len(suspicious) * 10, 30)
            }
        return {'source': 'crt.sh', 'found': False, 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'crt.sh', 'found': False, 'error': str(e)}

# ── Source 7: Typosquatting detector ─────────────────────────────
def check_typosquatting(domain, brand_domains=None):
    """Check if domain looks like a typosquat of known brands or provided domains"""
    KNOWN_BRANDS = [
        'paypal.com','amazon.com','google.com','microsoft.com','apple.com',
        'facebook.com','instagram.com','netflix.com','hsbc.com','barclays.com',
        'lloydsbank.com','natwest.com','halifax.com','santander.co.uk',
        'gov.uk','hmrc.gov.uk','dvla.gov.uk','nhs.uk',
    ]
    targets = list(set((brand_domains or []) + KNOWN_BRANDS))
    
    def similarity(a, b):
        # Normalise: strip TLD, replace hyphens with nothing for comparison
        a_name = re.sub(r'[.-]', '', a.split('.')[0])
        b_name = re.sub(r'[.-]', '', b.split('.')[0])
        # Also check if brand name is contained within the domain
        a_full = re.sub(r'[.-]', '', '.'.join(a.split('.')[:2]))
        b_core = re.sub(r'[.-]', '', b.split('.')[0])
        contain_score = 0.85 if b_core in a_full and b_core != a_full else 0
        seq_score = SequenceMatcher(None, a_name, b_name).ratio()
        return max(seq_score, contain_score)
    
    matches = []
    for brand in targets:
        score = similarity(domain, brand)
        if 0.7 <= score < 1.0 and domain != brand:
            matches.append({'brand': brand, 'similarity': round(score * 100)})
    
    matches.sort(key=lambda x: -x['similarity'])
    found = len(matches) > 0
    return {
        'source': 'Typosquatting Check',
        'found': found,
        'matches': matches[:5],
        'detail': f'Similar to {matches[0]["brand"]} ({matches[0]["similarity"]}%)' if found else 'No typosquatting patterns detected',
        'score_contrib': min(matches[0]['similarity'] - 40, 35) if found else 0
    }

# ── Master scan ───────────────────────────────────────────────────
def full_domain_scan(target, api_keys=None):
    api_keys = api_keys or {}
    domain = _clean_domain(target)
    
    results = []
    results.append(check_vt_domain(domain, api_keys.get('virustotal')))
    results.append(check_urlscan(domain))
    results.append(check_urlhaus_domain(domain))
    results.append(check_phishtank_domain(domain))
    results.append(check_openphish_domain(domain))
    results.append(check_crtsh(domain))
    results.append(check_typosquatting(domain))

    total_score = sum(r.get('score_contrib', 0) for r in results)
    total_score = min(total_score, 100)
    threats_found = sum(1 for r in results if r.get('found'))

    return {
        'domain': domain,
        'original_input': target,
        'overall_risk': _risk_level(total_score),
        'risk_score': total_score,
        'threats_found': threats_found,
        'sources_checked': len(results),
        'results': results,
        'scanned_at': datetime.utcnow().isoformat()
    }
