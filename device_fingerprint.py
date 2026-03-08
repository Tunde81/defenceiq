"""
Device Fingerprinting Engine — DefenceIQ
"""
import hashlib, json
from datetime import datetime

SUSPICIOUS_UA_PATTERNS = [
    'headlesschrome', 'phantomjs', 'selenium', 'webdriver',
    'python-requests', 'curl/', 'wget/', 'scrapy', 'bot', 'crawl'
]

HIGH_RISK_ASNS = [
    'AS9009','AS20473','AS14061','AS16509','AS15169',
    'AS8075','AS13335','AS60781','AS36352',
]

def compute_fingerprint_hash(fp_data):
    stable = {k: fp_data.get(k) for k in sorted([
        'screen_resolution','color_depth','timezone',
        'platform','canvas_hash','webgl_vendor',
        'fonts_count','plugins_count'
    ])}
    raw = json.dumps(stable, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def analyse_fingerprint(fp_data, user_agent='', ip_info=None):
    flags = []
    score = 0
    ip_info = ip_info or {}
    ua_lower = user_agent.lower()

    for pattern in SUSPICIOUS_UA_PATTERNS:
        if pattern in ua_lower:
            flags.append({'signal':'headless_browser','detail':f'UA matches automation: {pattern}','severity':'critical','score':40})
            score += 40
            break

    if fp_data.get('webdriver') is True:
        flags.append({'signal':'webdriver_detected','detail':'navigator.webdriver=true — browser controlled by automation','severity':'critical','score':45})
        score += 45

    plugins = fp_data.get('plugins_count', -1)
    if plugins == 0 and 'chrome' in ua_lower:
        flags.append({'signal':'no_plugins','detail':'Chrome with zero plugins — typical headless Chrome','severity':'high','score':20})
        score += 20

    canvas_hash = fp_data.get('canvas_hash', '')
    if canvas_hash in ('', 'blocked', 'error', None):
        flags.append({'signal':'canvas_blocked','detail':'Canvas fingerprinting blocked — anti-detect browser or privacy tool','severity':'medium','score':15})
        score += 15

    fp_tz = fp_data.get('timezone', '')
    ip_country = ip_info.get('country', '')
    if fp_tz == 'UTC' and ip_country not in ('','GB','IS','GH','SN','GM'):
        flags.append({'signal':'timezone_mismatch','detail':f'Device timezone UTC but IP suggests {ip_country} — possible VPN','severity':'medium','score':20})
        score += 20
    elif fp_tz and ip_country:
        tz_region = fp_tz.split('/')[0] if '/' in fp_tz else ''
        if ip_country in ('RU','CN','KP','IR','SY','MM','BY') and tz_region in ('America','Europe'):
            flags.append({'signal':'timezone_country_mismatch','detail':f'Timezone {fp_tz} inconsistent with IP country {ip_country}','severity':'high','score':25})
            score += 25

    res = fp_data.get('screen_resolution', '')
    if res:
        try:
            w, h = [int(x) for x in res.lower().replace('x',',').split(',')]
            if w < 800 or h < 600:
                flags.append({'signal':'unusual_resolution','detail':f'Resolution {res} unusually small — virtualised environment','severity':'medium','score':15})
                score += 15
            elif w == 1920 and h == 1080 and plugins == 0:
                flags.append({'signal':'generic_vm_resolution','detail':'1920x1080 + zero plugins — common VM/headless fingerprint','severity':'low','score':8})
                score += 8
        except: pass

    lang = fp_data.get('language', '')
    if lang and ip_country and (lang, ip_country) in [('en-US','RU'),('en-US','CN'),('en-US','KP'),('en-GB','RU'),('en-GB','CN')]:
        flags.append({'signal':'language_country_mismatch','detail':f'Browser lang {lang} inconsistent with IP country {ip_country}','severity':'medium','score':18})
        score += 18

    ip_asn = ip_info.get('asn', '')
    if ip_asn and any(ip_asn.startswith(a) for a in HIGH_RISK_ASNS):
        flags.append({'signal':'vpn_hosting_asn','detail':f'ASN {ip_asn} belongs to VPN/hosting provider','severity':'high','score':25})
        score += 25

    fonts = fp_data.get('fonts_count', -1)
    if fonts == 0:
        flags.append({'signal':'no_fonts','detail':'Zero fonts — sandboxed or restricted environment','severity':'medium','score':12})
        score += 12

    score = min(score, 100)
    if score >= 75: risk = 'critical'
    elif score >= 50: risk = 'high'
    elif score >= 25: risk = 'medium'
    elif score > 0: risk = 'low'
    else: risk = 'clean'

    fp_hash = compute_fingerprint_hash(fp_data)
    top = flags[0]['signal'].replace('_',' ').title() if flags else 'None'
    return {
        'fingerprint_hash': fp_hash,
        'risk_score': score,
        'risk_level': risk,
        'flag_count': len(flags),
        'flags': flags,
        'signals_checked': 8,
        'analysed_at': datetime.utcnow().isoformat(),
        'summary': f'Device {fp_hash} — {risk.upper()} risk. {len(flags)} flag(s). Primary: {top}.'
    }

def get_device_stats(org_id, session):
    from sqlalchemy import text
    row = session.execute(text("""
        SELECT COUNT(*) as total,
               COUNT(DISTINCT fingerprint_hash) as unique_devices,
               SUM(CASE WHEN risk_level IN ('critical','high') THEN 1 ELSE 0 END) as high_risk,
               SUM(CASE WHEN risk_level='critical' THEN 1 ELSE 0 END) as critical_count
        FROM device_fingerprints WHERE org_id=:o
    """), {'o': org_id}).fetchone()
    if row: return type('S',(),dict(row._mapping))()
    return type('S',(),{'total':0,'unique_devices':0,'high_risk':0,'critical_count':0})()
