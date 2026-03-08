"""
DefenceIQ Dark Web & Breach Intelligence Monitor
Free sources: HIBP Pwned Passwords, LeakCheck, EmailRep,
              AbuseIPDB, VirusTotal, OpenPhish, URLhaus, PhishTank, Tor Exit Nodes
"""
import requests, json, hashlib
from datetime import datetime

def check_abuseipdb(ip_address, api_key=None):
    if not api_key:
        return {'source': 'AbuseIPDB', 'found': False, 'reason': 'No API key configured'}
    try:
        r = requests.get('https://api.abuseipdb.com/api/v2/check',
            headers={'Key': api_key, 'Accept': 'application/json'},
            params={'ipAddress': ip_address, 'maxAgeInDays': 90}, timeout=8)
        data = r.json().get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        return {'source': 'AbuseIPDB', 'found': score > 0, 'score': score,
            'country': data.get('countryCode'), 'isp': data.get('isp'),
            'total_reports': data.get('totalReports', 0),
            'detail': f'Abuse score {score}/100 — {data.get("totalReports",0)} reports',
            'risk_level': 'critical' if score>=75 else 'high' if score>=50 else 'medium' if score>0 else 'clean'}
    except Exception as e:
        return {'source': 'AbuseIPDB', 'found': False, 'error': str(e)}

def check_virustotal_url(url_or_domain, api_key=None):
    if not api_key:
        return {'source': 'VirusTotal', 'found': False, 'reason': 'No API key configured'}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url_or_domain.encode()).decode().strip('=')
        r = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': api_key}, timeout=8)
        if r.status_code == 200:
            stats = r.json().get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
            malicious, suspicious = stats.get('malicious',0), stats.get('suspicious',0)
            return {'source': 'VirusTotal', 'found': malicious>0 or suspicious>0,
                'malicious_engines': malicious, 'suspicious_engines': suspicious,
                'detail': f'{malicious} malicious, {suspicious} suspicious engines',
                'risk_level': 'critical' if malicious>=5 else 'high' if malicious>0 else 'medium' if suspicious>0 else 'clean'}
        return {'source': 'VirusTotal', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'VirusTotal', 'found': False, 'error': str(e)}

def check_emailrep(email, api_key=None):
    try:
        headers = {'Key': api_key} if api_key else {}
        r = requests.get(f'https://emailrep.io/{email}',
            headers={**headers, 'User-Agent': 'DefenceIQ/1.0'}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            suspicious = data.get('suspicious', False)
            flags = data.get('details', {}).get('flags', [])
            return {'source': 'EmailRep', 'found': suspicious,
                'reputation': data.get('reputation','unknown'), 'suspicious': suspicious,
                'flags': flags, 'detail': f'Reputation: {data.get("reputation","unknown")}. Flags: {", ".join(flags) if flags else "none"}',
                'risk_level': 'high' if suspicious else 'clean'}
        return {'source': 'EmailRep', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'EmailRep', 'found': False, 'error': str(e)}

def check_openphish(url):
    try:
        r = requests.get('https://openphish.com/feed.txt', timeout=8)
        if r.status_code == 200:
            found = any(url.lower() in p.lower() for p in r.text.strip().split('\n'))
            return {'source': 'OpenPhish', 'found': found,
                'detail': 'URL found in OpenPhish active phishing feed' if found else 'Not in OpenPhish feed',
                'risk_level': 'critical' if found else 'clean'}
        return {'source': 'OpenPhish', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'OpenPhish', 'found': False, 'error': str(e)}

def check_hibp_passwords(password_plaintext):
    try:
        sha1 = hashlib.sha1(password_plaintext.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'DefenceIQ/1.0', 'Add-Padding': 'true'}, timeout=8)
        if r.status_code == 200:
            hashes = {line.split(':')[0]: int(line.split(':')[1]) for line in r.text.splitlines()}
            count = hashes.get(suffix, 0)
            return {'source': 'HIBP Pwned Passwords', 'found': count > 0,
                'exposure_count': count,
                'detail': f'Seen {count:,} times in breach dumps' if count > 0 else 'Not found in known breach dumps',
                'risk_level': 'critical' if count>1000 else 'high' if count>0 else 'clean'}
        return {'source': 'HIBP Pwned Passwords', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'HIBP Pwned Passwords', 'found': False, 'error': str(e)}

def check_leakcheck(email):
    try:
        r = requests.get(f'https://leakcheck.io/api/public?check={email}',
            headers={'User-Agent': 'DefenceIQ/1.0'}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            found_count = data.get('found', 0)
            fields = data.get('fields', [])
            high_risk_fields = {'password','hash','plaintext','credit_card','ssn','bvn','pin'}
            has_creds = bool(set(fields) & high_risk_fields)
            return {'source': 'LeakCheck', 'found': found_count > 0,
                'breach_count': found_count, 'exposed_fields': fields[:8],
                'credentials_exposed': has_creds,
                'detail': f'Found in {found_count} breach records. Exposed: {", ".join(fields[:5])}' if found_count > 0 else 'No breach records found',
                'risk_level': 'critical' if has_creds else 'high' if found_count>5 else 'medium' if found_count>0 else 'clean'}
        return {'source': 'LeakCheck', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'LeakCheck', 'found': False, 'error': str(e)}

def check_urlhaus(url_or_domain):
    try:
        if url_or_domain.startswith('http'):
            r = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': url_or_domain}, timeout=8)
        else:
            r = requests.post('https://urlhaus-api.abuse.ch/v1/host/', data={'host': url_or_domain}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            status = data.get('query_status','')
            found = status in ['is_host','is_url']
            urls_count = len(data.get('urls',[]))
            return {'source': 'URLhaus', 'found': found,
                'threat_type': data.get('threat','malware distribution'),
                'url_count': urls_count,
                'detail': f'{urls_count} malicious URLs — {data.get("threat","")}' if found else 'Not found in URLhaus',
                'risk_level': 'critical' if found else 'clean'}
        return {'source': 'URLhaus', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'URLhaus', 'found': False, 'error': str(e)}

def check_phishtank(url):
    try:
        import urllib.parse
        r = requests.post('https://checkurl.phishtank.com/checkurl/',
            data={'url': urllib.parse.quote(url, safe=''), 'format': 'json', 'app_key': ''},
            headers={'User-Agent': 'DefenceIQ/1.0'}, timeout=10)
        if r.status_code == 200:
            data = r.json().get('results', {})
            in_db = data.get('in_database', False)
            verified = data.get('verified', False)
            return {'source': 'PhishTank', 'found': verified or in_db,
                'in_database': in_db, 'verified_phish': verified,
                'detail': 'Verified phishing URL' if verified else ('Found in PhishTank database' if in_db else 'Not found in PhishTank'),
                'risk_level': 'critical' if verified else 'high' if in_db else 'clean'}
        return {'source': 'PhishTank', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'PhishTank', 'found': False, 'error': str(e)}

def check_tor_exit(ip_address):
    try:
        r = requests.get('https://check.torproject.org/torbulkexitlist', timeout=8)
        if r.status_code == 200:
            found = ip_address in set(r.text.strip().split('\n'))
            return {'source': 'Tor Exit Nodes', 'found': found,
                'detail': 'Known Tor exit node — traffic is anonymised' if found else 'Not a known Tor exit node',
                'risk_level': 'high' if found else 'clean'}
        return {'source': 'Tor Exit Nodes', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'Tor Exit Nodes', 'found': False, 'error': str(e)}

def dark_web_scan(indicator_type, indicator_value, api_keys=None):
    api_keys = api_keys or {}
    results = []
    risk_order = ['clean','low','medium','high','critical']
    overall_risk = 'clean'

    if indicator_type == 'email':
        results.append(check_leakcheck(indicator_value))
        results.append(check_emailrep(indicator_value, api_keys.get('emailrep')))
    elif indicator_type == 'password':
        results.append(check_hibp_passwords(indicator_value))
    elif indicator_type == 'ip':
        results.append(check_abuseipdb(indicator_value, api_keys.get('abuseipdb')))
        results.append(check_tor_exit(indicator_value))
    elif indicator_type in ['url','domain']:
        results.append(check_urlhaus(indicator_value))
        results.append(check_virustotal_url(indicator_value, api_keys.get('virustotal')))
        if indicator_type == 'url':
            results.append(check_phishtank(indicator_value))
            results.append(check_openphish(indicator_value))
    else:
        results.append({'source': 'DefenceIQ Intelligence', 'found': False,
            'detail': f'No dark web feed available for {indicator_type}.', 'risk_level': 'unknown'})

    for res in results:
        level = res.get('risk_level','clean')
        if level in risk_order and risk_order.index(level) > risk_order.index(overall_risk):
            overall_risk = level

    findings = [r for r in results if r.get('found')]
    summary = ' | '.join([f"{f['source']}: {f.get('detail','')}" for f in findings]) if findings else 'No threat matches found across checked sources.'

    return {'indicator_type': indicator_type, 'indicator_value': indicator_value,
        'scanned_at': datetime.utcnow().isoformat(), 'overall_risk': overall_risk,
        'sources_checked': len(results), 'results': results, 'threat_summary': summary}

def scan_indicator(indicator_type, indicator_value, api_keys=None):
    """Backward-compatible — used by existing threat_intel route"""
    api_keys = api_keys or {}
    results = []
    risk_order = ['clean','low','medium','high','critical']
    overall_risk = 'clean'

    if indicator_type == 'ip':
        results.append(check_abuseipdb(indicator_value, api_keys.get('abuseipdb')))
    elif indicator_type == 'email':
        results.append(check_emailrep(indicator_value, api_keys.get('emailrep')))
        results.append(check_leakcheck(indicator_value))
    elif indicator_type in ['url','domain']:
        results.append(check_virustotal_url(indicator_value, api_keys.get('virustotal')))
        results.append(check_urlhaus(indicator_value))
        if indicator_type == 'url':
            results.append(check_openphish(indicator_value))
            results.append(check_phishtank(indicator_value))
    else:
        results.append({'source': 'DefenceIQ Intelligence', 'found': False,
            'reason': f'No external feed for {indicator_type}.', 'risk_level': 'unknown'})

    for res in results:
        level = res.get('risk_level','clean')
        if level in risk_order and risk_order.index(level) > risk_order.index(overall_risk):
            overall_risk = level

    return {'indicator_type': indicator_type, 'indicator_value': indicator_value,
        'scanned_at': datetime.utcnow().isoformat(), 'overall_risk': overall_risk,
        'sources_checked': len(results), 'results': results}


# ── IP REPUTATION EXPANSION ───────────────────────────────────────

def check_ipinfo(ip_address):
    """Get ASN, geolocation, org, hostname via ipinfo.io (free tier: 50k/month)"""
    try:
        r = requests.get(f'https://ipinfo.io/{ip_address}/json',
            headers={'User-Agent': 'DefenceIQ/1.0'}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            org = data.get('org', '')
            is_hosting = any(k in org.lower() for k in ['hosting','cloud','vps','server','datacenter','amazon','google','microsoft','digitalocean','linode','vultr','hetzner','ovh'])
            return {
                'source': 'IPInfo',
                'found': False,
                'ip': data.get('ip'),
                'hostname': data.get('hostname',''),
                'city': data.get('city',''),
                'region': data.get('region',''),
                'country': data.get('country',''),
                'org': org,
                'asn': org.split(' ')[0] if org else '',
                'timezone': data.get('timezone',''),
                'is_hosting': is_hosting,
                'detail': f"{data.get('city','')}, {data.get('country','')} — {org}",
                'risk_level': 'medium' if is_hosting else 'clean'
            }
        return {'source': 'IPInfo', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'IPInfo', 'found': False, 'error': str(e)}


def check_ip_vpn_proxy(ip_address):
    """Check if IP is VPN/proxy/hosting using ip-api.com (free, no key)"""
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query',
            headers={'User-Agent': 'DefenceIQ/1.0'}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                is_proxy   = data.get('proxy', False)
                is_hosting = data.get('hosting', False)
                risk = 'high' if is_proxy else 'medium' if is_hosting else 'clean'
                flags = []
                if is_proxy:   flags.append('VPN/Proxy')
                if is_hosting: flags.append('Hosting/Datacenter')
                return {
                    'source': 'IP-API',
                    'found': is_proxy or is_hosting,
                    'country': data.get('country',''),
                    'country_code': data.get('countryCode',''),
                    'city': data.get('city',''),
                    'isp': data.get('isp',''),
                    'org': data.get('org',''),
                    'asn': data.get('as',''),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'is_proxy': is_proxy,
                    'is_hosting': is_hosting,
                    'flags': flags,
                    'detail': f"{'VPN/Proxy detected' if is_proxy else 'Hosting/DC' if is_hosting else 'Residential/ISP'} — {data.get('isp','')} ({data.get('country','')})",
                    'risk_level': risk
                }
        return {'source': 'IP-API', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'IP-API', 'found': False, 'error': str(e)}


def check_bgp_ranking(asn):
    """Check ASN reputation via bgpranking (free)"""
    try:
        if not asn:
            return {'source': 'BGP Ranking', 'found': False, 'reason': 'No ASN provided'}
        # Strip AS prefix
        asn_num = asn.replace('AS','').replace('as','').strip().split(' ')[0]
        r = requests.get(
            f'https://bgpranking-ng.circl.lu/json/asn?asn={asn_num}',
            headers={'User-Agent': 'DefenceIQ/1.0'}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            ranking = data.get('response', {}).get('ranking', {})
            rank = ranking.get('rank')
            position = ranking.get('position')
            found = rank is not None and rank > 0.01
            return {
                'source': 'BGP Ranking',
                'found': found,
                'asn': asn_num,
                'rank': rank,
                'position': position,
                'detail': f'ASN{asn_num} rank: {rank:.4f} (position {position})' if rank else f'ASN{asn_num} — no ranking data',
                'risk_level': 'high' if rank and rank > 0.05 else 'medium' if rank and rank > 0.01 else 'clean'
            }
        return {'source': 'BGP Ranking', 'found': False, 'reason': f'Status {r.status_code}'}
    except Exception as e:
        return {'source': 'BGP Ranking', 'found': False, 'error': str(e)}


def full_ip_reputation(ip_address, api_keys=None):
    """
    Full IP reputation scan — all sources combined.
    Returns enriched result with geolocation, ASN, abuse, proxy, Tor.
    """
    api_keys = api_keys or {}
    results  = []
    risk_order = ['clean','low','medium','high','critical']
    overall_risk = 'clean'

    # Run all IP checks
    ipapi_result  = check_ip_vpn_proxy(ip_address)
    abuse_result  = check_abuseipdb(ip_address, api_keys.get('abuseipdb'))
    tor_result    = check_tor_exit(ip_address)
    ipinfo_result = check_ipinfo(ip_address)

    results = [abuse_result, ipapi_result, tor_result, ipinfo_result]

    # BGP ranking from ASN
    asn = ipapi_result.get('asn') or ipinfo_result.get('asn','')
    if asn:
        bgp_result = check_bgp_ranking(asn)
        results.append(bgp_result)

    for res in results:
        level = res.get('risk_level','clean')
        if level in risk_order and risk_order.index(level) > risk_order.index(overall_risk):
            overall_risk = level

    # Build enriched geo data from best source
    geo = {}
    for src in [ipapi_result, ipinfo_result]:
        if src.get('country'):
            geo = {
                'country':      src.get('country',''),
                'country_code': src.get('country_code', src.get('country','')),
                'city':         src.get('city',''),
                'isp':          src.get('isp', src.get('org','')),
                'org':          src.get('org',''),
                'asn':          src.get('asn',''),
                'lat':          src.get('lat'),
                'lon':          src.get('lon'),
                'is_proxy':     src.get('is_proxy', False),
                'is_hosting':   src.get('is_hosting', False),
                'is_tor':       tor_result.get('found', False),
            }
            break

    findings = [r for r in results if r.get('found')]
    summary  = ' | '.join([f"{f['source']}: {f.get('detail','')}" for f in findings]) if findings else 'No threat matches found.'

    return {
        'indicator_type':  'ip',
        'indicator_value': ip_address,
        'scanned_at':      datetime.utcnow().isoformat(),
        'overall_risk':    overall_risk,
        'sources_checked': len(results),
        'results':         results,
        'geo':             geo,
        'threat_summary':  summary
    }
