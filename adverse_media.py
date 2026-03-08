"""
Adverse Media Screening Engine — DefenceIQ
Sources: NewsAPI, Google News RSS, Guardian API (all free tiers)
Uses Claude AI to classify relevance and severity.
"""
import requests, json, re
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv('/var/www/defenceiq/.env')

HEADERS = {'User-Agent': 'DefenceIQ/1.0'}

CRIME_KEYWORDS = [
    'fraud', 'money laundering', 'bribery', 'corruption', 'sanction', 'arrested',
    'convicted', 'indicted', 'charged', 'investigated', 'scam', 'embezzlement',
    'insider trading', 'tax evasion', 'terrorist', 'trafficking', 'ponzi',
    'regulatory action', 'fined', 'banned', 'disqualified', 'bankruptcy',
    'insolvency', 'defaulted', 'criminal', 'illicit', 'proceeds of crime'
]

def _risk_level(score):
    if score >= 75: return 'critical'
    if score >= 50: return 'high'
    if score >= 25: return 'medium'
    if score > 0:   return 'low'
    return 'clean'

# ── Source 1: NewsAPI ────────────────────────────────────────────────
def search_newsapi(query, api_key=None):
    if not api_key:
        return {'source': 'NewsAPI', 'found': False, 'articles': [], 'detail': 'No API key'}
    try:
        since = (datetime.utcnow() - timedelta(days=365)).strftime('%Y-%m-%d')
        r = requests.get('https://newsapi.org/v2/everything', params={
            'q': f'"{query}" AND ({" OR ".join(CRIME_KEYWORDS[:8])})',
            'from': since, 'sortBy': 'relevancy',
            'language': 'en', 'pageSize': 5,
            'apiKey': api_key
        }, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            articles = r.json().get('articles', [])
            crime_articles = []
            for a in articles:
                text = f"{a.get('title','')} {a.get('description','')}".lower()
                kw_hits = [k for k in CRIME_KEYWORDS if k in text]
                if kw_hits:
                    crime_articles.append({
                        'title': a.get('title',''),
                        'source': a.get('source',{}).get('name',''),
                        'url': a.get('url',''),
                        'date': a.get('publishedAt','')[:10],
                        'keywords': kw_hits[:3]
                    })
            found = len(crime_articles) > 0
            return {
                'source': 'NewsAPI',
                'found': found,
                'articles': crime_articles[:5],
                'total': len(crime_articles),
                'detail': f'{len(crime_articles)} adverse articles found' if found else 'No adverse media found',
                'score_contrib': min(len(crime_articles) * 15, 45)
            }
        return {'source': 'NewsAPI', 'found': False, 'articles': [], 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'NewsAPI', 'found': False, 'articles': [], 'error': str(e)}

# ── Source 2: Google News RSS ────────────────────────────────────────
def search_google_news_rss(query):
    try:
        import urllib.parse
        search_q = urllib.parse.quote(f'{query} fraud OR "money laundering" OR corruption OR arrested OR convicted')
        r = requests.get(
            f'https://news.google.com/rss/search?q={search_q}&hl=en-GB&gl=GB&ceid=GB:en',
            headers=HEADERS, timeout=10
        )
        if r.status_code == 200:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(r.content)
            items = root.findall('.//item')
            crime_articles = []
            for item in items[:10]:
                title = item.findtext('title', '')
                link  = item.findtext('link', '')
                date  = item.findtext('pubDate', '')[:16]
                text  = title.lower()
                kw_hits = [k for k in CRIME_KEYWORDS if k in text]
                if kw_hits:
                    crime_articles.append({
                        'title': title,
                        'source': 'Google News',
                        'url': link,
                        'date': date,
                        'keywords': kw_hits[:3]
                    })
            found = len(crime_articles) > 0
            return {
                'source': 'Google News RSS',
                'found': found,
                'articles': crime_articles[:5],
                'total': len(crime_articles),
                'detail': f'{len(crime_articles)} adverse results' if found else 'No adverse media found',
                'score_contrib': min(len(crime_articles) * 12, 40)
            }
        return {'source': 'Google News RSS', 'found': False, 'articles': [], 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'Google News RSS', 'found': False, 'articles': [], 'error': str(e)}

# ── Source 3: The Guardian API (free, no key needed for basic) ───────
def search_guardian(query):
    try:
        r = requests.get('https://content.guardianapis.com/search', params={
            'q': f'{query} fraud OR corruption OR "money laundering" OR convicted',
            'api-key': 'test',
            'show-fields': 'headline,trailText',
            'page-size': 5,
            'order-by': 'relevance'
        }, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            results = r.json().get('response', {}).get('results', [])
            crime_articles = []
            for a in results:
                fields = a.get('fields', {})
                title  = fields.get('headline', a.get('webTitle',''))
                text   = f"{title} {fields.get('trailText','')}".lower()
                kw_hits = [k for k in CRIME_KEYWORDS if k in text]
                if kw_hits:
                    crime_articles.append({
                        'title': title,
                        'source': 'The Guardian',
                        'url': a.get('webUrl',''),
                        'date': a.get('webPublicationDate','')[:10],
                        'keywords': kw_hits[:3]
                    })
            found = len(crime_articles) > 0
            return {
                'source': 'The Guardian',
                'found': found,
                'articles': crime_articles[:3],
                'total': len(crime_articles),
                'detail': f'{len(crime_articles)} Guardian results' if found else 'No results',
                'score_contrib': min(len(crime_articles) * 18, 40)
            }
        return {'source': 'The Guardian', 'found': False, 'articles': [], 'detail': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'source': 'The Guardian', 'found': False, 'articles': [], 'error': str(e)}

# ── Claude AI classifier ─────────────────────────────────────────────
def classify_with_ai(query, all_articles, api_key=None):
    if not api_key or not all_articles:
        return None
    try:
        headlines = '\n'.join([f"- {a['title']} ({a.get('date','')})" for a in all_articles[:8]])
        r = requests.post('https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={
                'model': 'claude-haiku-4-5-20251001',
                'max_tokens': 300,
                'messages': [{'role': 'user', 'content': f"""You are a financial crime compliance analyst.

Subject being screened: "{query}"

News headlines found:
{headlines}

Assess the adverse media risk. Reply in JSON only:
{{
  "relevant": true/false,
  "risk_level": "critical|high|medium|low|clean",
  "summary": "one sentence assessment",
  "primary_concern": "main risk category or null"
}}"""}]
            }, timeout=15)
        if r.status_code == 200:
            text = r.json()['content'][0]['text'].strip()
            text = re.sub(r'^```json\s*|\s*```$', '', text)
            return json.loads(text)
    except Exception:
        pass
    return None

# ── Master scan ──────────────────────────────────────────────────────
def screen_adverse_media(query, api_keys=None):
    api_keys = api_keys or {}
    results  = []

    results.append(search_google_news_rss(query))
    results.append(search_guardian(query))
    results.append(search_newsapi(query, api_keys.get('newsapi')))

    all_articles = []
    for r in results:
        all_articles.extend(r.get('articles', []))

    total_score  = sum(r.get('score_contrib', 0) for r in results)
    total_score  = min(total_score, 100)
    sources_hit  = sum(1 for r in results if r.get('found'))

    ai_assessment = classify_with_ai(query, all_articles, api_keys.get('anthropic'))
    if ai_assessment and ai_assessment.get('relevant') is False:
        total_score = max(total_score - 20, 0)

    return {
        'query': query,
        'overall_risk': _risk_level(total_score),
        'risk_score': total_score,
        'sources_hit': sources_hit,
        'sources_checked': len(results),
        'total_articles': len(all_articles),
        'articles': all_articles[:10],
        'results': results,
        'ai_assessment': ai_assessment,
        'scanned_at': datetime.utcnow().isoformat()
    }
