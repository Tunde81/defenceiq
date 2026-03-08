"""
DefenceIQ Sanctions & Watchlist Screening
Sources:
  - UN Security Council Consolidated List (730 individuals, 272 entities)
  - UK HMT Consolidated List (OFSI)
  - Fuzzy name matching with confidence scoring
"""
import requests
import csv
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from difflib import SequenceMatcher
import unicodedata
import re

# ── CACHE (in-memory, refreshed every 24h) ───────────────────────
_cache = {
    'un':        {'data': [], 'loaded_at': None},
    'hmt':       {'data': [], 'loaded_at': None},
}
CACHE_TTL_HOURS = 24


def _cache_valid(key):
    loaded = _cache[key]['loaded_at']
    return loaded and (datetime.utcnow() - loaded) < timedelta(hours=CACHE_TTL_HOURS)


def _normalise(text):
    """Lowercase, strip accents, remove punctuation for fuzzy matching"""
    if not text:
        return ''
    text = unicodedata.normalize('NFD', text)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Mn')
    text = re.sub(r'[^a-z0-9\s]', ' ', text.lower())
    return ' '.join(text.split())


def _is_latin(text):
    """Return True if text is primarily Latin script"""
    if not text:
        return False
    latin = sum(1 for c in text if ord(c) < 256 and c.isalpha())
    total = sum(1 for c in text if c.isalpha())
    return total > 0 and (latin / total) >= 0.8

def _fuzzy_score(a, b):
    """Return 0-100 similarity score between two strings"""
    # Skip non-Latin entries entirely
    if not _is_latin(b):
        return 0
    # Skip very short list entries (2-3 char abbreviations like "AB")
    if len(b.strip()) < 5:
        return 0
    a_norm, b_norm = _normalise(a), _normalise(b)
    if not a_norm or not b_norm:
        return 0
    # Exact match
    if a_norm == b_norm:
        return 100
    # One contains the other (only if b is reasonably long)
    if len(b_norm) >= 6 and (a_norm in b_norm or b_norm in a_norm):
        return 88
    # Token sort ratio (word-order independent — catches "Laden Osama Bin")
    a_tokens = sorted([t for t in a_norm.split() if len(t) > 1])
    b_tokens = sorted([t for t in b_norm.split() if len(t) > 1])
    if not a_tokens or not b_tokens:
        return 0
    token_score = SequenceMatcher(None, ' '.join(a_tokens), ' '.join(b_tokens)).ratio() * 100
    # Sequence ratio
    seq_score = SequenceMatcher(None, a_norm, b_norm).ratio() * 100
    raw = max(token_score, seq_score)
    # Penalise if query is much longer than list entry (avoids "John Smith X" -> short names)
    len_ratio = min(len(a_norm), len(b_norm)) / max(len(a_norm), len(b_norm))
    if len_ratio < 0.5:
        raw *= 0.85
    return round(raw)


# ── UN CONSOLIDATED LIST ─────────────────────────────────────────

def _load_un_list():
    if _cache_valid('un'):
        return _cache['un']['data']
    try:
        r = requests.get(
            'https://scsanctions.un.org/resources/xml/en/consolidated.xml',
            timeout=20, headers={'User-Agent': 'DefenceIQ/1.0'}
        )
        root = ET.fromstring(r.content)
        entries = []

        for ind in root.findall('.//INDIVIDUAL'):
            first  = ind.findtext('FIRST_NAME', '').strip()
            second = ind.findtext('SECOND_NAME', '').strip()
            third  = ind.findtext('THIRD_NAME', '').strip()
            fourth = ind.findtext('FOURTH_NAME', '').strip()
            full_name = ' '.join(filter(None, [first, second, third, fourth]))

            # Collect aliases
            aliases = []
            for alias in ind.findall('.//INDIVIDUAL_ALIAS'):
                aname = alias.findtext('ALIAS_NAME', '').strip()
                if aname:
                    aliases.append(aname)

            nationality = ind.findtext('NATIONALITY/VALUE', '') or ind.findtext('NATIONALITY', '')
            entries.append({
                'name':        full_name,
                'aliases':     aliases,
                'type':        'Individual',
                'list':        'UN Security Council',
                'list_type':   ind.findtext('UN_LIST_TYPE', ''),
                'ref':         ind.findtext('REFERENCE_NUMBER', ''),
                'listed_on':   ind.findtext('LISTED_ON', ''),
                'nationality': nationality,
                'comments':    ind.findtext('COMMENTS1', '')[:200] if ind.findtext('COMMENTS1') else '',
            })

        for ent in root.findall('.//ENTITY'):
            name = ent.findtext('FIRST_NAME', '').strip()
            aliases = []
            for alias in ent.findall('.//ENTITY_ALIAS'):
                aname = alias.findtext('ALIAS_NAME', '').strip()
                if aname:
                    aliases.append(aname)
            entries.append({
                'name':        name,
                'aliases':     aliases,
                'type':        'Entity',
                'list':        'UN Security Council',
                'list_type':   ent.findtext('UN_LIST_TYPE', ''),
                'ref':         ent.findtext('REFERENCE_NUMBER', ''),
                'listed_on':   ent.findtext('LISTED_ON', ''),
                'nationality': '',
                'comments':    '',
            })

        _cache['un']['data']      = entries
        _cache['un']['loaded_at'] = datetime.utcnow()
        return entries
    except Exception as e:
        return []


# ── UK HMT CONSOLIDATED LIST ─────────────────────────────────────

def _load_hmt_list():
    if _cache_valid('hmt'):
        return _cache['hmt']['data']
    try:
        r = requests.get(
            'https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.csv',
            timeout=20, headers={'User-Agent': 'DefenceIQ/1.0'}
        )
        # Row 0 is metadata (Last Updated, date), Row 1 is real header
        lines  = r.text.splitlines()
        reader = csv.DictReader(io.StringIO('\n'.join(lines[1:])))
        entries = []
        seen_groups = {}  # group_id -> entry index, for deduplication + alias merging

        for row in reader:
            # Name 6 = surname/entity name, Name 1-5 = given names
            surname  = str(row.get('Name 6', '') or '').strip()
            given1   = str(row.get('Name 1', '') or '').strip()
            given2   = str(row.get('Name 2', '') or '').strip()
            given3   = str(row.get('Name 3', '') or '').strip()
            given4   = str(row.get('Name 4', '') or '').strip()
            given5   = str(row.get('Name 5', '') or '').strip()
            full     = ' '.join(filter(None, [given1, given2, given3, given4, given5, surname]))
            if not full:
                continue

            group_id   = str(row.get('Group ID', '') or '').strip()
            alias_type = str(row.get('Alias Type', '') or '').strip()
            regime     = str(row.get('Regime', '') or '').strip()
            listed_on  = str(row.get('Listed On', '') or '').strip()
            nationality= str(row.get('Nationality', '') or '').strip()
            group_type = str(row.get('Group Type', '') or 'Individual').strip()
            other_info = str(row.get('Other Information', '') or '')[:200]

            # If same group_id seen before, add as alias instead of new entry
            if group_id and group_id in seen_groups:
                idx = seen_groups[group_id]
                if alias_type.lower() not in ('primary name', ''):
                    entries[idx]['aliases'].append(full)
                continue

            entry = {
                'name':        full,
                'aliases':     [],
                'type':        group_type,
                'list':        'UK HMT (OFSI)',
                'list_type':   regime,
                'ref':         group_id,
                'listed_on':   listed_on,
                'nationality': nationality,
                'comments':    other_info,
            }
            if group_id:
                seen_groups[group_id] = len(entries)
            entries.append(entry)

        _cache['hmt']['data']      = entries
        _cache['hmt']['loaded_at'] = datetime.utcnow()
        return entries
    except Exception as e:
        print(f"HMT load error: {e}")
        return []


# ── MAIN SCREENING FUNCTION ──────────────────────────────────────

def screen_name(query_name, threshold=82):
    """
    Screen a name against UN and UK HMT sanctions lists.
    Returns matches above threshold with confidence scores.
    threshold: minimum fuzzy score (0-100) to include as a match
    """
    if not query_name or len(query_name.strip()) < 2:
        return {'error': 'Name too short to screen'}

    un_list  = _load_un_list()
    hmt_list = _load_hmt_list()
    all_entries = un_list + hmt_list

    matches = []
    seen_refs = set()

    for entry in all_entries:
        best_score = 0
        matched_on = entry['name']

        # Score against primary name
        score = _fuzzy_score(query_name, entry['name'])
        if score > best_score:
            best_score = score
            matched_on = entry['name']

        # Score against aliases
        for alias in entry.get('aliases', []):
            alias_score = _fuzzy_score(query_name, alias)
            if alias_score > best_score:
                best_score = alias_score
                matched_on = f"{alias} (alias)"

        if best_score >= threshold:
            ref_key = f"{entry['list']}:{entry['ref']}"
            if ref_key not in seen_refs:
                seen_refs.add(ref_key)
                matches.append({
                    **entry,
                    'score':      best_score,
                    'matched_on': matched_on,
                    'match_type': 'exact' if best_score == 100 else 'strong' if best_score >= 90 else 'possible',
                })

    # Sort by score descending
    matches.sort(key=lambda x: x['score'], reverse=True)

    # Determine overall risk
    if any(m['score'] >= 90 for m in matches):
        overall_risk = 'critical'
    elif any(m['score'] >= 80 for m in matches):
        overall_risk = 'high'
    elif matches:
        overall_risk = 'medium'
    else:
        overall_risk = 'clean'

    un_count  = sum(1 for m in matches if 'UN' in m['list'])
    hmt_count = sum(1 for m in matches if 'HMT' in m['list'])

    return {
        'query':         query_name,
        'screened_at':   datetime.utcnow().isoformat(),
        'overall_risk':  overall_risk,
        'match_count':   len(matches),
        'un_matches':    un_count,
        'hmt_matches':   hmt_count,
        'total_screened': len(all_entries),
        'un_list_size':  len(un_list),
        'hmt_list_size': len(hmt_list),
        'matches':       matches[:20],  # top 20
        'summary': f'{len(matches)} match(es) found across UN SC and UK HMT lists' if matches else 'No matches found on UN Security Council or UK HMT sanctions lists',
    }


def get_list_stats():
    """Return current list sizes and cache status"""
    un  = _load_un_list()
    hmt = _load_hmt_list()
    return {
        'un_count':       len(un),
        'hmt_count':      len(hmt),
        'total':          len(un) + len(hmt),
        'un_loaded_at':   _cache['un']['loaded_at'].isoformat() if _cache['un']['loaded_at'] else None,
        'hmt_loaded_at':  _cache['hmt']['loaded_at'].isoformat() if _cache['hmt']['loaded_at'] else None,
    }
