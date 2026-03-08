"""
AI-Powered SAR/STR Narrative Generator — DefenceIQ
Generates draft Suspicious Activity Reports in UK NCA/UKFIU format
using Claude AI, pulling all available case intelligence automatically.
"""
import requests, json, os
from datetime import datetime
from dotenv import load_dotenv
load_dotenv('/var/www/defenceiq/.env')


def _call_claude(prompt, max_tokens=1200):
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        return None, 'No Anthropic API key configured'
    try:
        r = requests.post('https://api.anthropic.com/v1/messages',
            headers={
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json'
            },
            json={
                'model': 'claude-haiku-4-5-20251001',
                'max_tokens': max_tokens,
                'messages': [{'role': 'user', 'content': prompt}]
            }, timeout=30)
        if r.status_code == 200:
            return r.json()['content'][0]['text'].strip(), None
        return None, f'API error {r.status_code}'
    except Exception as e:
        return None, str(e)


def generate_sar_narrative(case_data, intelligence_data=None):
    """
    Generate a full UK SAR narrative from case data and all available intelligence.
    case_data: dict with case fields
    intelligence_data: dict with sanctions, AML, KYC, device, adverse media results
    """
    intel = intelligence_data or {}

    # Build intelligence summary
    intel_sections = []

    if intel.get('sanctions'):
        s = intel['sanctions']
        if s.get('is_match'):
            intel_sections.append(f"SANCTIONS: Subject matched {s.get('matched_list','unknown list')} at {s.get('match_score',0)}% confidence. Matched entity: {s.get('matched_name','')}.")

    if intel.get('aml_flags'):
        flags = intel['aml_flags']
        intel_sections.append(f"AML FLAGS: {len(flags)} rule(s) triggered: {', '.join(flags[:5])}.")

    if intel.get('adverse_media'):
        am = intel['adverse_media']
        if am.get('total_articles', 0) > 0:
            intel_sections.append(f"ADVERSE MEDIA: {am['total_articles']} adverse articles found across {am.get('sources_hit',0)} sources. Risk: {am.get('overall_risk','').upper()}.")

    if intel.get('device'):
        d = intel['device']
        if d.get('risk_level') in ('high', 'critical'):
            intel_sections.append(f"DEVICE INTELLIGENCE: {d.get('risk_level','').upper()} risk device fingerprint. Flags: {', '.join(d.get('flags',[])[:4])}.")

    if intel.get('ip_reputation'):
        ip = intel['ip_reputation']
        if ip.get('is_tor') or ip.get('is_vpn') or ip.get('abuse_score', 0) > 50:
            intel_sections.append(f"IP INTELLIGENCE: Subject accessed platform via {'Tor' if ip.get('is_tor') else 'VPN/proxy'}. IP abuse score: {ip.get('abuse_score',0)}/100.")

    if intel.get('kyc'):
        k = intel['kyc']
        flags = []
        if k.get('pep_status'): flags.append('PEP')
        if k.get('sanctions_hit'): flags.append('Sanctions hit')
        if k.get('risk_rating') in ('high','critical'): flags.append(f"{k.get('risk_rating','').upper()} risk KYC")
        if flags:
            intel_sections.append(f"KYC: {', '.join(flags)}. Due diligence level: {k.get('dd_level','Standard')}.")

    intel_summary = '\n'.join(intel_sections) if intel_sections else 'No additional intelligence layers available.'

    amount = case_data.get('amount_involved', '')
    amount_str = f"£{float(amount):,.2f}" if amount and str(amount).replace('.','').isdigit() else (amount or 'undetermined')

    prompt = f"""You are a UK financial crime compliance officer drafting a Suspicious Activity Report (SAR) for submission to the National Crime Agency (NCA) via the UKFIU portal.

Write a professional, factual SAR narrative in UK NCA format. Use formal compliance language. Be specific and concise. Do not speculate beyond the evidence.

CASE DETAILS:
- Case Reference: {case_data.get('case_ref', 'N/A')}
- Subject Name: {case_data.get('subject_name', 'Unknown')}
- Subject Email: {case_data.get('subject_email', 'N/A')}
- Subject IP: {case_data.get('subject_ip', 'N/A')}
- Fraud Type: {case_data.get('fraud_type', 'Unclassified')}
- Amount Involved: {amount_str}
- Risk Level: {case_data.get('risk_level', 'Unknown').upper()}
- Case Status: {case_data.get('status', 'Open')}
- Description: {case_data.get('description', 'No description provided')}
- Date Opened: {case_data.get('created_at', 'Unknown')}

INTELLIGENCE FINDINGS:
{intel_summary}

Write the SAR narrative with these sections:
1. REASON FOR SUSPICION — why this activity is suspicious
2. SUBJECT DETAILS — who is involved
3. NATURE OF SUSPICIOUS ACTIVITY — what happened
4. INTELLIGENCE SUMMARY — corroborating intelligence findings
5. ACTION TAKEN — what the reporting firm has done
6. CONSENT REQUEST — whether consent is sought to proceed

Keep the total narrative under 600 words. Use UK English. Do not include section headers with numbers — use bold section names only."""

    narrative, error = _call_claude(prompt, max_tokens=900)
    if error:
        return {'success': False, 'error': error}

    # Generate a one-line alert summary too
    summary_prompt = f"""Summarise this SAR case in exactly one sentence for an alert log (max 25 words):
Subject: {case_data.get('subject_name','Unknown')}, Fraud type: {case_data.get('fraud_type','')}, Amount: {amount_str}, Risk: {case_data.get('risk_level','')}"""

    summary, _ = _call_claude(summary_prompt, max_tokens=60)

    return {
        'success': True,
        'narrative': narrative,
        'summary': summary or '',
        'case_ref': case_data.get('case_ref'),
        'generated_at': datetime.utcnow().isoformat(),
        'word_count': len(narrative.split()) if narrative else 0
    }
