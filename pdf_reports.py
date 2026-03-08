from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

BRAND_BLUE = colors.HexColor('#0f3460')
BRAND_ACCENT = colors.HexColor('#2563eb')
LIGHT_BLUE = colors.HexColor('#eff6ff')
BORDER_COLOR = colors.HexColor('#e2e8f0')
TEXT_DARK = colors.HexColor('#0f172a')
TEXT_MID = colors.HexColor('#475569')
TEXT_LIGHT = colors.HexColor('#94a3b8')
RED = colors.HexColor('#dc2626')
ORANGE = colors.HexColor('#d97706')
GREEN = colors.HexColor('#16a34a')

def severity_color(sev):
    return {'critical': RED, 'high': ORANGE, 'medium': colors.HexColor('#d97706'), 'low': GREEN}.get(sev, TEXT_MID)

def generate_fraud_report(org, cases, report_type, period_start, period_end, output_path):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=15*mm, bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', fontSize=18, fontName='Helvetica-Bold',
        textColor=colors.white, alignment=TA_LEFT, spaceAfter=2)
    subtitle_style = ParagraphStyle('Subtitle', fontSize=10, fontName='Helvetica',
        textColor=colors.HexColor('#93c5fd'), alignment=TA_LEFT)
    h2_style = ParagraphStyle('H2', fontSize=12, fontName='Helvetica-Bold',
        textColor=BRAND_BLUE, spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle('Body', fontSize=9, fontName='Helvetica',
        textColor=TEXT_MID, spaceAfter=4, leading=14)
    label_style = ParagraphStyle('Label', fontSize=7.5, fontName='Helvetica-Bold',
        textColor=TEXT_LIGHT, spaceAfter=2, leading=10)
    value_style = ParagraphStyle('Value', fontSize=9.5, fontName='Helvetica-Bold',
        textColor=TEXT_DARK, spaceAfter=2)

    story = []

    # Header band
    header_data = [[
        Paragraph(f'🛡 DefenceIQ', title_style),
        Paragraph(f'CONFIDENTIAL', ParagraphStyle('conf', fontSize=8,
            fontName='Helvetica-Bold', textColor=colors.HexColor('#fca5a5'),
            alignment=TA_RIGHT))
    ]]
    header_table = Table(header_data, colWidths=[120*mm, 50*mm])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BRAND_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (0,-1), 8),
        ('RIGHTPADDING', (-1,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(header_table)

    # Report title band
    title_data = [[
        Paragraph(report_type, ParagraphStyle('rt', fontSize=14,
            fontName='Helvetica-Bold', textColor=BRAND_BLUE)),
        Paragraph(f'Generated: {datetime.utcnow().strftime("%d %B %Y %H:%M UTC")}',
            ParagraphStyle('gen', fontSize=8, fontName='Helvetica',
            textColor=TEXT_LIGHT, alignment=TA_RIGHT))
    ]]
    title_table = Table(title_data, colWidths=[120*mm, 50*mm])
    title_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BLUE),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (0,-1), 8),
        ('RIGHTPADDING', (-1,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LINEBELOW', (0,0), (-1,-1), 1, BORDER_COLOR),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 6*mm))

    # Org & period info
    info_data = [
        [Paragraph('ORGANISATION', label_style), Paragraph('REPORTING PERIOD', label_style),
         Paragraph('SECTOR', label_style), Paragraph('COUNTRY', label_style)],
        [Paragraph(org.name, value_style),
         Paragraph(f'{period_start.strftime("%d %b %Y")} — {period_end.strftime("%d %b %Y")}', value_style),
         Paragraph(org.sector or '—', value_style),
         Paragraph(org.country or '—', value_style)],
    ]
    info_table = Table(info_data, colWidths=[45*mm, 50*mm, 35*mm, 40*mm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.white),
        ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 6*mm))

    # Summary stats
    total = len(cases)
    critical = sum(1 for c in cases if c.severity == 'critical')
    high = sum(1 for c in cases if c.severity == 'high')
    resolved = sum(1 for c in cases if c.status == 'resolved')
    total_loss = sum(float(c.amount_lost or 0) for c in cases)
    avg_score = sum(float(c.ai_score or 0) for c in cases if c.ai_score) / max(1, sum(1 for c in cases if c.ai_score))

    story.append(Paragraph('EXECUTIVE SUMMARY', h2_style))
    story.append(HRFlowable(width='100%', thickness=1, color=BRAND_ACCENT, spaceAfter=6))

    stats_data = [
        [Paragraph('TOTAL CASES', label_style), Paragraph('CRITICAL', label_style),
         Paragraph('HIGH SEVERITY', label_style), Paragraph('RESOLVED', label_style),
         Paragraph('TOTAL LOSS', label_style), Paragraph('AVG AI SCORE', label_style)],
        [Paragraph(str(total), ParagraphStyle('sv', fontSize=18, fontName='Helvetica-Bold', textColor=BRAND_ACCENT)),
         Paragraph(str(critical), ParagraphStyle('sv', fontSize=18, fontName='Helvetica-Bold', textColor=RED)),
         Paragraph(str(high), ParagraphStyle('sv', fontSize=18, fontName='Helvetica-Bold', textColor=ORANGE)),
         Paragraph(str(resolved), ParagraphStyle('sv', fontSize=18, fontName='Helvetica-Bold', textColor=GREEN)),
         Paragraph(f'NGN {total_loss:,.0f}', ParagraphStyle('sv', fontSize=11, fontName='Helvetica-Bold', textColor=TEXT_DARK)),
         Paragraph(f'{avg_score:.0f}/100', ParagraphStyle('sv', fontSize=18, fontName='Helvetica-Bold', textColor=BRAND_BLUE))],
    ]
    stats_table = Table(stats_data, colWidths=[28*mm, 28*mm, 28*mm, 28*mm, 38*mm, 28*mm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ('BACKGROUND', (0,1), (-1,1), colors.white),
        ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 6*mm))

    # Narrative summary
    story.append(Paragraph('REPORTING NARRATIVE', h2_style))
    story.append(HRFlowable(width='100%', thickness=1, color=BRAND_ACCENT, spaceAfter=6))
    narrative = (
        f"During the reporting period from {period_start.strftime('%d %B %Y')} to {period_end.strftime('%d %B %Y')}, "
        f"{org.name} recorded a total of {total} fraud case(s) on the DefenceIQ platform. "
        f"Of these, {critical} were classified as Critical severity and {high} as High severity, "
        f"representing the most urgent threats requiring immediate regulatory attention. "
        f"A total of {resolved} case(s) were successfully resolved within the reporting period. "
        f"The estimated total financial exposure across all reported cases amounts to NGN {total_loss:,.2f}. "
        f"AI-assisted risk scoring, powered by the DefenceIQ intelligence engine, returned an average "
        f"risk score of {avg_score:.0f} out of 100 across scored cases. "
        f"This report has been generated in compliance with applicable regulatory reporting obligations."
    )
    story.append(Paragraph(narrative, body_style))
    story.append(Spacer(1, 6*mm))

    # Case table
    if cases:
        story.append(Paragraph('FRAUD CASE REGISTER', h2_style))
        story.append(HRFlowable(width='100%', thickness=1, color=BRAND_ACCENT, spaceAfter=6))

        table_data = [[
            Paragraph('Case Ref', label_style),
            Paragraph('Fraud Type', label_style),
            Paragraph('Indicator', label_style),
            Paragraph('Severity', label_style),
            Paragraph('Status', label_style),
            Paragraph('AI Score', label_style),
            Paragraph('Amount (NGN)', label_style),
            Paragraph('Date', label_style),
        ]]
        for case in cases:
            sev_color = severity_color(case.severity)
            table_data.append([
                Paragraph(case.case_ref, ParagraphStyle('mono', fontSize=7.5,
                    fontName='Helvetica', textColor=BRAND_ACCENT)),
                Paragraph(case.fraud_type or '—', ParagraphStyle('td', fontSize=8,
                    fontName='Helvetica', textColor=TEXT_DARK)),
                Paragraph(f'{case.indicator_type}: {(case.indicator_value or "")[:15]}',
                    ParagraphStyle('td', fontSize=7.5, fontName='Helvetica', textColor=TEXT_MID)),
                Paragraph(case.severity.upper(), ParagraphStyle('sev', fontSize=7.5,
                    fontName='Helvetica-Bold', textColor=sev_color)),
                Paragraph(case.status.replace('_',' ').title(), ParagraphStyle('td', fontSize=8,
                    fontName='Helvetica', textColor=TEXT_MID)),
                Paragraph(f'{int(case.ai_score)}/100' if case.ai_score else '—',
                    ParagraphStyle('td', fontSize=8, fontName='Helvetica-Bold', textColor=BRAND_BLUE)),
                Paragraph(f'{float(case.amount_lost):,.0f}' if case.amount_lost else '—',
                    ParagraphStyle('td', fontSize=8, fontName='Helvetica', textColor=TEXT_DARK)),
                Paragraph(case.created_at.strftime('%d %b %Y'),
                    ParagraphStyle('td', fontSize=7.5, fontName='Helvetica', textColor=TEXT_MID)),
            ])

        col_widths = [28*mm, 28*mm, 30*mm, 18*mm, 20*mm, 16*mm, 22*mm, 18*mm]
        case_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BRAND_BLUE),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 7.5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(case_table)

    story.append(Spacer(1, 8*mm))

    # Footer
    footer_data = [[
        Paragraph('This report is generated by DefenceIQ — AI Fraud Intelligence Platform by Fa3Tech Limited.',
            ParagraphStyle('foot', fontSize=7, fontName='Helvetica', textColor=TEXT_LIGHT)),
        Paragraph(f'CONFIDENTIAL — {datetime.utcnow().strftime("%d %B %Y")}',
            ParagraphStyle('foot2', fontSize=7, fontName='Helvetica-Bold',
            textColor=TEXT_LIGHT, alignment=TA_RIGHT))
    ]]
    footer_table = Table(footer_data, colWidths=[110*mm, 60*mm])
    footer_table.setStyle(TableStyle([
        ('LINEABOVE', (0,0), (-1,0), 1, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (0,-1), 0),
        ('RIGHTPADDING', (-1,0), (-1,-1), 0),
    ]))
    story.append(footer_table)

    doc.build(story)
    return output_path
