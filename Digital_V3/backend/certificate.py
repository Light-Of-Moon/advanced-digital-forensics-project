"""PDF Certificate Generation for forensic evidence."""
import os
import sys
import io
import qrcode
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.config import config

logger = logging.getLogger(__name__)

def generate_certificate(evidence: dict, case: dict, investigator: dict) -> bytes:
    """Generate a professional PDF forensic integrity certificate."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('title', fontSize=18, fontName='Helvetica-Bold',
                                     alignment=TA_CENTER, textColor=colors.HexColor('#0d1b2a'),
                                     spaceAfter=6)
        subtitle_style = ParagraphStyle('subtitle', fontSize=12, fontName='Helvetica',
                                        alignment=TA_CENTER, textColor=colors.HexColor('#1565C0'),
                                        spaceAfter=12)
        heading_style = ParagraphStyle('heading', fontSize=11, fontName='Helvetica-Bold',
                                       textColor=colors.HexColor('#0d1b2a'), spaceBefore=10, spaceAfter=4)
        normal_style = ParagraphStyle('normal_c', fontSize=9, fontName='Helvetica',
                                      textColor=colors.HexColor('#2c2c2c'))

        story = []

        # Header
        story.append(Paragraph("DIGITAL FORENSIC INTEGRITY CERTIFICATE", title_style))
        story.append(Paragraph("Blockchain-Verified Evidence Authentication", subtitle_style))

        # Divider
        story.append(Table([['']], colWidths=[170*mm], style=TableStyle([
            ('LINEABOVE', (0,0), (-1,-1), 2, colors.HexColor('#1565C0'))
        ])))
        story.append(Spacer(1, 8*mm))

        # Evidence details table
        def row(label, value):
            return [Paragraph(f"<b>{label}</b>", normal_style),
                    Paragraph(str(value or 'N/A'), normal_style)]

        data = [
            row("Certificate ID:", f"CERT-{evidence.get('id', '?'):06d}"),
            row("Evidence Number:", evidence.get('evidence_number', 'N/A')),
            row("Case Number:", case.get('case_number', 'N/A')),
            row("Case Title:", case.get('title', 'N/A')),
            row("Original Filename:", evidence.get('original_filename', 'N/A')),
            row("File Size:", evidence.get('file_size_human', 'N/A')),
            row("SHA-256 Hash:", evidence.get('sha256_hash', 'N/A')),
            row("MD5 Hash:", evidence.get('md5_hash', 'N/A')),
            row("Evidence Type:", evidence.get('evidence_type', 'N/A').upper()),
            row("Upload Date:", str(evidence.get('created_at', 'N/A'))[:19]),
            row("Blockchain TX:", evidence.get('blockchain_tx', 'N/A')),
            row("Blockchain Block:", str(evidence.get('blockchain_block', 'N/A'))),
            row("Verification Status:", evidence.get('status', 'N/A').upper()),
            row("Investigating Officer:", investigator.get('full_name', 'N/A')),
            row("Badge Number:", investigator.get('badge_number', 'N/A')),
            row("Department:", investigator.get('department', 'N/A')),
        ]

        table = Table(data, colWidths=[60*mm, 110*mm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e3f2fd')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0d1b2a')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#90caf9')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f5f9ff')]),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 8*mm))

        # QR Code
        qr_data = (
            f"Evidence: {evidence.get('evidence_number', 'N/A')}\n"
            f"Case: {case.get('case_number', 'N/A')}\n"
            f"SHA256: {evidence.get('sha256_hash', 'N/A')}\n"
            f"TX: {evidence.get('blockchain_tx', 'N/A')}\n"
            f"Status: {evidence.get('status', 'N/A').upper()}"
        )
        qr_img = qrcode.make(qr_data)
        qr_buf = io.BytesIO()
        qr_img.save(qr_buf, format='PNG')
        qr_buf.seek(0)

        qr_table = Table([[
            RLImage(qr_buf, width=35*mm, height=35*mm),
            Paragraph(
                "<b>Scan QR code to verify this certificate.</b><br/><br/>"
                "This document certifies that the above digital evidence has been cryptographically "
                "hashed and its integrity immutably recorded on the blockchain. Any modification "
                "to the original file will cause the SHA-256 hash to mismatch, indicating tampering.",
                ParagraphStyle('small', fontSize=8, fontName='Helvetica',
                               textColor=colors.HexColor('#2c2c2c'))
            )
        ]], colWidths=[40*mm, 130*mm])
        qr_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#1565C0')),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#e8f5e9')),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(qr_table)
        story.append(Spacer(1, 8*mm))

        # Footer
        story.append(Table([['']], colWidths=[170*mm], style=TableStyle([
            ('LINEABOVE', (0,0), (-1,-1), 1, colors.HexColor('#1565C0'))
        ])))
        story.append(Paragraph(
            "⚠ This certificate is generated by the Blockchain-Based Digital Evidence Verification System. "
            "Unauthorized modification is a criminal offense.",
            ParagraphStyle('footer', fontSize=7, fontName='Helvetica',
                           alignment=TA_CENTER, textColor=colors.grey)
        ))

        doc.build(story)
        return buffer.getvalue()

    except Exception as e:
        logger.error(f"Certificate generation error: {e}")
        raise
