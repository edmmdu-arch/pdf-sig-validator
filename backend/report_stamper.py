"""
report_stamper.py
------------------
Appends a NEW, clearly-labeled validation report page to the end of the
original PDF, showing a big ✓ / ✗ plus signer + chain details.

Deliberately does NOT touch bytes inside the original signature's
ByteRange - doing so would either break the original signature's
integrity check or (worse) misleadingly forge a "valid" appearance
on a signature field that was never actually validated by the real
signer's software. This module only ADDS a page; the original signed
content is passed through unmodified.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas

from validator import ValidationResult

GREEN = HexColor("#1a7f37")
RED = HexColor("#cf222e")
GRAY = HexColor("#57606a")
DARK = HexColor("#1f2328")


def _build_report_page(result: ValidationResult) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    margin = 20 * mm
    y = height - margin

    # Header
    c.setFillColor(DARK)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, y, "PDF Signature Validation Report")
    y -= 8 * mm

    c.setFont("Helvetica", 9)
    c.setFillColor(GRAY)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    c.drawString(margin, y, f"Generated {ts}  ·  Source file: {result.filename}")
    y -= 12 * mm

    # Overall verdict badge
    verdict_color = GREEN if result.overall_valid else RED
    verdict_symbol = "\u2713" if result.overall_valid else "\u2717"
    verdict_text = "SIGNATURE VALID" if result.overall_valid else "SIGNATURE NOT VALID / NOT TRUSTED"

    c.setFillColor(verdict_color)
    c.setFont("Helvetica-Bold", 40)
    c.drawString(margin, y - 12 * mm, verdict_symbol)

    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin + 18 * mm, y - 6 * mm, verdict_text)
    y -= 22 * mm

    if result.signature_count == 0:
        c.setFillColor(DARK)
        c.setFont("Helvetica", 11)
        c.drawString(margin, y, "No embedded digital signatures were found in this document.")
        c.showPage()
        c.save()
        buf.seek(0)
        return buf.read()

    # Per-signature details
    for idx, sig in enumerate(result.signatures, start=1):
        if y < margin + 40 * mm:
            c.showPage()
            y = height - margin

        c.setFillColor(DARK)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, f"Signature {idx}: field '{sig.field_name}'")
        y -= 7 * mm

        rows = [
            ("Signer", sig.signer_cn or "Unknown"),
            ("Issuer / CA", sig.issuer or "Unknown"),
            ("Signing time", sig.signing_time or "Not available"),
            ("Document intact (not tampered)", "Yes" if sig.intact else "No"),
            ("Certificate chain trusted", "Yes" if sig.trusted else "No — root not in trust anchor set"),
            (
                "Revocation status",
                "Not revoked" if sig.revocation_ok else ("Unknown / not checked" if sig.revocation_ok is None else "REVOKED"),
            ),
            ("Coverage", sig.coverage.replace("_", " ")),
        ]

        c.setFont("Helvetica", 10)
        for label, value in rows:
            c.setFillColor(GRAY)
            c.drawString(margin + 4 * mm, y, f"{label}:")
            c.setFillColor(DARK)
            c.drawString(margin + 65 * mm, y, str(value))
            y -= 6 * mm

        if sig.errors:
            c.setFillColor(RED)
            c.setFont("Helvetica-Oblique", 9)
            for err in sig.errors:
                c.drawString(margin + 4 * mm, y, f"Error: {err[:100]}")
                y -= 5 * mm

        y -= 8 * mm

    # Footer disclaimer
    c.setFillColor(GRAY)
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(
        margin,
        margin,
        "This report is an independent technical assessment appended by the validation service. "
        "It does not modify or replace the original signed content.",
    )

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()


def append_validation_report(original_pdf_bytes: bytes, result: ValidationResult) -> bytes:
    """
    Returns new PDF bytes = original pages (byte-for-byte from the
    original file, so the embedded signature ByteRange remains
    intact/checkable independently) + one or more appended report pages.
    """
    report_bytes = _build_report_page(result)

    original_reader = PdfReader(io.BytesIO(original_pdf_bytes))
    report_reader = PdfReader(io.BytesIO(report_bytes))

    writer = PdfWriter()
    for page in original_reader.pages:
        writer.add_page(page)
    for page in report_reader.pages:
        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    out.seek(0)
    return out.read()
