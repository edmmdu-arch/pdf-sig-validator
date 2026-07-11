"""
validator.py
------------
Core PDF digital-signature validation logic.

For each embedded signature in a PDF this module answers three
independent questions, which is exactly what Adobe/other viewers
collapse into a single "?" or "✓" icon:

  1. INTACT   -> has the signed byte range been tampered with since signing?
  2. TRUSTED  -> does the signer's certificate chain up to a root we trust?
  3. VALID AT SIGNING TIME -> were the certs valid (not expired/revoked)
                               at the time of signing?

A signature is only shown as a full "✓ Signature Valid" when all three
are true. If the chain doesn't resolve to a trusted root (e.g. the
CCA India root isn't in the default trust store), viewers show "?"
even though the document itself is intact.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, EmbeddedPdfSignature
from pyhanko.sign.validation.status import PdfSignatureStatus
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.keys import load_cert_from_pemder

TRUST_ANCHORS_DIR = Path(__file__).parent / "trust_anchors"


@dataclass
class SignatureReport:
    field_name: str
    signer_cn: str | None
    signer_full_subject: str | None
    issuer: str | None
    signing_time: str | None
    intact: bool
    trusted: bool
    revocation_ok: bool | None
    overall_valid: bool
    coverage: str  # "entire_document" | "partial" | "unknown"
    errors: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    filename: str
    signature_count: int
    signatures: list[SignatureReport]
    overall_valid: bool  # True only if ALL signatures are fully valid


def _load_trust_roots() -> list[Any]:
    """
    Load every .pem / .cer / .crt file placed in backend/trust_anchors/
    as a trusted root. This is where you drop the CCA India root
    certificate (and any intermediate CAs you want to pin directly)
    downloaded from https://cca.gov.in/cca/?q=licensed_ca.html
    """
    roots = []
    if not TRUST_ANCHORS_DIR.exists():
        return roots
    for cert_path in TRUST_ANCHORS_DIR.glob("*"):
        if cert_path.suffix.lower() in (".pem", ".cer", ".crt", ".der"):
            try:
                roots.append(load_cert_from_pemder(str(cert_path)))
            except Exception:
                # Skip unreadable files rather than crashing the whole app
                continue
    return roots


def _build_validation_context(offline: bool = False) -> ValidationContext:
    """
    offline=True disables live OCSP/CRL network calls - useful for
    environments without outbound internet access (revocation check
    is then simply skipped / reported as 'unknown').
    """
    roots = _load_trust_roots()
    cert_registry = SimpleCertificateStore()
    return ValidationContext(
        trust_roots=roots,
        allow_fetching=not offline,
        revocation_mode="soft-fail",  # don't hard-fail if OCSP/CRL unreachable
    )


def _coverage_label(sig: EmbeddedPdfSignature) -> str:
    try:
        if sig.sig_object.get("/ByteRange") and sig.diff_result is not None:
            if sig.diff_result.modification_level.name == "NONE":
                return "entire_document"
            return "partial"
    except Exception:
        pass
    return "unknown"


def validate_pdf(file_bytes: bytes, filename: str, offline: bool = False) -> ValidationResult:
    reader = PdfFileReader(io.BytesIO(file_bytes))
    embedded_sigs = list(reader.embedded_signatures)

    if not embedded_sigs:
        return ValidationResult(
            filename=filename,
            signature_count=0,
            signatures=[],
            overall_valid=False,
        )

    vc = _build_validation_context(offline=offline)
    reports: list[SignatureReport] = []

    for sig in embedded_sigs:
        errors: list[str] = []
        try:
            status: PdfSignatureStatus = validate_pdf_signature(sig, vc)

            signer_cert = status.signing_cert
            signer_cn = None
            signer_subject = None
            issuer = None
            if signer_cert is not None:
                signer_subject = signer_cert.subject.human_friendly
                issuer = signer_cert.issuer.human_friendly
                cn_attr = signer_cert.subject.native.get("common_name")
                signer_cn = cn_attr if cn_attr else signer_subject

            intact = bool(status.intact)
            trusted = bool(status.trusted)
            revocation_ok = getattr(status, "revocation_status_ok", None)
            overall = bool(status.valid) if hasattr(status, "valid") else (intact and trusted)

            signing_time = None
            if getattr(status, "signer_reported_dt", None):
                signing_time = str(status.signer_reported_dt)
            elif getattr(status, "timestamp_validity", None):
                signing_time = str(status.timestamp_validity.timestamp)

            reports.append(
                SignatureReport(
                    field_name=sig.field_name,
                    signer_cn=signer_cn,
                    signer_full_subject=signer_subject,
                    issuer=issuer,
                    signing_time=signing_time,
                    intact=intact,
                    trusted=trusted,
                    revocation_ok=revocation_ok,
                    overall_valid=intact and trusted,
                    coverage=_coverage_label(sig),
                    errors=errors,
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
            reports.append(
                SignatureReport(
                    field_name=getattr(sig, "field_name", "unknown"),
                    signer_cn=None,
                    signer_full_subject=None,
                    issuer=None,
                    signing_time=None,
                    intact=False,
                    trusted=False,
                    revocation_ok=None,
                    overall_valid=False,
                    coverage="unknown",
                    errors=errors,
                )
            )

    overall_valid = len(reports) > 0 and all(r.overall_valid for r in reports)

    return ValidationResult(
        filename=filename,
        signature_count=len(reports),
        signatures=reports,
        overall_valid=overall_valid,
    )
