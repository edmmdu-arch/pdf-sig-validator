"""
trust_manager.py
-----------------
Manages the certificates in backend/trust_anchors/ - the set of
signers/roots Attestor treats as trusted.

Adding a certificate here is the equivalent of clicking "Add to
Trusted Certificates" in Adobe Reader: it's a deliberate decision by
whoever runs this server to vouch for a specific certificate, not an
automatic or blanket trust grant. It does not, and must not, cause a
tampered document to validate - the intact/hash check is completely
independent of trust and is never bypassed.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Any

from pyhanko.pdf_utils.reader import PdfFileReader
from asn1crypto import x509 as asn1_x509

TRUST_ANCHORS_DIR = Path(__file__).parent / "trust_anchors"
TRUST_ANCHORS_DIR.mkdir(exist_ok=True)


def list_trusted_certs() -> list[dict[str, Any]]:
    certs = []
    for cert_path in sorted(TRUST_ANCHORS_DIR.glob("*")):
        if cert_path.suffix.lower() not in (".pem", ".cer", ".crt", ".der"):
            continue
        try:
            raw = cert_path.read_bytes()
            cert = _parse_cert_bytes(raw)
            certs.append(
                {
                    "filename": cert_path.name,
                    "subject": cert.subject.human_friendly,
                    "issuer": cert.issuer.human_friendly,
                    "serial_number": str(cert.serial_number),
                    "not_valid_after": str(cert["tbs_certificate"]["validity"]["not_after"].native),
                }
            )
        except Exception as exc:  # noqa: BLE001
            certs.append({"filename": cert_path.name, "error": str(exc)})
    return certs


def remove_trusted_cert(filename: str) -> bool:
    # Prevent path traversal - only allow bare filenames within trust_anchors
    safe_name = Path(filename).name
    target = TRUST_ANCHORS_DIR / safe_name
    if not target.exists() or target.parent != TRUST_ANCHORS_DIR:
        return False
    target.unlink()
    return True


def trust_certificate_from_pdf(pdf_bytes: bytes, signature_index: int = 0) -> dict[str, Any]:
    """
    Extracts the signing certificate from the Nth embedded signature
    in the given PDF and writes it into trust_anchors/ as a PEM file.
    Returns metadata about what was trusted.
    """
    reader = PdfFileReader(io.BytesIO(pdf_bytes))
    embedded_sigs = list(reader.embedded_signatures)

    if not embedded_sigs:
        raise ValueError("No embedded signatures found in this PDF - nothing to trust.")
    if signature_index >= len(embedded_sigs):
        raise ValueError(
            f"PDF only has {len(embedded_sigs)} signature(s); "
            f"index {signature_index} is out of range."
        )

    sig = embedded_sigs[signature_index]
    signer_cert = sig.signer_cert
    if signer_cert is None:
        raise ValueError("Could not extract a signer certificate from this signature.")

    pem_bytes = _cert_to_pem(signer_cert)

    # Name the file after a hash of the cert so re-trusting the same
    # cert twice doesn't create duplicates, and the filename is safe.
    fingerprint = hashlib.sha256(signer_cert.dump()).hexdigest()[:16]
    filename = f"trusted_{fingerprint}.pem"
    (TRUST_ANCHORS_DIR / filename).write_bytes(pem_bytes)

    return {
        "trusted": True,
        "filename": filename,
        "subject": signer_cert.subject.human_friendly,
        "issuer": signer_cert.issuer.human_friendly,
        "serial_number": str(signer_cert.serial_number),
        "note": (
            "This certificate has been added to the trust store. "
            "PDFs signed with this exact certificate will now validate "
            "as trusted. This does not affect documents signed by "
            "other certificates, and does not override tampering checks."
        ),
    }


def _parse_cert_bytes(raw: bytes) -> asn1_x509.Certificate:
    if raw.strip().startswith(b"-----BEGIN"):
        from asn1crypto import pem

        _, _, der = pem.unarmor(raw)
        return asn1_x509.Certificate.load(der)
    return asn1_x509.Certificate.load(raw)


def _cert_to_pem(cert: asn1_x509.Certificate) -> bytes:
    from asn1crypto import pem

    return pem.armor("CERTIFICATE", cert.dump())
