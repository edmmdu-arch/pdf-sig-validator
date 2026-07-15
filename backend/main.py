"""
main.py
-------
FastAPI backend.

Endpoints:
  POST /api/validate
      multipart/form-data, field name "file" = the PDF to check.
      Returns JSON verdict (SignatureReport per embedded signature).

  POST /api/validate-and-stamp
      Same input. Returns the ORIGINAL pdf bytes + an appended
      validation-report page as a downloadable PDF
      (Content-Type: application/pdf).

Run locally:
  cd backend
  python -m venv venv && source venv/bin/activate
  pip install -r requirements.txt
  uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import io
from dataclasses import asdict

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from validator import validate_pdf
from report_stamper import append_validation_report

app = FastAPI(title="PDF Signature Validator")

# Allow the local dev frontend (adjust for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE_MB = 25


async def _read_and_check(file: UploadFile) -> bytes:
    if file.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a PDF.")
    data = await file.read()
    if len(data) > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File exceeds {MAX_FILE_SIZE_MB}MB limit.")
    if not data.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="File does not look like a valid PDF.")
    return data


@app.post("/api/validate")
async def api_validate(file: UploadFile = File(...)):
    data = await _read_and_check(file)
    try:
        result = validate_pdf(data, filename=file.filename or "uploaded.pdf")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Could not parse/validate PDF: {exc}") from exc

    return JSONResponse(
        {
            "filename": result.filename,
            "signature_count": result.signature_count,
            "overall_valid": result.overall_valid,
            "signatures": [asdict(s) for s in result.signatures],
        }
    )


@app.post("/api/validate-and-stamp")
async def api_validate_and_stamp(file: UploadFile = File(...)):
    data = await _read_and_check(file)
    try:
        result = validate_pdf(data, filename=file.filename or "uploaded.pdf")
        stamped = append_validation_report(data, result)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"Could not validate/stamp PDF: {exc}") from exc

    out_name = (file.filename or "document").rsplit(".", 1)[0] + "_validated.pdf"
    return StreamingResponse(
        io.BytesIO(stamped),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},
    )


@app.get("/api/health")
async def health():
    return {"status": "ok"}
