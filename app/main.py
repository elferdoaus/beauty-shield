from fastapi import FastAPI
from pydantic import BaseModel

from app.scanner import scan_url
from app.risk import calculate_risk


app = FastAPI()


class ScanRequest(BaseModel):
    url: str


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "BeautyShield"
    }


@app.post("/scan")
def scan(request: ScanRequest):
    issues = scan_url(request.url)

    score, level = calculate_risk(issues)

    return {
        "target": request.url,
        "risk_score": score,
        "risk_level": level,
        "issues": issues
    }