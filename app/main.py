from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from app.scanner import scan_url
from app.risk import calculate_risk


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

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