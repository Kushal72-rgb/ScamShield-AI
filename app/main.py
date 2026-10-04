import os
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import GEMINI_API_KEY
from app.models import AnalysisRequest, AnalysisResponse, ConversationAnalysisRequest
from app.analyzer import analyze_message, analyze_screenshot, analyze_conversation

app = FastAPI(
    title="ScamShield AI",
    description="AI-powered scam, impersonation, and phishing detection using Google Gemini.",
    version="1.0.0",
)

# Enable CORS for local development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend status and API key configuration."""
    return {
        "status": "online",
        "api_key_configured": bool(GEMINI_API_KEY),
    }


@app.post(
    "/api/analyze",
    response_model=AnalysisResponse,
    summary="Analyze suspicious message text",
)
def analyze(payload: AnalysisRequest):
    """Analyze a suspicious message text and return structured cybersecurity threat assessment.

    Automatically handles offline/degraded mode when Gemini API is unconfigured or experiencing quota limits.
    """
    try:
        result = analyze_message(payload.message)
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        err_msg = str(exc)
        status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if ("503" in err_msg or "high demand" in err_msg or "429" in err_msg or "quota" in err_msg.lower())
            else status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        raise HTTPException(
            status_code=status_code,
            detail=err_msg,
        )


@app.post(
    "/api/analyze-image",
    response_model=AnalysisResponse,
    summary="Analyze suspicious message screenshot",
)
async def analyze_image_endpoint(file: UploadFile = File(...)):
    """Analyze an uploaded screenshot image for scams, phishing, and visual social engineering."""
    if not GEMINI_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Gemini API key is not configured. "
                "Please create a .env file and set GEMINI_API_KEY=your_key."
            ),
        )

    allowed_mimes = ["image/png", "image/jpeg", "image/jpg", "image/webp"]
    content_type = file.content_type or "image/png"
    if content_type.lower() not in allowed_mimes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image format: {content_type}. Please upload a PNG, JPG, or WEBP image.",
        )

    # Read image strictly in-memory (never written to disk permanently)
    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    max_size = 10 * 1024 * 1024  # 10MB limit
    if len(image_bytes) > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds the 10MB limit.",
        )

    try:
        result = analyze_screenshot(image_bytes, mime_type=content_type)
        return result
    except Exception as exc:
        err_msg = str(exc)
        status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if ("503" in err_msg or "high demand" in err_msg or "429" in err_msg or "quota" in err_msg.lower())
            else status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        raise HTTPException(
            status_code=status_code,
            detail=err_msg,
        )


@app.post(
    "/api/analyze-conversation",
    response_model=AnalysisResponse,
    summary="Analyze multi-message conversation thread for cumulative scam patterns",
)
def analyze_conversation_endpoint(payload: ConversationAnalysisRequest):
    """Analyze a multi-message conversation sequence for cumulative grooming, urgency escalation, and fraud."""
    try:
        result = analyze_conversation(payload.messages)
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        err_msg = str(exc)
        status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if ("503" in err_msg or "high demand" in err_msg or "429" in err_msg or "quota" in err_msg.lower())
            else status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        raise HTTPException(
            status_code=status_code,
            detail=err_msg,
        )


# Mount static directory for frontend
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_index():
    """Serve the single-page frontend application."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "ScamShield AI API is running. Frontend index.html not found."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
