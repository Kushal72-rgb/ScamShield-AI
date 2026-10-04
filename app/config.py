import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()

# Primary model: gemini-3.8-flash
configured_model = os.getenv("GEMINI_MODEL", "").strip()
if not configured_model or configured_model == "gemini-2.5-flash":
    DEFAULT_MODEL = "gemini-3.8-flash"
else:
    DEFAULT_MODEL = configured_model

# Fallback models in case primary model experiences high demand or temporary outage
FALLBACK_MODELS = [
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-flash-latest",
]

# Optional PhishTank API key (https://phishtank.org/developer_info.php)
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()
