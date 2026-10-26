"""Settings shared by the CIRA agent."""
import os
from pathlib import Path

HOME = Path.home()
DATA_DIR = Path(os.environ.get("CIRA_HOME", HOME / ".cira"))
QUARANTINE_DIR = DATA_DIR / "quarantine"
ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "models"
FRONTEND_DIR = ROOT / "frontend"
PORT = int(os.environ.get("CIRA_PORT", "8765"))

# Scan limits keep a quick scan quick.
MAX_FILES = 5000
SAMPLE_BYTES = 256 * 1024          # bytes read per file for entropy and magic bytes
MAX_HASH_BYTES = 100 * 1024 * 1024  # files larger than this are not hashed
MAX_PE_BYTES = 50 * 1024 * 1024     # files larger than this are not parsed as programs

# Risk levels on the 0-100 score.
HIGH_SCORE = 70
MEDIUM_SCORE = 40


def level_for(score: float) -> str:
    if score >= HIGH_SCORE:
        return "High"
    if score >= MEDIUM_SCORE:
        return "Medium"
    return "Low"
