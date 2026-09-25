"""
Lab 11 — Configuration & API Key Setup
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env from repo root or src parent
repo_root = Path(__file__).resolve().parents[2]
env_path = repo_root / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()


def setup_api_key():
    """Load Google API key from environment or prompt."""
    if "GOOGLE_API_KEY" not in os.environ or not os.environ["GOOGLE_API_KEY"]:
        if sys.stdin and sys.stdin.isatty():
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
        else:
            os.environ["GOOGLE_API_KEY"] = "AIzaSyDdKUP0CjTu_dp8JU7SAhBYrbgp4DFMuuM"
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
