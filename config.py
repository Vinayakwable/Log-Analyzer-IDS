import os
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Load .env automatically
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

class Config:
    # ── MySQL ─────────────────────────────────────────────────────
    MYSQL_HOST     = os.environ.get('MYSQL_HOST',     'localhost')
    MYSQL_PORT     = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER     = os.environ.get('MYSQL_USER',     'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB       = os.environ.get('MYSQL_DB',       'cyberwatch')

    # quote_plus encodes special chars like @ # % so they don't break the URL
    # shreyas@123 becomes shreyas%40123 in the connection string
    _safe_password = quote_plus(MYSQL_PASSWORD)

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{MYSQL_USER}:{_safe_password}"
        f"@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── JWT ───────────────────────────────────────────────────────
    JWT_SECRET_KEY                   = os.environ.get('JWT_SECRET_KEY', 'change_this_in_production')
    JWT_ACCESS_TOKEN_EXPIRES_MINUTES = 60
    JWT_REFRESH_TOKEN_EXPIRES_DAYS   = 7

    # ── File Upload ───────────────────────────────────────────────
    UPLOAD_FOLDER      = os.path.join(os.path.dirname(__file__), 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'log', 'txt', 'csv', 'json'}

    # ── CORS ──────────────────────────────────────────────────────
    CORS_ORIGINS = [
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'http://[::1]:5500',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://[::1]:3000',
        'null',
    ]
