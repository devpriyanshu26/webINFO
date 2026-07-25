import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "webinfo-secret-key-change-in-production")
    API_RATE_LIMIT = int(os.environ.get("API_RATE_LIMIT", "60"))
    API_RATE_WINDOW = int(os.environ.get("API_RATE_WINDOW", "60"))
    CACHE_TTL = int(os.environ.get("CACHE_TTL", "300"))
    REDIS_URL = os.environ.get("REDIS_URL", "")
    MAX_SCAN_TIMEOUT = int(os.environ.get("MAX_SCAN_TIMEOUT", "120"))
    MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
    PASSIVE_MODE = True

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
