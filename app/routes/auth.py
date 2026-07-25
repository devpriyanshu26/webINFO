import hashlib
import secrets
from flask import Blueprint, jsonify, request, current_app

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

API_KEYS = {}

def generate_api_key():
    return f"wi_{secrets.token_hex(24)}"

def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if not key or key not in API_KEYS:
            return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated

@auth_bp.route("/generate", methods=["POST"])
def create_key():
    key = generate_api_key()
    API_KEYS[key] = {"created": __import__("datetime").datetime.now().isoformat(), "active": True}
    return jsonify({"api_key": key, "message": "Store this key securely. It will not be shown again."})

@auth_bp.route("/validate", methods=["GET"])
@require_api_key
def validate_key():
    return jsonify({"valid": True, "key_info": API_KEYS.get(request.headers.get("X-API-Key"), {})})
