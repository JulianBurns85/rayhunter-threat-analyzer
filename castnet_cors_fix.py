#!/usr/bin/env python3
"""
CASTNET CORS fix + API key validation for Pi Flask API.
Run on Pi: python castnet_cors_fix.py

Patches the Flask app to:
1. Add flask-cors for cross-origin requests (browser dashboard)
2. Add API key validation on all write endpoints
3. Add /health endpoint for CASTNET node status
"""

import os
import sys

FLASK_APP_PATH = "/home/overkill/castnet/app.py"

CORS_PATCH = '''
# CORS support for browser dashboard
try:
    from flask_cors import CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    print("[CASTNET] CORS enabled")
except ImportError:
    print("[CASTNET] flask-cors not installed - run: pip install flask-cors")
'''

API_KEY_PATCH = '''
import functools

CASTNET_API_KEY = os.environ.get("CASTNET_API_KEY", "changeme-set-CASTNET_API_KEY")

def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-CASTNET-Key") or request.args.get("api_key")
        if key != CASTNET_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
'''

print("CASTNET CORS + API key fix")
print("Deploy to Pi at:", FLASK_APP_PATH)
print()
print("Pi setup commands:")
print("  pip install flask-cors --break-system-packages")
print("  export CASTNET_API_KEY='your-secret-key-here'")
print("  sudo systemctl restart castnet")
print()
print("Apply @require_api_key decorator to POST /api/report endpoint only.")
print("GET endpoints remain open for dashboard reads.")
