import os
import requests
import sqlite3
import datetime
from flask import Flask, redirect, url_for, session, request, jsonify, g
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24) # Used for session management (e.g., storing OAuth state)
app.permanent_session_lifetime = timedelta(minutes=60) # Session active for 60 minutes

# --- Discord OAuth2 Configuration ---
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "http://127.0.0.1:5000/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL")
# Make sure this REDIRECT_URI matches the one you set in your Discord application settings
# It should point to the /callback endpoint of your Flask app
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "http://127.0.0.1:5000/callback")

# --- Database Configuration ---
DATABASE = 'database.db'

DEPARTMENT_IDS = {
    'military-police',
    'admin-affairs',
    'sector-command',
    'recruitment-affairs',
    'officer-affairs',
    'senior-officer-affairs'
}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    try:
        with app.app_context():
            db = get_db()
            if os.path.exists('schema.sql'):
                with app.open_resource('schema.sql', mode='r') as f:
                    db.cursor().executescript(f.read())
                db.commit()
            else:
                app.logger.warning("schema.sql not found. Skipping database initialization.")
            ensure_core_tables()
    except Exception as e:
        app.logger.error(f"Error initializing database: {e}")

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# --- Allowed Discord User IDs (By Department) ---
# Hardcoded in the file as requested by the user for easy management
ALLOWED_DEPARTMENT_MEMBERS = {
    'SHORTA_ASKARYA': ["1350227902888808625", "1277659394305163310", "1322876094742790185"],
    'SHOON_EDARYA': ["1350227902888808625", "1277659394305163310", "1322876094742790185"],
    'KEYADAT_AL_SECTOR': ["1350227902888808625", "1277659394305163310", "1322876094742790185"],
    'SHOON_TAJNEED': ["1350227902888808625", "1277659394305163310", "1322876094742790185"],
    'SHOON_DOBAT': ["1350227902888808625", "1277659394305163310", "1322876094742790185"],
    'SHOON_KEBAR_DOBAT': ["1277659394305163310", "1322876094742790185"]
}

# Discord API Endpoints
DISCORD_API_BASE_URL = "https://discord.com/api/v10"
AUTHORIZATION_BASE_URL = "https://discord.com/oauth2/authorize"
TOKEN_URL = f"{DISCORD_API_BASE_URL}/oauth2/token"
USER_PROFILE_URL = f"{DISCORD_API_BASE_URL}/users/@me"

# --- Flask Routes ---

@app.route("/")
def index():
    return "Backend is running. Navigate to /login/discord to start the OAuth flow."

@app.route("/login/discord")
def login_discord():
    # Store a random state in the session to prevent CSRF attacks
    session["oauth_state"] = os.urandom(16).hex()
    
    # Store department_id in session for later verification in /callback
    department_id = request.args.get("department_id", "military-police")
    session["department_id"] = department_id

    # We only need the 'identify' scope to get the user's Discord ID
    scopes = "identify"

    # Construct the Discord authorization URL
    discord_auth_url = (
        f"{AUTHORIZATION_BASE_URL}?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={DISCORD_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={scopes.replace(' ', '%20')}&"
        f"state={session['oauth_state']}"
    )
    return redirect(discord_auth_url)

@app.route("/callback")
def callback():
    # Verify the state parameter to prevent CSRF
    if request.args.get("state") != session.get("oauth_state"):
        app.logger.warning("CSRF attack detected or invalid state parameter.")
        return jsonify({"message": "Invalid state parameter."}), 400

    code = request.args.get("code")
    if not code:
        return jsonify({"message": "Authorization code not provided."}), 400

    # Exchange the authorization code for an access token
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "scope": "identify", # Match the scope used in /login/discord
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(TOKEN_URL, data=data, headers=headers)
    token_response.raise_for_status()
    token_json = token_response.json()
    
    access_token = token_json["access_token"]

    # Use the access token to get user's profile information
    user_headers = {"Authorization": f"Bearer {access_token}"}
    user_profile_response = requests.get(USER_PROFILE_URL, headers=user_headers)
    user_profile_response.raise_for_status()
    user_profile = user_profile_response.json()
    
    user_id = user_profile["id"]
    username = user_profile["username"]

    department_id = session.get("department_id", "military-police")

    # Check if the user's ID is in the allowed list for the specific department
    if is_department_member(user_id, department_id):
        session["is_verified"] = True
        session["user_discord_id"] = user_id
        session["username"] = username
        # Redirect back to the frontend with success indicators
        return redirect(f"{FRONTEND_URL}?verified=true&department_id={department_id}")
    else:
        session["is_verified"] = False
        # Redirect back to the frontend with failure indicators
        return redirect(f"{FRONTEND_URL}?verified=false&department_id={department_id}&reason=id_not_allowed")

def is_department_member(discord_id, department_id):
    # Map department IDs to the legacy ENV names for consistency
    env_var_map = {
        'military-police': 'SHORTA_ASKARYA',
        'admin-affairs': 'SHOON_EDARYA',
        'sector-command': 'KEYADAT_AL_SECTOR',
        'recruitment-affairs': 'SHOON_TAJNEED',
        'officer-affairs': 'SHOON_DOBAT',
        'senior-officer-affairs': 'SHOON_KEBAR_DOBAT'
    }
    
    env_name = env_var_map.get(department_id)
    if not env_name:
        return False

    # Check if the user's ID is in the hardcoded list for the specific department
    allowed_ids = ALLOWED_DEPARTMENT_MEMBERS.get(env_name, [])
    if discord_id in allowed_ids:
        return True

    # Fallback to database if needed, though hardcoded list is now preferred
    table_map = {
        'military-police': 'military_police_members',
        'admin-affairs': 'admin_affairs_members',
        'sector-command': 'sector_command_members',
        'recruitment-affairs': 'recruitment_affairs_members',
        'officer-affairs': 'officer_affairs_members',
        'senior-officer-affairs': 'senior_officer_affairs_members'
    }
    
    table_name = table_map.get(department_id)
    if not table_name:
        return False
        
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(f"SELECT 1 FROM {table_name} WHERE discord_id = ?", (discord_id,))
        return cursor.fetchone() is not None
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        return False

def ensure_core_tables():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allowed_department_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            user_name TEXT,
            UNIQUE(department_id, user_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hwid_locks (
            user_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            locked_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
    """)
    cursor.execute("PRAGMA table_info(allowed_department_ids)")
    existing_columns = {row["name"] for row in cursor.fetchall()}
    if "user_name" not in existing_columns:
        cursor.execute("ALTER TABLE allowed_department_ids ADD COLUMN user_name TEXT")
    db.commit()

init_db()

def normalize_user_id(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value.isdigit():
        return None
    return value

def normalize_department_id(value):
    if value is None:
        return None
    value = str(value).strip()
    if value not in DEPARTMENT_IDS:
        return None
    return value

def normalize_device_id(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value or len(value) > 200:
        return None
    return value

def normalize_user_name(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if len(value) > 80:
        value = value[:80]
    return value

def is_allowed_in_department_db(user_id, department_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT 1 FROM allowed_department_ids WHERE department_id = ? AND user_id = ?",
        (department_id, user_id),
    )
    return cursor.fetchone() is not None

def check_or_create_hwid_lock(user_id, device_id):
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT device_id FROM hwid_locks WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row is None:
        cursor.execute(
            "INSERT INTO hwid_locks (user_id, device_id, locked_at, last_seen_at) VALUES (?, ?, ?, ?)",
            (user_id, device_id, now, now),
        )
        db.commit()
        return True, "locked"
    if row["device_id"] != device_id:
        return False, "mismatch"
    cursor.execute(
        "UPDATE hwid_locks SET last_seen_at = ? WHERE user_id = ?",
        (now, user_id),
    )
    db.commit()
    return True, "ok"

def require_sector_admin(admin_user_id, admin_device_id):
    if not is_allowed_in_department_db(admin_user_id, "sector-command"):
        return False, "not_allowed"
    ok, lock_status = check_or_create_hwid_lock(admin_user_id, admin_device_id)
    if not ok:
        return False, "hwid_mismatch"
    return True, lock_status

@app.route("/api/verify", methods=["POST", "OPTIONS"])
def api_verify():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    department_id = normalize_department_id(payload.get("department_id"))
    user_id = normalize_user_id(payload.get("user_id"))
    device_id = normalize_device_id(payload.get("device_id"))
    if not department_id or not user_id or not device_id:
        return jsonify({"status": "failed", "reason": "invalid_request"}), 400
    if not is_allowed_in_department_db(user_id, department_id):
        return jsonify({"status": "failed", "reason": "id_not_allowed"}), 403
    ok, lock_status = check_or_create_hwid_lock(user_id, device_id)
    if not ok:
        return jsonify({"status": "failed", "reason": "hwid_mismatch"}), 403
    return jsonify({"status": "success", "lock": lock_status, "user_id": user_id, "department_id": department_id})

@app.route("/api/ids/list", methods=["GET", "OPTIONS"])
def api_ids_list():
    if request.method == "OPTIONS":
        return ("", 204)
    department_id = normalize_department_id(request.args.get("department_id"))
    admin_user_id = normalize_user_id(request.args.get("admin_user_id"))
    admin_device_id = normalize_device_id(request.args.get("admin_device_id"))
    if not department_id or not admin_user_id or not admin_device_id:
        return jsonify({"status": "failed", "reason": "invalid_request"}), 400
    ok, reason = require_sector_admin(admin_user_id, admin_device_id)
    if not ok:
        return jsonify({"status": "failed", "reason": reason}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT user_id, user_name FROM allowed_department_ids WHERE department_id = ? ORDER BY user_id ASC",
        (department_id,),
    )
    rows = cursor.fetchall()
    items = [{"user_id": row["user_id"], "user_name": row["user_name"]} for row in rows]
    ids = [row["user_id"] for row in rows]
    return jsonify({"status": "success", "department_id": department_id, "ids": ids, "items": items})

@app.route("/api/ids/add", methods=["POST", "OPTIONS"])
def api_ids_add():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    department_id = normalize_department_id(payload.get("department_id"))
    user_id = normalize_user_id(payload.get("user_id"))
    user_name = normalize_user_name(payload.get("user_name"))
    admin_user_id = normalize_user_id(payload.get("admin_user_id"))
    admin_device_id = normalize_device_id(payload.get("admin_device_id"))
    if not department_id or not user_id or not admin_user_id or not admin_device_id:
        return jsonify({"status": "failed", "reason": "invalid_request"}), 400
    ok, reason = require_sector_admin(admin_user_id, admin_device_id)
    if not ok:
        return jsonify({"status": "failed", "reason": reason}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO allowed_department_ids (department_id, user_id, user_name)
        VALUES (?, ?, ?)
        ON CONFLICT(department_id, user_id) DO UPDATE SET
            user_name = excluded.user_name
    """, (department_id, user_id, user_name))
    db.commit()
    return jsonify({"status": "success", "department_id": department_id, "user_id": user_id, "user_name": user_name})

@app.route("/api/ids/remove", methods=["POST", "OPTIONS"])
def api_ids_remove():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    department_id = normalize_department_id(payload.get("department_id"))
    user_id = normalize_user_id(payload.get("user_id"))
    admin_user_id = normalize_user_id(payload.get("admin_user_id"))
    admin_device_id = normalize_device_id(payload.get("admin_device_id"))
    if not department_id or not user_id or not admin_user_id or not admin_device_id:
        return jsonify({"status": "failed", "reason": "invalid_request"}), 400
    ok, reason = require_sector_admin(admin_user_id, admin_device_id)
    if not ok:
        return jsonify({"status": "failed", "reason": reason}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "DELETE FROM allowed_department_ids WHERE department_id = ? AND user_id = ?",
        (department_id, user_id),
    )
    db.commit()
    return jsonify({"status": "success", "department_id": department_id, "user_id": user_id})

@app.route("/api/hwid/reset", methods=["POST", "OPTIONS"])
def api_hwid_reset():
    if request.method == "OPTIONS":
        return ("", 204)
    payload = request.get_json(silent=True) or {}
    user_id = normalize_user_id(payload.get("user_id"))
    admin_user_id = normalize_user_id(payload.get("admin_user_id"))
    admin_device_id = normalize_device_id(payload.get("admin_device_id"))
    if not user_id or not admin_user_id or not admin_device_id:
        return jsonify({"status": "failed", "reason": "invalid_request"}), 400
    ok, reason = require_sector_admin(admin_user_id, admin_device_id)
    if not ok:
        return jsonify({"status": "failed", "reason": reason}), 403
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM hwid_locks WHERE user_id = ?", (user_id,))
    db.commit()
    return jsonify({"status": "success", "user_id": user_id, "removed": cursor.rowcount})

@app.route("/check_status")
def check_status():
    """Endpoint for frontend to check current login and ID verification status."""
    department_id = request.args.get("department_id")
    
    if session.get("is_verified") and session.get("department_id") == department_id:
        return jsonify({
            "status": "success",
            "message": f"Welcome, {session.get('username')}! Your ID is verified.",
            "user_id": session.get("user_discord_id")
        })
    elif "is_verified" in session: # User tried to login but failed or department mismatch
        if session.get("department_id") != department_id:
             return jsonify({"status": "failed", "message": "لم يتم التحقق من هويتك لهذا القسم."})
             
        reason = request.args.get("reason", "unknown")
        message = "فشل التحقق. لا تسوي كذا عشان تتجنب المحاسبة العسكرية."
        if reason == "id_not_allowed":
            message = "فشل التحقق. معرف ديسكورد الخاص بك غير موجود في قائمة المعرفات المسموح بها لهذا القسم."
        elif reason == "api_error" or reason == "server_error":
            message = "حدث خطأ أثناء التحقق. يرجى المحاولة مرة أخرى."
        return jsonify({"status": "failed", "message": message})
    else: # User has not attempted login yet
        return jsonify({"status": "not_logged_in", "message": "الرجاء تسجيل الدخول عبر ديسكورد للتحقق من الصلاحيات."})

@app.route("/logout")
def logout():
    session.pop("is_verified", None)
    session.pop("user_discord_id", None)
    session.pop("username", None)
    session.pop("department_id", None)
    session.pop("oauth_state", None)
    return redirect(FRONTEND_URL) # Redirect to frontend's home page

if __name__ == "__main__":
    # In a production environment, use a more robust WSGI server like Gunicorn or uWSGI
    # and serve over HTTPS. For local development, this is fine.
    app.run(debug=True, port=5000)
