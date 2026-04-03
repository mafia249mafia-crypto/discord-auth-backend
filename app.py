import os
import requests
import sqlite3
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
    except Exception as e:
        app.logger.error(f"Error initializing database: {e}")

# Initialize the database
init_db()

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
