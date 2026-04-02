import os
import requests
from flask import Flask, redirect, url_for, session, request, jsonify
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

# Comma-separated string of Discord User IDs allowed to access the military police page
# Example: "123456789012345678,987654321098765432"
ALLOWED_DISCORD_USER_IDS_STR = os.getenv("ALLOWED_DISCORD_USER_IDS")
ALLOWED_DISCORD_USER_IDS = [id.strip() for id in ALLOWED_DISCORD_USER_IDS_STR.split(',')] if ALLOWED_DISCORD_USER_IDS_STR else []

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
        "scope": "identify guilds", # Must match the scope used in /login/discord
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

        # Check if the user's ID is in the allowed list
    if user_id in ALLOWED_DISCORD_USER_IDS:
        session["is_military_police"] = True
        session["user_discord_id"] = user_id
        session["username"] = username
        # Redirect back to the frontend with a success indicator
        return redirect(f"{FRONTEND_URL}?verified=true")
    else:
        session["is_military_police"] = False
        # Redirect back to the frontend with a failure indicator, as user ID is not in the allowed list
        return redirect(f"{FRONTEND_URL}?verified=false&reason=id_not_allowed")

@app.route("/check_status")
def check_status():
    """Endpoint for frontend to check current login and ID verification status."""
    if session.get("is_military_police"):
        return jsonify({
            "status": "success",
            "message": f"Welcome, {session.get('username')}! Your ID is verified.",
            "user_id": session.get("user_discord_id")
        })
    elif "is_military_police" in session: # User tried to login but failed ID check
        reason = request.args.get("reason", "unknown")
        message = "فشل التحقق. لا تسوي كذا عشان تتجنب المحاسبة العسكرية."
        if reason == "id_not_allowed":
            message = "فشل التحقق. معرف ديسكورد الخاص بك غير موجود في قائمة المعرفات المسموح بها."
        elif reason == "api_error" or reason == "server_error":
            message = "حدث خطأ أثناء التحقق. يرجى المحاولة مرة أخرى."
        return jsonify({"status": "failed", "message": message})
    else: # User has not attempted login yet
        return jsonify({"status": "not_logged_in", "message": "الرجاء تسجيل الدخول عبر ديسكورد للتحقق من الصلاحيات."})

@app.route("/logout")
def logout():
    session.pop("is_military_police", None)
    session.pop("user_discord_id", None)
    session.pop("username", None)
    session.pop("oauth_state", None)
    return redirect(FRONTEND_URL) # Redirect to frontend's home page

if __name__ == "__main__":
    # In a production environment, use a more robust WSGI server like Gunicorn or uWSGI
    # and serve over HTTPS. For local development, this is fine.
    app.run(debug=True, port=5000)
