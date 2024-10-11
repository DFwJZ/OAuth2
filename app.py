import os
import json
from flask import Flask, render_template, url_for, redirect, session, request
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from dotenv import load_dotenv
import logging

load_dotenv()

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_secret_key")  # Use environment variable in production

def load_client_secret():
    # Check if we're in a development environment
    if os.environ.get('FLASK_ENV') == 'development':
        # Load from file in development
        client_secrets_file = os.path.join(os.path.dirname(__file__), "client_secret.json")
        if os.path.exists(client_secrets_file):
            with open(client_secrets_file) as f:
                return json.load(f)
        else:
            raise FileNotFoundError(f"client_secret.json not found at {client_secrets_file}")
    elif os.environ.get('FLASK_ENV') == 'production':
        # In production, use environment variables
        return {
            "web": {
                "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
                "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "redirect_uris": [os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8080/callback")]
            }
        }
    else:
        print("Not Supported Flask Environment")
        exit(1)

# Load client configuration
client_config = load_client_secret()

SCOPES = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    print("Callback received")
    print("State:", session.get('state'))
    print("URL:", request.url)
    flow = Flow.from_client_config(client_config, scopes=SCOPES, state=session['state'])
    flow.redirect_uri = url_for('callback', _external=True)
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    credentials = Credentials(**session['credentials'])
    people_service = build('people', 'v1', credentials=credentials)
    profile = people_service.people().get(resourceName='people/me', personFields='names,emailAddresses,photos').execute()
    
    name = profile['names'][0]['displayName']
    email = profile['emailAddresses'][0]['value']
    picture = profile.get('photos', [{}])[0].get('url')
    
    print(f"Debug - Picture URL: {picture}")  # Add this line


    return render_template('profile.html', name=name, email=email, picture=picture)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only
    app.run(debug=True, port=8080)