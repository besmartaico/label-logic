import os
import json
import time
import logging
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
RULES_FILE = 'rules.json'

# 🔧 Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s — %(levelname)s — %(message)s',
    handlers=[
        logging.FileHandler("organizer.log"),
        logging.StreamHandler()  # Remove this line if you don't want console output
    ]
)

def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
    return []

def apply_label(service, user_id, msg_id, label_name):
    try:
        label_id = None
        label_list = service.users().labels().list(userId=user_id).execute().get('labels', [])
        for label in label_list:
            if label['name'] == label_name:
                label_id = label['id']
                break

        if not label_id:
            label_obj = {
                'name': label_name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
            new_label = service.users().labels().create(userId=user_id, body=label_obj).execute()
            label_id = new_label['id']

        service.users().messages().modify(
            userId=user_id,
            id=msg_id,
            body={
                'addLabelIds': [label_id],
                'removeLabelIds': ['INBOX']
            }
        ).execute()

        logging.info(f"Labeled and archived message ID {msg_id} as {label_name}")

    except Exception as e:
        logging.error(f"❌ Failed to apply label to message ID {msg_id}: {e}")

def authenticate_gmail():
    credentials_dict = json.loads(os.getenv("GOOGLE_CREDENTIALS_JSON", "{}"))
    if not credentials_dict:
        raise ValueError("Missing GOOGLE_CREDENTIALS_JSON environment variable")

    flow = Flow.from_client_config(credentials_dict, SCOPES)
    auth_url, _ = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    print(f"🔗 Visit this URL to authorize the app:\n{auth_url}")
    code = input("Paste the authorization code here: ")
    flow.fetch_token(code=code)

    creds = flow.credentials
    service = build('gmail', 'v1', credentials=creds)
    return service
