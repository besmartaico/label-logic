import os
import pickle
import json
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
LABELS_TO_WATCH = ['@Later', '@Finance', '@News']
EXAMPLES_FILE = 'labeled_examples.jsonl'

def load_credentials():
    creds = None
    if os.path.exists('token.json'):
        with open('token.json', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'wb') as token:
            pickle.dump(creds, token)
    return creds

def get_label_map(service):
    labels_result = service.users().labels().list(userId='me').execute()
    return {label['id']: label['name'] for label in labels_result['labels']}

def already_saved(example):
    if not os.path.exists(EXAMPLES_FILE):
        return False
    with open(EXAMPLES_FILE, 'r') as f:
        for line in f:
            saved = json.loads(line)
            if saved['from'] == example['from'] and saved['subject'] == example['subject'] and saved['label'] == example['label']:
                return True
    return False

def save_example(example):
    with open(EXAMPLES_FILE, 'a') as f:
        f.write(json.dumps(example) + '\n')

def main():
    creds = load_credentials()
    service = build('gmail', 'v1', credentials=creds)
    label_map = get_label_map(service)

    # Reverse the map to get label names from IDs
    label_id_map = {v: k for k, v in label_map.items() if v in LABELS_TO_WATCH}

    results = service.users().messages().list(
        userId='me',
        maxResults=100,
        labelIds=list(label_id_map.values())
    ).execute()

    messages = results.get('messages', [])
    print(f"🔍 Found {len(messages)} messages with watched labels.")

    for msg in messages:
        msg_data = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='metadata',
            metadataHeaders=['Subject', 'From']
        ).execute()

        headers = msg_data['payload'].get('headers', [])
        sender = subject = '(unknown)'
        for header in headers:
            if header['name'] == 'From':
                sender = header['value']
            elif header['name'] == 'Subject':
                subject = header['value']

        label_ids = msg_data.get('labelIds', [])
        for label_id in label_ids:
            label_name = label_map.get(label_id)
            if label_name in LABELS_TO_WATCH:
                example = {
                    'from': sender,
                    'subject': subject,
                    'label': label_name
                }
                if not already_saved(example):
                    save_example(example)
                    print(f"✅ Saved: {example}")

if __name__ == '__main__':
    main()
