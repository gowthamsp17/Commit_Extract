import os
import base64
from email.message import EmailMessage
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def authenticate():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return creds

def send_email(log_file):
    creds = authenticate()
    service = build('gmail', 'v1', credentials=creds)

    message = EmailMessage()
    message.set_content(open(log_file).read())

    message['To'] = 'gowtham.sp@zohocorp.com, spgowtham.1703@gmail.com'
    message['From'] = 'me'
    message['Subject'] = 'Kernel + CVE Report'

    with open(log_file, 'rb') as f:
        message.add_attachment(f.read(), maintype='text', subtype='plain', filename=os.path.basename(log_file))

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    service.users().messages().send(userId="me", body={'raw': raw}).execute()

if __name__ == '__main__':
    import sys
    send_email(sys.argv[1])
