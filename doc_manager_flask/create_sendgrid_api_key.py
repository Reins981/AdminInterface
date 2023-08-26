import os
from sendgrid import SendGridAPIClient


sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))

data = {
    "name": "SecDoc",
    "scopes": [
        "mail.send",
        "alerts.create",
        "alerts.read"
    ]
}

response = sg.client.api_keys.post(
    request_body=data
)

print(response.status_code)
print(response.body)
print(response.headers)
