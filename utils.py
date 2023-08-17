import json
import os

BASE_PATH_SA = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "service_account"
)

FIREBASE_SERVICES = os.path.join(
    BASE_PATH_SA,
    "google-services.json"
)

BASE_PATH_SA = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "service_account"
)

CRED = os.path.join(
    BASE_PATH_SA,
    "documentmanagement-f7ce9-firebase-adminsdk-v2523-2961c1b483.json"
)


def parse_client_setting_from_json(json_file_path, key):
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
            if 'client' in data and key in data['client'][0]:
                key_config = data['client'][0][key][0]
                return key_config
            else:
                print(f"API {key} not found in JSON file.")
                return None
    except Exception as e:
        print("Error parsing JSON file:", e)
        return None


def get_url_for_firebase_auth():
    api_key_config = parse_client_setting_from_json(FIREBASE_SERVICES, 'api_key')
    # URL for the Firebase Auth REST API
    return (f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
            f"{api_key_config['current_key']}")