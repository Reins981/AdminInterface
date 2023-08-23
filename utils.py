import json
import os
from firebase_admin import (
    firestore,
    auth,
    storage
)
from datetime import datetime
from threading import current_thread
from enum import Enum


class Domains(Enum):
    PDC = "BACQROO-PDC"
    MEX = "BACQROO-MEX"
    ALL = "BACQROO-ALL"


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


def is_value_present_in_dict(key, list_of_dicts, target_value):
    for dictionary in list_of_dicts:
        if dictionary.get(key) == target_value:
            return True
    return False


def get_dict_based_on_value_from_dict(key, list_of_dicts, target_value):
    for dictionary in list_of_dicts:
        if dictionary.get(key) == target_value:
            return dictionary
    return None


def upload_document(db, user_id, user_email, user_domain, category, file_path):
    if file_path:
        try:
            document_name = os.path.basename(file_path)
            print(f"{current_thread()} uploading file `{document_name}`")
            # Sanity check if the user still exists
            user = auth.get_user_by_email(user_email)  # Replace with the user's email
            user_name = user.display_name if user.display_name else "None"

            year = datetime.now().year
            document_path = (f"{user_domain.lower()}"
                             f"/{category}"
                             f"/{year}"
                             f"/{user_id}"
                             f"/{user_name}"
                             f"/{document_name}")

            if user_id:
                def _upload_thread():
                    # Upload the document to Firebase Cloud Storage
                    bucket = storage.bucket()
                    blob = bucket.blob(
                        document_path)  # Replace with the actual path to your uploaded document
                    blob.upload_from_filename(
                        file_path,
                        content_type='application/pdf')
                    # Set metadata
                    blob.metadata = {'uid': user_id}
                    blob.patch()

                    # Get the download URL of the uploaded document
                    document_url = blob.generate_signed_url(
                        expiration=300)  # URL expires in 5 minutes

                    new_document = {
                        "user_name": user_name,
                        "user_email": user_email,
                        "owner": user_id,
                        "category": category,
                        "user_domain": user_domain,
                        "document_name": document_name,
                        "document_url": document_url,
                        "year": year,
                        "deleted_at": None,
                        "last_update": firestore.SERVER_TIMESTAMP,
                        "is_new": False
                    }

                    # Sanity check. This should never happen unless someone deletes the domain
                    # which is highly unlikely
                    if 'domain' not in user.custom_claims:
                        raise RuntimeError(f"Domain missing for user {user_id}")

                    # Use the document name as a field to locate and update the document
                    documents_ref = db.collection("_".join(("documents", user_domain.lower())))

                    query = (documents_ref.
                             where("owner", "==", user_id).
                             where("category", "==", category).
                             where("document_name", "==", document_name).
                             where("user_domain", "==", user.custom_claims['domain']))

                    existing_docs = query.get()

                    if existing_docs:
                        # Update the existing document
                        doc_id = existing_docs[0].id
                        document_ref = documents_ref.document(doc_id)
                        document_ref.update(new_document)
                        print(f"Updated existing document {document_name}")
                    else:
                        # Create a new document
                        new_document['is_new'] = True
                        documents_ref.add(new_document)
                        print(f"Added new document {document_name}")

                    _on_upload_completed()

                def _on_upload_completed():
                    pass

                _upload_thread()
        except Exception as e:
            raise RuntimeError(str(e))
