import threading
import datetime
import urllib.parse
from init_secret import generate_token
from validate_email_address import validate_email
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_from_directory,
)
import firebase_admin
from functools import wraps
import os
import re
import requests
import shutil
from firebase_admin import (
    credentials,
    auth,
    firestore,
    storage
)
from utils import (
    get_url_for_firebase_auth,
    upload_document,
    CRED,
    Domains,
    is_value_present_in_dict,
    get_dict_based_on_value_from_dict,
    get_all_users,
    get_app_secret_key,
    get_app_temporary_upload_folder,
    get_firestore_storage_bucket,
    get_app_max_num_super_users
)
from thread_base import ThreadPool, TaskCounter
from mail_template import (
    send_verify_user_mail,
    send_notification_mail,
    set_app
)

app = Flask(__name__, static_folder='images')
app.secret_key = get_app_secret_key()
set_app(app)

# Define a temporary folder for storing uploaded files
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), get_app_temporary_upload_folder())
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure the temporary upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(CRED)
firebase_admin.initialize_app(cred, {
    'storageBucket': get_firestore_storage_bucket()
})

# Create a Firestore client instance
db = firestore.client()


def requires_admin_role():
    if 'user_id' not in session or 'role' not in session:
        return False

    user_role = session['role']
    return user_role == 'admin' or user_role == 'super_admin'


def dummy_task():
    pass


@app.before_request
def before_request():
    if request.endpoint != 'login' and not requires_admin_role():
        return render_template(
            'login.html',
            error_message="Only admins are allowed to login"
        )


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))  # Redirect to login if not authenticated
        return f(*args, **kwargs)

    return decorated_function


@login_required
def is_valid_email(email):
    return validate_email(email)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            user = auth.get_user_by_email(email)
            # Sign in the user with email and password

            # Verify the password
            firebase_auth_url = get_url_for_firebase_auth()

            # Request payload
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            # Make the POST request to verify the password
            response = requests.post(firebase_auth_url, json=payload)

            # Check if the request was successful
            if response.ok:
                user_data = response.json()

                role = user.custom_claims.get('role', None)
                verified = user.custom_claims.get('verified', None)
                admin_domain = user.custom_claims.get('domain', None)
                if role and (role == 'admin' or role == 'super_admin'):
                    if verified:
                        session.clear()
                        session['user_id'] = user.uid
                        session['display_name'] = user.display_name
                        session['role'] = role
                        session['admin_domain'] = admin_domain
                        return redirect(url_for('index'))
                    else:
                        error_message = f"User {user.display_name} is not verified!"
                        return render_template('login.html', error_message=error_message)
                else:
                    error_message = "Only admin users are authorized to log in."
                    return render_template('login.html', error_message=error_message)

            else:
                error_message = response.json()["error"]["message"]
                return render_template('login.html', error_message=error_message)
        except Exception as e:
            error_message = str(e)
            return render_template('login.html', error_message=error_message)

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/menu')
@login_required
def menu():
    return redirect(url_for('index'))


@app.route('/', methods=['GET'])
@login_required
def index():
    users = fetch_users_by_domain(current_user_domain())
    if isinstance(users, str):
        error_message = users
        # Clear the session data
        session.clear()
        return render_template(
            'login.html',
            error_message=error_message
        )
    return render_template('index.html', users=users)


@login_required
def sort_domains(domains):
    # Sort each domain
    for domain in domains:
        categories = domain['categories']
        for category in categories:
            category_docs = category['documents']
            category_docs = sorted(category_docs,
                                   key=lambda doc: doc.get('last_update'),
                                   reverse=True)
            category['documents'] = category_docs


@login_required
def prepare_query_snapshot(query_snapshot, domains, unique_document_names):
    # Loop through the query results and add documents to the list
    for document in query_snapshot:
        document_data = document.to_dict()
        # Does the domain exist?
        if not is_value_present_in_dict('name',
                                        domains,
                                        document_data.get('user_domain')):
            domain = {
                'name': document_data.get('user_domain'),
                'categories': []
            }
            domains.append(domain)
        # Does the category exist for the specified domain?
        relevant_domain = \
            [domain for domain in domains if
             domain['name'] == document_data.get('user_domain')]
        if not is_value_present_in_dict('name',
                                        relevant_domain[0].get('categories'),
                                        document_data.get('category')):
            category = {
                'name': document_data.get('category'),
                'documents': []
            }
            relevant_domain[0]['categories'].append(category)

        # Add the document ID to the dictionary
        document_data['document_id'] = document.id
        document_name = document_data['document_name']

        if document_name not in unique_document_names:
            category_dict = get_dict_based_on_value_from_dict(
                'name',
                relevant_domain[0]['categories'],
                document_data.get('category')
            )
            if category_dict:
                category_dict['documents'].append(document_data)
            unique_document_names.add(document_name)

    print(domains)
    return domains


@app.route('/document_history')
@login_required
def document_history():
    try:
        admin_domain = session.get('admin_domain', None)
        if not admin_domain:
            return render_template('history.html', error_message="Admin domain not found")

        # Use a set to keep track of unique document names
        unique_document_names = set()
        # Entry point
        domains = list()

        if admin_domain == Domains.ALL.value:
            # Get a list of all collections
            collections = [col.id for col in db.collections()]
            for collection in collections:
                # Clear old references
                unique_document_names.clear()
                documents_ref = db.collection(collection)
                query_snapshot = documents_ref.get()

                # Prepare the query snapshot and return the domains entry point
                domains = prepare_query_snapshot(query_snapshot, domains, unique_document_names)
                # Sort each domain
                sort_domains(domains)

        else:
            documents_ref = db.collection("_".join(("documents", admin_domain.lower())))
            query_snapshot = documents_ref.get()

            # Prepare the query snapshot and return the domains entry point
            domains = prepare_query_snapshot(query_snapshot, domains, unique_document_names)
            # Sort each domain
            sort_domains(domains)

        # Render the history.html template with the retrieved documents
        return render_template('history.html', domains=domains)
    except Exception as e:
        # Handle errors appropriately
        error_message = str(e)
        return render_template('history.html', error_message=error_message)


# ... Other routes and app configuration ...


@app.route('/delete_document', methods=['DELETE'])
@login_required
def delete_document():
    try:
        document_id = request.args.get('id')
        document_name = request.args.get('name')
        document_year = request.args.get('year')
        document_domain = request.args.get('domain')
        document_category = request.args.get('category')
        document_email = request.args.get('email')

        user = auth.get_user_by_email(document_email)
        # Check if the document still exists
        documents_ref = db.collection("_".join(("documents", document_domain.lower())))
        existing_doc = documents_ref.document(document_id).get()

        if existing_doc.exists:
            existing_data = existing_doc.to_dict()
            if (existing_data["category"] == document_category
                    and existing_data["owner"] == user.uid):
                # Update the existing document
                # Set a timestamp field to mark the document as deleted
                delete_time = firestore.SERVER_TIMESTAMP
                documents_ref.document(document_id).update({"deleted_at": delete_time})
                # Delete the document
                documents_ref.document(document_id).delete()

                # Delete the document from Firebase Cloud Storage
                storage_bucket = storage.bucket()
                file_path = (f"{document_domain.lower()}/"
                             f"{document_category}/"
                             f"{document_year}/"
                             f"{user.uid}/"
                             f"{user.display_name}/"
                             f"{document_name}")

                blob = storage_bucket.blob(file_path)
                blob.delete()

                response = {'success': True}
            else:
                response = {'success': False, 'error': 'Document properties do not match'}
        else:
            response = {'success': False, 'error': 'Document does not exist'}
    except Exception as e:
        # Handle errors appropriately
        response = {'success': False, 'error': str(e)}

    return jsonify(response)


@app.route('/logo/<path:filename>')
@login_required
def logo(filename):
    return send_from_directory('images', filename)


@app.route('/clear_error_message', methods=['POST'])
@login_required
def clear_error_message():
    if 'error_message' in session:
        session.pop('error_message')
    return ''


@app.route('/clear_success_message', methods=['POST'])
@login_required
def clear_success_message():
    if 'success_message' in session:
        session.pop('success_message')
    return ''


# Endpoint for sending verification email
@app.route('/send_verification_email', methods=['GET'])
@login_required
def send_verification_email():
    error = False
    user = None
    try:
        email = request.args.get('email')

        # Generate a random verification token
        verification_token = generate_token()

        # Calculate the expiration timestamp (e.g., 24 hours from now)
        expiration_time = datetime.datetime.now() + datetime.timedelta(hours=1)

        user = auth.get_user_by_email(email)
        current_custom_claims = user.custom_claims
        if current_custom_claims and 'verification_token' in current_custom_claims:
            current_custom_claims['verification_token'] = verification_token
            current_custom_claims['verification_token_expiration'] = expiration_time.timestamp()
            auth.set_custom_user_claims(user.uid, current_custom_claims)

            # Include the verification token as a parameter in the link
            verification_link = url_for('verify_email',
                                        token=verification_token,
                                        email=email,
                                        _external=True)
            # Send email with verification_link to the user's email address
            print(verification_link)
            status, msg = send_verify_user_mail(user.display_name, verification_link, email)
            if status != 'success':
                error = True
                session['error_message'] = msg
            else:
                session['success_message'] = msg

    except Exception as e:
        error = True
        # Store the error message in the session
        session['error_message'] = str(e)

    # Make sure the user is deleted in case email sending fails due to various reasons
    if error and user:
        delete_user(user.uid)

    return redirect(url_for('index'))


# Endpoint for verifying email
@app.route('/verify_email/<token>')
@login_required
def verify_email(token):
    error = False
    user = None
    try:
        email = request.args.get('email')
        user = auth.get_user_by_email(email)
        current_custom_claims = user.custom_claims
        if current_custom_claims and 'verification_token' in current_custom_claims:
            token_expiration = current_custom_claims.get('verification_token_expiration')
            if token_expiration and token_expiration > datetime.datetime.now().timestamp():
                if current_custom_claims['verification_token'] == token:
                    current_custom_claims['verified'] = True
                    # update user's custom claims to change the verified status
                    auth.set_custom_user_claims(user.uid, current_custom_claims)
                    message = f'Email verified! User `{user.display_name}` can now log in.'
                else:
                    error_message = f'Invalid verification token for user {user.uid}.'
                    message = error_message
                    error = True
                    # Make sure to delete the user from the database
                    delete_user(user.uid)
            else:
                error_message = f'Verification token has expired for user {user.uid}.'
                message = error_message
                error = True
                # Make sure to delete the user from the database
                delete_user(user.uid)
        else:
            error_message = f'No verification token set for user {user.uid}.'
            message = error_message
            error = True
            # Make sure to delete the user from the database
            delete_user(user.uid)
    except Exception as e:
        # Store the error message in the session
        message = str(e)
        error = True
        # Make sure to delete the user from the database
        if user:
            delete_user(user.uid)

    return render_template('login.html', success_message=message) if not error else (
        render_template('login.html', error_message=message))


@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    username = request.form['display_name']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    domain = request.form['domain']
    role = 'super_admin' if role == 'admin' and domain == Domains.ALL.value else role

    if not is_valid_email(email):
        error_message = "Invalid email address format"
        session['error_message'] = error_message
        return redirect(url_for('index'))

    # Check if password meets the criteria
    if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        # Store the error message in the session
        error_message = ("Password must be at least 8 characters long "
                         "and include a special character.")
        session['error_message'] = error_message
        return redirect(url_for('index'))

    try:

        users = get_all_users()

        allowed_number = get_app_max_num_super_users()
        results = list(filter(lambda x: x.custom_claims['domain'] == Domains.ALL.value, users))
        if len(results) > allowed_number:
            # Store the error message in the session
            session['error_message'] = f"Maximum allowed number of Super Users is {allowed_number}!"
            return redirect(url_for('index'))

        # Create a new user with email and password
        user = auth.create_user(email=email, password=password, display_name=username)

        # Assign custom claims to indicate user role
        auth.set_custom_user_claims(user.uid, {
            'role': role,
            'domain': domain,
            "disabled": user.disabled,
            "verified": False,
            "verification_token": None
        })

        # Send verification email to the user
        return redirect(url_for('send_verification_email', email=email))
    except Exception as e:
        # Store the error message in the session
        session['error_message'] = str(e)
        return redirect(url_for('index'))


@app.route('/update_user_status', methods=['POST'])
@login_required
def update_user_status():
    uid = request.form['uid']
    action = request.form.get("action")

    try:
        # Get the user's current custom claims
        user = auth.get_user(uid)

        # Handle the disable/enable action
        if action == "toggle_disable":
            # Toggle the user's disable status
            auth.update_user(uid, disabled=not user.disabled)

        # Get the updated user data after toggling the status
        updated_user = auth.get_user(uid)

        response_data = {
            "success": True,
            "message": "User status updated successfully.",
            "user": {
                "uid": updated_user.uid,
                "disabled": updated_user.disabled,
                # Include any other user properties you want to update in the UI
            }
        }

        return jsonify(response_data)
    except Exception as e:
        response_data = {
            "success": False,
            "message": str(e),
            "user": None
        }
        return jsonify(response_data)


@app.route('/update_user', methods=['POST'])
@login_required
def update_user():
    uid = request.form['uid']
    new_role = request.form['new_role']

    try:
        # Get the user's current custom claims
        user = auth.get_user(uid)

        if new_role:
            current_custom_claims = user.custom_claims

            current_custom_claims = dict() if current_custom_claims is None \
                else current_custom_claims

            # Delete the old role claim if it exists
            if current_custom_claims and 'role' in current_custom_claims:
                del current_custom_claims['role']

            # Update the current custom claims with the new role
            current_custom_claims['role'] = new_role

            # update user's custom claims to change role
            auth.set_custom_user_claims(uid, current_custom_claims)

        updated_user = auth.get_user(uid)
        custom_claims_updated = updated_user.custom_claims

        response_data = {
            "success": True,
            "message": "User role updated successfully.",
            "user": {
                "uid": user.uid,
                "role": custom_claims_updated['role']
            }
        }
        return jsonify(response_data)
    except Exception as e:
        response_data = {
            "success": False,
            "message": str(e),
            "user": None,
        }
        return jsonify(response_data)


@app.route('/delete_user/<uid>', methods=['POST'])
@login_required
def delete_user(uid):
    try:
        # Delete the user account
        auth.delete_user(uid)

        return redirect(url_for('index'))
    except Exception as e:
        # Store the error message in the session
        session['error_message'] = str(e)
        return redirect(url_for('index'))


@login_required
def current_user_domain(session_lookup=True, current_user=None):
    if session_lookup:
        # Get the current user's UID
        try:
            current_user = auth.get_user(session['user_id'])
        except Exception as e:
            return 'ERROR:' + str(e)

    # Get the current user's custom claims, including the domain
    custom_claims = current_user.custom_claims

    return custom_claims.get('domain', None)


@login_required
def sort_users(users_by_domain: dict):
    # Sort users within each domain
    for domain, domain_users in users_by_domain.items():
        domain_users.sort(key=lambda user: user.email)

    # Flatten the sorted users by domain into a single list
    return [user for domain_users in users_by_domain.values() for user in domain_users]


@login_required
def fetch_users_by_domain(domain):
    if not domain:
        return 'Could not find domain for current user'

    if 'ERROR:' in domain:
        error_message = domain
        return error_message

    try:
        user_records = auth.list_users().users

        # Create a dictionary to store users by domain
        users_by_domain = {}

        if domain == Domains.ALL.value:
            for user in user_records:
                # Access user's custom claims to check for domain
                user_domain = current_user_domain(False, user)
                if user_domain is None:
                    user_domain = 'N/A'
                if user_domain not in users_by_domain:
                    users_by_domain[user_domain] = []
                users_by_domain[user_domain].append(user)

            return sort_users(users_by_domain)

        for user in user_records:
            user_domain = current_user_domain(False, user)
            # Users not assigned to a domain won`t be displayed
            if user_domain is None:
                continue
            if user_domain == domain:
                if user_domain not in users_by_domain:
                    users_by_domain[user_domain] = []
                users_by_domain[user_domain].append(user)

        return sort_users(users_by_domain)

    except Exception as e:
        return str(e)


@login_required
def clean_directory(directory_path):
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            return f"Failed to delete {file_path}. Reason: {e}"
    return 'success'


@app.route('/handle_selection', methods=['POST'])
@login_required
def handle_selection():
    # Create a reference to the Firestore database
    selected_user_uid = request.form['user_dropdown']
    selected_email = request.form['selected_email']
    selected_domain = request.form['selected_domain']

    response_data = {
        'success': True,
        'message': ''
    }

    user = auth.get_user_by_email(selected_email)
    verified = user.custom_claims.get('verified', None)

    if not verified:
        response_data['success'] = False
        response_data['message'] = (f"Upload for user `{user.display_name}` is not allowed, "
                                    f"user is not verified")
        return jsonify(response_data)

    disabled = user.custom_claims.get('disabled', None)

    if disabled:
        response_data['success'] = False
        response_data['message'] = (f"Upload for user `{user.display_name}` is not allowed, "
                                    f"user is disabled")
        return jsonify(response_data)

    upload_files = request.files.getlist('documents')

    # First clean the temo dir
    status = clean_directory(app.config["UPLOAD_FOLDER"])
    if status != 'success':
        response_data['success'] = False
        response_data['message'] = status
        return jsonify(response_data)

    # Calculate total size first
    total_file_size = 0
    for upload_file in upload_files:
        document_name = upload_file.filename
        temp_file_path = os.path.join(app.config["UPLOAD_FOLDER"], document_name)
        upload_file.save(temp_file_path)
        total_file_size += os.path.getsize(temp_file_path)

    print(f"Uploading in total {total_file_size} bytes")

    task_counter = TaskCounter()
    thread_counter = len(upload_files)
    terminate_event = threading.Event()
    pool = ThreadPool(num_threads=len(upload_files),
                      terminate_condition=terminate_event,
                      task_counter=task_counter)
    print(f"Starting in total {thread_counter} Worker Threads")

    category = request.form['selected_category']
    for upload_file in upload_files:
        document_name = upload_file.filename

        # Upload file to the temporary folder
        temp_file_path = os.path.join(app.config["UPLOAD_FOLDER"], document_name)

        # Schedule the upload to happen after a short delay
        try:
            pool.add_task(
                upload_document,
                db,
                selected_user_uid,
                selected_email,
                selected_domain,
                category,
                temp_file_path,
            )
        except Exception as e:
            response_data = {
                'success': False,
                "message": str(e)
            }
            return jsonify(response_data)

    pool.wait_completion()

    results = pool.thread_results()
    all_true = any(item[0] for item in results)

    if all_true:
        response_data['message'] = 'Document(s) uploaded successfully'
    else:
        for success, error_message in results:
            if not success and error_message:
                response_data['success'] = False
                response_data['message'] = error_message
                break

    # Send the notification mail
    user = auth.get_user_by_email(selected_email)
    status, msg = send_notification_mail(user.display_name, selected_email)

    if status != 'success':
        response_data['success'] = False
        response_data['message'] = ('Document(s) uploaded successfully '
                                    'but a notification error occured: ') + msg
    else:
        response_data['message'] += ", Notification sent.."

    return jsonify(response_data)


@app.route('/handle_selection_specific', methods=['POST'])
@login_required
def handle_selection_specific():
    # Create a reference to the Firestore database
    selected_uids = request.form.get('user_dropdown').split(',')
    selected_emails = request.form['selected_email'].split(',')
    selected_domains = request.form['selected_domain'].split(',')

    response_data = {
        'success': True,
        'message': ''
    }

    upload_files = request.files.getlist('documents')

    # First clean the temo dir
    status = clean_directory(app.config["UPLOAD_FOLDER"])
    if status != 'success':
        response_data['success'] = False
        response_data['message'] = status
        return jsonify(response_data)

    # Calculate total size first
    total_file_size = 0
    for upload_file in upload_files:
        document_name = upload_file.filename
        temp_file_path = os.path.join(app.config["UPLOAD_FOLDER"], document_name)
        upload_file.save(temp_file_path)
        total_file_size += os.path.getsize(temp_file_path)

    print(f"Uploading in total {total_file_size} bytes")

    task_counter = TaskCounter()
    thread_counter = len(upload_files) * len(selected_uids)
    terminate_event = threading.Event()
    pool = ThreadPool(num_threads=len(upload_files) * len(selected_uids),
                      terminate_condition=terminate_event,
                      task_counter=task_counter)
    print(f"Starting in total {thread_counter} Worker Threads")

    category = request.form['selected_category']
    error = False
    user_specific_error = None
    user_error_list = set()
    for upload_file in upload_files:
        document_name = upload_file.filename

        # Upload the file to the temporary folder
        temp_file_path = os.path.join(app.config["UPLOAD_FOLDER"], document_name)

        for i, selected_user_uid in enumerate(selected_uids):
            # Reset
            user_error = False
            selected_email = selected_emails[i]
            selected_domain = selected_domains[i]

            if selected_user_uid == 'undefined' or selected_email == 'undefined':
                response_data['success'] = False
                response_data['message'] = ("No document(s) selected.\n "
                                            "Press the `Browse` button for selection")
                error = True
                # Break the inner loop...
                break

            # Do not allow uploads for unverified or disabled users
            user = auth.get_user_by_email(selected_email)
            verified = user.custom_claims.get('verified', None)

            if not verified:
                user_error_list.add(user.display_name)
                user_error = True
                user_specific_error = user_error

            disabled = user.custom_claims.get('disabled', None)

            if disabled:
                user_error_list.add(user.display_name)
                user_error = True
                user_specific_error = user_error

            # Schedule the upload to happen after a short delay
            print(f"Handle file upload for user {selected_user_uid}/{selected_email}")
            try:
                if user_error:
                    pool.add_task(
                        dummy_task
                    )
                else:
                    pool.add_task(
                        upload_document,
                        db,
                        selected_user_uid,
                        selected_email,
                        selected_domain,
                        category,
                        temp_file_path,
                    )
            except Exception as e:
                response_data = {
                    'success': False,
                    "message": str(e)
                }
                error = True
                # Break the inner loop...
                break
        else:
            # Continue if the inner loop wasn't broken.
            continue
        # Inner loop was broken, break the outer.
        break

    mail_error_messages = ""
    for i, selected_user_uid in enumerate(selected_uids):
        selected_email = selected_emails[i]
        user = auth.get_user_by_email(selected_email)

        if user.display_name not in user_error_list:
            # Send the notification mail
            print(f"Send mail to {user.display_name}: {selected_email}")
            status, msg = send_notification_mail(user.display_name, selected_email)

            if status != 'success':
                mail_error_messages += "/".join((msg, mail_error_messages))
                response_data['message'] += mail_error_messages
                error = True

    if error:
        pool.terminate_condition.set()
        for _ in range(thread_counter):
            print(f"Executing dummy task..")
            pool.add_task(dummy_task)
    else:
        pool.wait_completion()

        results = pool.thread_results()
        all_true = any(item[0] for item in results)

        if all_true:
            response_data['message'] = 'Document(s) uploaded successfully, Notification(s) sent..'

            if user_specific_error:
                if len(user_error_list) > 1:
                    response_data['message'] = (f'Document(s) uploaded and '
                                                f'notifications sent successfully '
                                                f'but not for the following users: '
                                                f'{str(user_error_list)}. '
                                                f'These users are disabled or not verified')
                else:
                    response_data['success'] = False
                    response_data['message'] = (f'Document(s) not uploaded '
                                                f'for the following user: '
                                                f'{str(user_error_list)}. '
                                                f'This user is disabled or not verified')

        else:
            for success, error_message in results:
                if not success and error_message:
                    response_data['success'] = False
                    response_data['message'] = error_message
                    break

    return jsonify(response_data)


if __name__ == '__main__':
    app.run(debug=True)
