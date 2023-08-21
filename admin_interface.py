from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    Response
)
import firebase_admin
from functools import wraps
import os
import re
import requests
import shutil
import asyncio
from firebase_admin import (
    credentials,
    auth,
    firestore
)
from utils import (
    get_url_for_firebase_auth,
    upload_document,
    CRED
)
from thread_base import Worker, ThreadPool, TaskCounter

app = Flask(__name__, static_folder='images')
app.secret_key = 'tz957fpzG0Pib5GPFd1rdv82v1abxbrZX9btUAL_dpI'

# Define a temporary folder for storing uploaded files
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "temporary_upload")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure the temporary upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(CRED)
firebase_admin.initialize_app(cred, {
            'storageBucket': 'documentmanagement-f7ce9.appspot.com'
        })


def requires_admin_role():
    if 'user_id' not in session or 'role' not in session:
        return False

    user_role = session['role']
    return user_role == 'admin'


@app.before_request
def before_request():
    if request.endpoint != 'login' and not requires_admin_role():
        return redirect(url_for('login'))


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))  # Redirect to login if not authenticated
        return f(*args, **kwargs)
    return decorated_function


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
                if role and role == 'admin':
                    session['user_id'] = user.uid
                    session['display_name'] = user.display_name
                    session['role'] = role
                    return redirect(url_for('index'))
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


@app.route('/', methods=['GET'])
@login_required
def index():
    users = fetch_users_by_domain(current_user_domain())
    if isinstance(users, str):
        error_message = users
        return render_template(
            'index.html',
            users=[],
            error_message=error_message
        )
    return render_template('index.html', users=users)


@app.route('/clear_error_message', methods=['POST'])
@login_required
def clear_error_message():
    if 'error_message' in session:
        session.pop('error_message')
    return ''


@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    username = request.form['display_name']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    domain = request.form['domain']

    # Check if password meets the criteria
    if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        # Store the error message in the session
        error_message = ("Password must be at least 8 characters long "
                         "and include a special character.")
        session['error_message'] = error_message
        return redirect(url_for('index'))

    try:
        # Create a new user with email and password
        user = auth.create_user(email=email, password=password, display_name=username)

        # Assign custom claims to indicate user role
        auth.set_custom_user_claims(user.uid, {
            'role': role,
            'domain': domain,
            "disabled": user.disabled
        })

        return redirect(url_for('index'))
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
        current_user = auth.get_user(session['user_id'])

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
    try:
        user_records = auth.list_users().users

        # Create a dictionary to store users by domain
        users_by_domain = {}

        if domain == 'BACQROO-ALL':
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
        # Store the error message in the session
        session['error_message'] = str(e)
        return redirect(url_for('index'))


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
    db = firestore.client()
    selected_user_uid = request.form['user_dropdown']
    selected_email = request.form['selected_email']
    selected_domain = request.form['selected_domain']

    response_data = {
        'success': True,
        'message': 'Document(s) uploaded successfully'
    }

    upload_files = request.files.getlist('documents')

    # First clean the temo dir
    status = clean_directory(app.config["UPLOAD_FOLDER"])
    if status != 'success':
        response_data['success'] = False
        response_data['message'] = status
        return response_data

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
    pool = ThreadPool(num_threads=len(upload_files),
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

    return jsonify(response_data)


@app.route('/handle_selection_specific', methods=['POST'])
@login_required
def handle_selection_specific():
    # Create a reference to the Firestore database
    db = firestore.client()
    selected_uids = request.form.get('user_dropdown').split(',')
    selected_emails = request.form['selected_email'].split(',')
    selected_domains = request.form['selected_domain'].split(',')

    response_data = {
        'success': True,
        'message': 'Document(s) uploaded successfully'
    }

    upload_files = request.files.getlist('documents')

    # First clean the temo dir
    status = clean_directory(app.config["UPLOAD_FOLDER"])
    if status != 'success':
        response_data['success'] = False
        response_data['message'] = status
        return response_data

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
    pool = ThreadPool(num_threads=len(upload_files) * len(selected_uids),
                      task_counter=task_counter)
    print(f"Starting in total {thread_counter} Worker Threads")

    category = request.form['selected_category']
    for upload_file in upload_files:
        document_name = upload_file.filename

        # Upload the file to the temporary folder
        temp_file_path = os.path.join(app.config["UPLOAD_FOLDER"], document_name)

        for i, selected_user_uid in enumerate(selected_uids):
            selected_email = selected_emails[i]
            selected_domain = selected_domains[i]
            # Schedule the upload to happen after a short delay
            print(f"Handle file upload for user {selected_user_uid}/{selected_email}")
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

    return jsonify(response_data)


if __name__ == '__main__':
    app.run(debug=True)
