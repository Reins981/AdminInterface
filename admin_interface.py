from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)
import firebase_admin
from functools import wraps
import os
import re
import requests
from firebase_admin import credentials, auth
from utils import (
    get_url_for_firebase_auth,
    CRED
)

app = Flask(__name__, static_folder='images')
app.secret_key = 'tz957fpzG0Pib5GPFd1rdv82v1abxbrZX9btUAL_dpI'

# Initialize Firebase Admin SDK
cred = credentials.Certificate(CRED)
firebase_admin.initialize_app(cred)


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
        users = auth.list_users().users
        return render_template(
            'index.html',
            users=users,
            error_message="Password must be at least 8 characters long "
                          "and include a special character."
        )

    try:
        # Create a new user with email and password
        user = auth.create_user(email=email, password=password, display_name=username)

        # Assign custom claims to indicate user role
        auth.set_custom_user_claims(user.uid, {'role': role, 'domain': domain})

        return redirect(url_for('index'))
    except Exception as e:
        return str(e)


@app.route('/update_user', methods=['POST'])
@login_required
def update_user():
    uid = request.form['uid']
    new_role = request.form['new_role']

    try:
        # Get the user's current custom claims
        user = auth.get_user(uid)
        current_custom_claims = user.custom_claims

        current_custom_claims = dict() if current_custom_claims is None else current_custom_claims

        # Delete the old role claim if it exists
        if current_custom_claims and 'role' in current_custom_claims:
            del current_custom_claims['role']

        # Update the current custom claims with the new role
        current_custom_claims['role'] = new_role

        # Update user's custom claims to change role
        auth.set_custom_user_claims(uid, current_custom_claims)

        return redirect(url_for('index'))
    except Exception as e:
        return str(e)


@app.route('/delete_user/<uid>', methods=['POST'])
@login_required
def delete_user(uid):
    try:
        # Delete the user account
        auth.delete_user(uid)

        return redirect(url_for('index'))
    except Exception as e:
        return str(e)


def current_user_domain(session_lookup=True, current_user=None):
    if session_lookup:
        # Get the current user's UID
        current_user = auth.get_user(session['user_id'])

    # Get the current user's custom claims, including the domain
    custom_claims = current_user.custom_claims

    return custom_claims.get('domain', None)


def sort_users(users_by_domain: dict):
    # Sort users within each domain
    for domain, domain_users in users_by_domain.items():
        domain_users.sort(key=lambda user: user.email)

    # Flatten the sorted users by domain into a single list
    return [user for domain_users in users_by_domain.values() for user in domain_users]


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
        return "Error fetching users by domain:", str(e)


if __name__ == '__main__':
    app.run(debug=True)
