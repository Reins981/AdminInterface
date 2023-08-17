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
from firebase_admin import credentials, auth

app = Flask(__name__, static_folder='images')

BASE_PATH_SA = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "service_account"
)

CRED = os.path.join(
    BASE_PATH_SA,
    "documentmanagement-f7ce9-firebase-adminsdk-v2523-2961c1b483.json"
)

# Initialize Firebase Admin SDK
cred = credentials.Certificate(CRED)
firebase_admin.initialize_app(cred)


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
            auth.verify_password(password, user)
            session['user_id'] = user.uid
            return redirect(url_for('index'))
        except Exception:
            error_message = "Invalid email or password"
            return render_template('login.html', error_message=error_message)

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    users = auth.list_users().users
    return render_template('index.html', users=users)


@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
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
        user = auth.create_user(email=email, password=password)

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


if __name__ == '__main__':
    app.run(debug=True)
