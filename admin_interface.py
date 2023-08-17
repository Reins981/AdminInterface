from flask import Flask, render_template, request, redirect, url_for
import firebase_admin
import os
from firebase_admin import credentials, auth

app = Flask(__name__)

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


@app.route('/')
def index():
    users = auth.list_users().users
    return render_template('index.html', users=users)


@app.route('/create_user', methods=['POST'])
def create_user():
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    try:
        # Create a new user with email and password
        user = auth.create_user(email=email, password=password)

        # Assign custom claims to indicate user role
        auth.set_custom_user_claims(user.uid, {'role': role})

        return redirect(url_for('index'))
    except Exception as e:
        return str(e)


@app.route('/update_user', methods=['POST'])
def update_user():
    uid = request.form['uid']
    new_role = request.form['new_role']

    try:
        # Update user's custom claims to change role
        auth.set_custom_user_claims(uid, {'role': new_role})

        return redirect(url_for('index'))
    except Exception as e:
        return str(e)


@app.route('/delete_user/<uid>', methods=['POST'])
def delete_user(uid):
    try:
        # Delete the user account
        auth.delete_user(uid)

        return redirect(url_for('index'))
    except Exception as e:
        return str(e)


if __name__ == '__main__':
    app.run(debug=True)
