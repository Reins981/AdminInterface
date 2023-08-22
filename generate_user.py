import re
import os
import hashlib
import argparse
import firebase_admin
from firebase_admin import auth, credentials
from utils import CRED

# Initialize Firebase Admin SDK
cred = credentials.Certificate(CRED)
firebase_admin.initialize_app(cred, {
    'storageBucket': 'documentmanagement-f7ce9.appspot.com'
})


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt

    # Combine salt and password and hash the result
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, hashed


def create_user(username, email, password, role, domain):
    _, hashed_password = hash_password(password)
    print(f"Creating user:")
    print(f"\tusername: {username}")
    print(f"\temail: {email}")
    print(f"\tpassword: {hashed_password}")
    print(f"\trole: {role}")
    print(f"\tdomain: {domain}")

    # Check if password meets the criteria
    if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        error_message = ("Password must be at least 8 characters long "
                         "and include a special character.")
        raise RuntimeError(error_message)

    try:
        # Create a new user with email and password
        user = auth.create_user(email=email, password=password, display_name=username)

        # Assign custom claims to indicate user role
        auth.set_custom_user_claims(user.uid, {
            'role': role,
            'domain': domain,
            "disabled": user.disabled,
            "verified": True,
            "verification_token": None
        })

    except Exception as e:
        raise RuntimeError(str(e))

    print("Success!")

if __name__ == '__main__':  # noqa C901

    parser = argparse.ArgumentParser()
    parser.add_argument("-u",
                        "--username",
                        dest="username",
                        required=True,
                        type=str,
                        help="username")
    parser.add_argument("-e",
                        "--email",
                        dest="email",
                        required=True,
                        type=str,
                        help="email")
    parser.add_argument("-p",
                        "--password",
                        dest="password",
                        required=True,
                        type=str,
                        help="password requirements: length >= 8 and >= 1 special character")
    parser.add_argument("-r",
                        "--role",
                        dest="role",
                        type=str,
                        default="admin",
                        help="user role: [admin,client]")
    parser.add_argument("-d",
                        "--domain",
                        dest="domain",
                        type=str,
                        default="BACQROO-ALL",
                        help="domain the user belongs to [BACQROO-ALL,BACQROO-PDC,BACQROO-MEX]")

    args = parser.parse_args()

    create_user(args.username, args.email, args.password, args.role, args.domain)
