import secrets


def generate_token():
    # Generate a random secret key
    secret_key = secrets.token_urlsafe(32)
    return secret_key
