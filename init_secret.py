import secrets

# Generate a random secret key
secret_key = secrets.token_urlsafe(32)

print("Generated Secret Key:", secret_key)
