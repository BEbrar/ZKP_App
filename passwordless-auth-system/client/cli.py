# User registration
import hashlib
from constants import p, g, q


def user_registration(username, password):
    # Use the password as x
    x = int.from_bytes(hashlib.sha256(password.encode()).digest(), 'big') % q
    y = pow(g, x, p)  # Compute public key
    # Simulate storing in a database
    print(f"User {username} registered with public key: {y}")
    return y
    