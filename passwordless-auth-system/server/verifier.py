import hashlib
from server.constants import p, g, q

# Verify proof (t, s) for given username
def verify_proof(t, s, y):
    # Ensure all inputs are integers
    t = int(t)
    s = int(s)
    y = int(y)

    # Compute challenge
    hash_input = f"{t}{y}".encode()
    c = int(hashlib.sha256(hash_input).hexdigest(), 16) % q

    # Verify if g^s mod p == t * y^c mod p
    lhs = pow(g, s, p)  # Left-hand side
    rhs = (t * pow(y, c, p)) % p  # Right-hand side

    print(f"lhs: {lhs}, rhs: {rhs}")  # For Debugging  
    return lhs == rhs
