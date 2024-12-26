import hashlib
from constants import p, g, q

# Verify proof (c, s) for given username
def verify_proof(c, s, y):
    # Ensure all inputs are integers
    c = int(c)
    s = int(s)
    y = int(y)

    # Recompute t using g^s * y^c mod p
    lhs = (pow(g, s, p) * pow(y, c, p)) % p  # Recomputed commitment t

    # Recompute the challenge c = H(g || y || t)
    hash_input = f"{g}{lhs}{y}".encode()
    computed_c = int(hashlib.sha256(hash_input).hexdigest(), 16) % q

    # Debugging output to inspect the values
    print(f"lhs (recomputed t): {lhs}, computed_c: {computed_c}, received_c: {c}")

    # Verify if the recomputed challenge matches the received challenge
    return computed_c == c
