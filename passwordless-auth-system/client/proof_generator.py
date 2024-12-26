import hashlib
import random
from constants import p, g, q


# Derive x from password and generate proof
def generate_proof(password, y):
    # Derive x from password
    x = int.from_bytes(hashlib.sha256(password.encode()).digest(), 'big') % q

    # Generate random r and compute commitment t
    r = random.randint(1, q)
    t = pow(g, r, p)  # t = g^r mod p

    hash_input = f"{g}{t}{y}".encode() #we add  c here and instead of t we send the c 
    c = int(hashlib.sha256(hash_input).hexdigest(), 16) % q

    # Compute response s = r - c * x mod (p-1)
    s = (r - c * x) % q

    return c, s