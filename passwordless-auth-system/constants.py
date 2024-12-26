from Crypto.Util.number import getPrime

# Global parameters
# Generate a large prime number
p = getPrime(256)
q = p-1
# A generator for the group
g = 2


