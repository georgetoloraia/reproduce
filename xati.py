# Define secp256k1 curve parameters (simplified for demonstration)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Prime field
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798  # Base point G
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Order of G

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __repr__(self):
        return f"Point({hex(self.x)}, {hex(self.y)})"

    def is_infinity(self):
        return self.x is None and self.y is None

def inverse_mod(k, p):
    """Compute the modular inverse of k mod p using Fermat's Little Theorem."""
    return pow(k, p-2, p)

def point_add(P, Q):
    """Add two distinct points P and Q on the elliptic curve."""
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P
    if P.x == Q.x and (P.y != Q.y or P.y == 0):
        return Point(None, None)  # Infinity point (result of P + (-P))

    # Calculate slope (s)
    if P.x != Q.x:
        s = (Q.y - P.y) * inverse_mod(Q.x - P.x, p) % p  # (y2 - y1)/(x2 - x1)
    else:
        s = (3 * P.x**2 + a) * inverse_mod(2 * P.y, p) % p  # Doubling slope: (3x² + a)/(2y)

    x3 = (s**2 - P.x - Q.x) % p
    y3 = (s * (P.x - x3) - P.y) % p
    return Point(x3, y3)

def point_double(P):
    """Double a point P on the elliptic curve."""
    return point_add(P, P)

def scalar_multiply(k, P):
    """Compute k * P using the double-and-add algorithm."""
    result = Point(None, None)  # Infinity point (identity)
    current = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_double(current)
        k = k // 2
    return result

# Base point G
G = Point(Gx, Gy)

# Compute Q = 3G (G + G + G)
Q = scalar_multiply(3, G)

# Print results
print("Base Point G:", G)
print("2G = G + G:", point_double(G))
print("3G = 2G + G:", point_add(point_double(G), G))
print("\nFinal Result (3G):", Q)

a0 = G
a1 = point_double(G)
a2 = point_add(point_double(G), G)

l = n - a0.x
m = l - a0.x
print(l)
print(m)

