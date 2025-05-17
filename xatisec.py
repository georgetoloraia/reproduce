import multiprocessing
from multiprocessing import Queue
from coincurve import PublicKey

# # Define secp256k1 curve parameters
# p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# a = 0
# b = 7
# Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
# Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
# n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# class Point:
#     def __init__(self, x, y):
#         self.x = x
#         self.y = y

#     def is_infinity(self):
#         return self.x is None and self.y is None

# def inverse_mod(k, p):
#     return pow(k, p-2, p)

# def point_add(P, Q):
#     if P.is_infinity():
#         return Q
#     if Q.is_infinity():
#         return P
#     if P.x == Q.x and (P.y != Q.y or P.y == 0):
#         return Point(None, None)
#     if P.x != Q.x:
#         s = (Q.y - P.y) * inverse_mod(Q.x - P.x, p) % p
#     else:
#         s = (3 * P.x**2 + a) * inverse_mod(2 * P.y, p) % p
#     x3 = (s**2 - P.x - Q.x) % p
#     y3 = (s * (P.x - x3) - P.y) % p
#     return Point(x3, y3)

# def point_double(P):
#     return point_add(P, P)

# def scalar_multiply(k, P):
#     result = Point(None, None)
#     current = P
#     while k > 0:
#         if k % 2 == 1:
#             result = point_add(result, current)
#         current = point_double(current)
#         k = k // 2
#     return result

# def read_points(filename):
#     points = []
#     with open(filename, 'r') as f:
#         for line in f:
#             line = line.strip()
#             if not line:
#                 continue
#             x_str, y_str = line.split(',')
#             x = int(x_str.strip())
#             y = int(y_str.strip())
#             points.append(x)
#     return points

def read_points(filename):
    points = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            x_str, y_str = line.split(',')
            x = int(x_str.strip())
            points.append(x)
    return set(points)

all_pubs = read_points("allpubs_point.txt")

# G = Point(Gx, Gy)
'''
# Base point G
z = 0
# Iterate through private keys 0-199
for i in all_pubs:
    l = (n * i) % 5659563192761508084413547218350839200336357371519716031604788420739928035857
    public_key = scalar_multiply(abs(l), G)
    
    # Skip the infinity point (i=0)
    if public_key.is_infinity():
        continue
    
    # Convert x-coordinate to hex (without '0x' prefix)
    # x_hex = hex(public_key.x)[2:]
    x_hex = str(public_key.x)
    # print(f"x_hex = {type(x_hex)} I = {type(i)}")
    if int(x_hex) in all_pubs:
        print(f"\nWoooooooooW .............\n Fooooooooooooound .............. \n {l}")
    
    # Check if x-coordinate starts with "11"
    if x_hex.startswith("1129"):
        print(f"Private Key (i): {z} = {i} = {l}")
        # print(f"X-coordinate (hex): 0x{x_hex}\n")
        # print(public_key.x)

        print(x_hex)
        if x_hex == "112982238584007708620509113802838448076193634440624888256500166945793332233482":
            print(f"\nWoooooooooW .............\n Fooooooooooooound .............. \n {l}")
            break
    z += 1

'''

z = 1
l = 1
for sebra in range(1, 150000):
    for i in all_pubs:
        while l < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            l = z + l
            # public_key = scalar_multiply(l, G)

            if l < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                priv_bytes = l.to_bytes(32, 'big')
                pub = PublicKey.from_valid_secret(priv_bytes)
                pub_point = pub.point()  # returns (x, y)
                x = pub_point[0]

            # Skip the infinity point (i=0)
            # if x.is_infinity():
            #     continue

            # x_hex = str(x)

            if int(x) in all_pubs:
                print(f"\nWoooooooooW .............\n Fooooooooooooound .............. \n {l}")

            # Check if x-coordinate starts with "11"
            if str(x).startswith(str(i)[:4]):
                # print(f"Private Key (i): {z} = {l}")
                # print(f"X-coordinate (hex): 0x{x_hex}\n")
                # print(x)

                z = l

            z += 1
        z = 1
        l = 1
    z = 1
    l = sebra
