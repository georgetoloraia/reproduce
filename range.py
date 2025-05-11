import itertools
from tqdm import tqdm
from binascii import unhexlify
from multiprocessing import Pool, cpu_count

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __eq__(self, other):
        return (
            isinstance(other, ECPoint)
            and self.x == other.x
            and self.y == other.y
            and self.infinity == other.infinity
        )

    def __hash__(self):
        return hash((self.x, self.y, self.infinity))

class Secp256k1:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    G = ECPoint(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )

    @staticmethod
    def point_add(p1, p2):
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, True)
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, True)
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        else:
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p
        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def scalar_multiply(k, point):
        result = ECPoint(None, None, True)
        addend = point
        while k:
            if k & 1:
                result = Secp256k1.point_add(result, addend)
            addend = Secp256k1.point_add(addend, addend)
            k >>= 1
        return result

    @staticmethod
    def get_pubkey_bytes(point, compressed=True):
        prefix = b"\x02" if point.y % 2 == 0 else b"\x03"
        return prefix + point.x.to_bytes(32, 'big') if compressed else b"\x04" + point.x.to_bytes(32, 'big') + point.y.to_bytes(32, 'big')

def generate_keys_in_range_with_ones(low, high, ones):
    for k in range(low, high + 1):
        if bin(k).count("1") == ones:
            yield k

def check_private_candidate(args):
    k, pubkey_bytes = args
    candidate = Secp256k1.scalar_multiply(k, Secp256k1.G)
    candidate_bytes = Secp256k1.get_pubkey_bytes(candidate, compressed=True)
    if candidate_bytes == pubkey_bytes:
        return k
    return None

def try_keys_in_range(pubkey_hex, low, high, ones):
    pubkey_bytes = unhexlify(pubkey_hex)
    candidates = [(k, pubkey_bytes) for k in generate_keys_in_range_with_ones(low, high, ones)]

    with Pool(cpu_count()) as pool:
        for result in tqdm(pool.imap_unordered(check_private_candidate, candidates), total=len(candidates), desc="Searching", unit="key"):
            if result:
                return result, bin(result).count('1'), hex(result)
    return None

if __name__ == "__main__":
    low = 21778071482940061661655974875633165533184
    high = 43556142965880123323311949751266331066367
    ones = 65
    pubkey_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"

    result = try_keys_in_range(pubkey_hex, low, high, ones)
    if result:
        priv, ones_count, priv_hex = result
        print("✅ Private key found!")
        print(f"Decimal: {priv}\nHex: {priv_hex}\n1s count: {ones_count}")
    else:
        print("❌ No matching private key found in the range.")
