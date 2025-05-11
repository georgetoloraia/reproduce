import multiprocessing
from tqdm import tqdm
from multiprocessing import Manager

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

def check_key_wrapper(args):
    return check_key(*args)

def check_key(x, y, max_bits):
    pub = ECPoint(x, y)
    G = Secp256k1.G
    for k in range(1, 2**max_bits):
        cand = Secp256k1.scalar_multiply(k, G)
        if cand == pub:
            return (x, k, bin(k)[2:])
    return (x, None, None)

def simulate_scalar_trace_for_file(filename="allpubs_point.txt", max_bits=20):
    # Load pubkeys from file
    pubkeys = []
    with open(filename, "r") as f:
        for line in f:
            x_str, y_str = line.strip().split(",")
            x = int(x_str)
            y = int(y_str)
            pubkeys.append((x, y))

    found_count = multiprocessing.Value('i', 0)
    total_keys = len(pubkeys)

    def update_progress(result):
        x, priv, bstr = result
        with found_count.get_lock():
            if priv:
                found_count.value += 1
        pbar.update(1)

    with multiprocessing.Pool() as pool:
        with tqdm(total=total_keys, desc="Tracing pubkeys", unit="key", dynamic_ncols=True) as pbar:
            results = []
            for result in pool.imap_unordered(check_key_wrapper, [(x, y, max_bits) for x, y in pubkeys]):
                update_progress(result)
                results.append(result)
                pbar.set_postfix(found=found_count.value)

    # Write results
    with open("recovered_keys_bruteforce.txt", "w") as out:
        for x, priv, bstr in results:
            if priv:
                out.write(f"Pubkey.x: {x}\nPrivate: {priv}\nBinary: {bstr}\n{'-'*40}\n")

    return results

# Run the function
if __name__ == "__main__":
    simulate_scalar_trace_for_file("allpubs_point.txt", max_bits=256)
