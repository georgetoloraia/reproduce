import argparse
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point

class ECPoint:
    def __init__(self, point):
        self.point = point

    @property
    def x(self):
        return self.point.x()

    @property
    def y(self):
        return self.point.y()

    def __sub__(self, other):
        # Subtract points by adding the inverse
        inverse_other = Point(
            other.point.curve(),
            other.point.x(),
            -other.point.y(),  # Negate y-coordinate
            other.point.order()
        )
        return ECPoint(self.point + inverse_other)

    def halve(self):
        # Multiply by modular inverse of 2
        inverse_2 = pow(2, SECP256k1.order - 2, SECP256k1.order)
        return ECPoint(self.point * inverse_2)

    def __eq__(self, other):
        return self.point == other.point

    @classmethod
    def G(cls):
        return cls(SECP256k1.generator)

    @classmethod
    def parse(cls, line):
        x_str, y_str = line.strip().split(",")
        x = int(x_str.strip())
        y = int(y_str.strip())
        return cls(Point(SECP256k1.curve, x, y))


def read_steps(filename):
    with open(filename, 'r') as f:
        return [ECPoint.parse(line) for line in f]

def read_pubkeys(filename):
    with open(filename, 'r') as f:
        return [ECPoint.parse(line) for line in f]

def recover_private_keys(pubkeys, steps, max_bits=256, limit=None, stdout=False):
    solutions = []
    for pubkey in pubkeys[:limit]:
        queue = [(pubkey, "", 0)]
        found = False
        while queue and not found:
            current, bits, depth = queue.pop(0)
            if depth > max_bits:
                continue
            if current == ECPoint.G():
                try:
                    derived_key = int(bits[::-1], 2)
                    # print(derived_key)
                    # Verify the derived key
                    test_pub = ECPoint.G().point * derived_key
                    # print(test_pub.x, test_pub.y)
                    if test_pub.x() == pubkey.x and test_pub.y() == pubkey.y:
                        solutions.append((pubkey, derived_key))
                        if stdout:
                            print(f"Found key: {derived_key} for pubkey {pubkey.x}, {pubkey.y}")
                        found = True
                except:
                    continue
                continue
            # Try '0' step: halve the point
            try:
                prev_zero = current.halve()
                queue.append((prev_zero, bits + "0", depth + 1))
            except:
                pass
            # Try '1' step: subtract each candidate
            for cand in steps:
                prev_candidate = current - cand
                queue.append((prev_candidate, bits + "1", depth + 1))
            # print(queue)
    return solutions

def main():
    parser = argparse.ArgumentParser(description="Reverse private key reconstruction")
    parser.add_argument("--generate-steps", action="store_true", help="Generate steps.txt")
    parser.add_argument("--max_bits", type=int, default=256, help="Maximum bit depth")
    parser.add_argument("--limit", type=int, help="Limit number of pubkeys checked")
    parser.add_argument("--stdout", action="store_true", help="Output results to stdout")
    args = parser.parse_args()

    if args.generate_steps:
        # Generate steps.txt: 1P, 2P, ..., 256P
        # Note: This is a conceptual implementation. Real implementation needs actual scalar multiplication.
        steps = []
        G = SECP256k1.generator
        with open("steps.txt", "w") as f:
            for i in range(1, 257):
                point = G * i
                f.write(f"{hex(point.x())} {hex(point.y())}\n")
        print("Generated steps.txt")
        return

    steps = read_steps("steps.txt")
    pubkeys = read_pubkeys("allpubs_point.txt")
    solutions = recover_private_keys(pubkeys, steps, args.max_bits, args.limit, args.stdout)

    # Save solutions to a file or handle as needed
    with open("solutions.txt", "w") as f:
        for pubkey, priv in solutions:
            f.write(f"Pubkey: {pubkey.x}, {pubkey.y} -> Private: {hex(priv)}\n")

if __name__ == "__main__":
    main()