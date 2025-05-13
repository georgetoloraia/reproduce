from time import sleep
from random import randint
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import classSECP

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

class Secp256k1:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    G = ECPoint(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    h = 1

    @staticmethod
    def point_add(p1, p2):
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, infinity=True)
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, infinity=True)
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        else:
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p

        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def scalar_mult(k, ste, need_check_oub):
        result = ECPoint(ste.x, ste.y, infinity=False)
        addend = ste
        while k:
            if k & 1:
                result = Secp256k1.point_add(result, addend)
            addend = Secp256k1.point_add(addend, addend)
            k >>= 1
        return result

    @staticmethod
    def generate_public_key(private_key, ste, need_check_pub):
        return Secp256k1.scalar_mult(private_key, ste, need_check_pub)

def load_points_from_file(filename, reverse=True):
    with open(filename) as f:
        lines = f.readlines()
    if reverse:
        lines = lines[::-1]
    return [ECPoint(*map(int, line.strip().split(','))) for line in lines]

def load_points_from_file_pubs(filename):
    with open(filename) as re:
        return set(int(line.strip().split(",")[0]) for line in re)

# 🔁 Worker function for Pool
def process_pair(args):
    private_key, ste, need_check_pub, allpubs = args
    public_key = Secp256k1.generate_public_key(private_key, ste, need_check_pub)
    priv_from_pub = public_key.x - need_check_pub
    result_point = classSECP.Secp256k1.generate_public_key(abs(priv_from_pub))
    if result_point.x in allpubs:
        print(f"\nwooow\n{priv_from_pub}\n")
        return f"\nwooow\n{priv_from_pub}\n"
    return None

def main():
    private_key = 0x1
    stepslist = load_points_from_file("steps.txt")
    allpubs = load_points_from_file_pubs("allpubs_point.txt")

    tasks = [(private_key, ste, need_check_pub, allpubs) for ste in stepslist for need_check_pub in allpubs]

    with Pool(processes=cpu_count()) as pool:
        for result in tqdm(pool.imap_unordered(process_pair, tasks), total=len(tasks), desc="Processing"):
            if result:
                print(result)

if __name__ == "__main__":
    main()
