from time import sleep
from random import randint

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity  # Point at infinity (neutral element)

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
        # Handle the identity element (point at infinity)
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1

        # Handle the case where p1 and p2 are reflections of each other over the x-axis
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, infinity=True)

        # Handle the case where p1 and p2 are the same point (point doubling)
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, infinity=True)  # Tangent is vertical
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        else:
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p
        
        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def scalar_mult(k, point):
        # Simple and insecure scalar multiplication, not using double-and-add
        result = ECPoint(None, None, infinity=True)  # Start with the point at infinity
        addend = point

        while k:
            if k & 1:
                result = Secp256k1.point_add(result, addend)
                # print(f"result.x from c;lass = {result.x}")
            addend = Secp256k1.point_add(addend, addend)
            # print(f"addend {addend.x} {addend.y}")
            k >>= 1

        return result

    @staticmethod
    def generate_public_key(private_key):
        return Secp256k1.scalar_mult(private_key, Secp256k1.G)

def main():
    # Example usage:
    '''
    for private key we can enable all posible funqtions
    '''
    # private_key = 0b1100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001  # This should be a large, random number in a real application
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # while True:
    private_key = 0xaa85554255222554814a9088aaa92448511524501552442044a21292a492525508292940549208951281150aa540509
    # private_key = randint(2**255, 2**256)
    public_key = Secp256k1.generate_public_key(abs(private_key))
    # print(public_key.x)
    print(f"Public Key: = 04{hex(public_key.x)[2:].zfill(64)}{hex(public_key.y)[2:].zfill(64)}")
    print(private_key)



if __name__ == "__main__":
    main()