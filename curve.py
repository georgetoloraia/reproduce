from fastecdsa import curve, point
import random
import sys
import time
import math
from operator import itemgetter

# secp256k1 parameters
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = point.Point(Gx, Gy, curve=curve.secp256k1)

def verify_point_on_curve(x, y, p):
    """Verify if point (x, y) lies on secp256k1: y^2 = x^3 + 7 mod p"""
    try:
        left = (y * y) % p
        right = (pow(x, 3, p) + 7) % p
        return left == right
    except Exception as e:
        print(f"Error verifying point ({x}, {y}): {e}")
        return False

def compute_kG(k, G):
    """Compute k * G on the secp256k1 curve"""
    try:
        if not 1 <= k < N:
            return None, None
        result = k * G
        return result.x, result.y
    except Exception:
        return None, None

def modular_inverse(a, n):
    """Compute modular inverse of a mod n using Extended Euclidean Algorithm"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, n)
    if gcd != 1:
        return None
    return (x % n + n) % n

def measure_closeness(P_x, P_y, Q_x, Q_y, p):
    """Measure closeness of point (P_x, P_y) to (Q_x, Q_y) modulo p"""
    if P_x is None or P_y is None:
        return float('inf')
    dx = min(abs(P_x - Q_x), p - abs(P_x - Q_x))
    dy = min(abs(P_y - Q_y), p - abs(P_y - Q_y))
    return math.sqrt(dx**2 + dy**2)

def pollard_rho_with_closeness(G, Q, Qx, Qy, N, max_iterations=1000000, max_closest=5, closeness_threshold=10**10):
    """Pollard's Rho with closeness tracking to find k such that Q = k * G"""
    def update_point(P, a, b, closest_points, seen_ks):
        x = P.x if P and hasattr(P, 'x') else 0
        partition = x % 3
        if partition == 0:
            new_P = P + G
            new_a = (a + 1) % N
            new_b = b
        elif partition == 1:
            new_P = P + P
            new_a = (2 * a) % N
            new_b = (2 * b) % N
        else:
            new_P = P + Q
            new_a = a
            new_b = (b + 1) % N
        if new_P and hasattr(new_P, 'x') and new_b != 0:
            inv_b = modular_inverse(new_b, N)
            if inv_b is not None:
                k = (new_a * inv_b) % N
                if k not in seen_ks:
                    dist = measure_closeness(new_P.x, new_P.y, Qx, Qy, p)
                    closest_points.append((k, dist))
                    seen_ks.add(k)
                    closest_points.sort(key=itemgetter(1))
                    closest_points[:] = closest_points[:max_closest]
                    if dist < closeness_threshold:
                        return new_P, new_a, new_b, k, True
        return new_P, new_a, new_b, None, False
    
    start_time = time.time()
    iterations = 0
    closest_points = []
    seen_ks = set()
    
    a1, b1 = random.randint(1, N-1), random.randint(1, N-1)
    P1 = (a1 * G) + (b1 * Q)
    a2, b2 = a1, b1
    P2 = P1
    
    while iterations < max_iterations:
        iterations += 1
        P1, a1, b1, k1, stop = update_point(P1, a1, b1, closest_points, seen_ks)
        if stop and k1 and compute_kG(k1, G) == (Qx, Qy):
            print(f"Found k = {k1} after {iterations} iterations for Q = ({Qx}, {Qy})")
            return k1, closest_points
        P2, a2, b2, k2, stop = update_point(P2, a2, b2, closest_points, seen_ks)
        if stop and k2 and compute_kG(k2, G) == (Qx, Qy):
            print(f"Found k = {k2} after {iterations} iterations for Q = ({Qx}, {Qy})")
            return k2, closest_points
        P2, a2, b2, k2, stop = update_point(P2, a2, b2, closest_points, seen_ks)
        if stop and k2 and compute_kG(k2, G) == (Qx, Qy):
            print(f"Found k = {k2} after {iterations} iterations for Q = ({Qx}, {Qy})")
            return k2, closest_points
        
        if P1 == P2 and P1 is not None:
            b_diff = (b2 - b1) % N
            inv_b_diff = modular_inverse(b_diff, N)
            if inv_b_diff is None:
                continue
            k = ((a1 - a2) * inv_b_diff) % N
            if k != 0 and compute_kG(k, G) == (Qx, Qy):
                print(f"Found k = {k} after {iterations} iterations for Q = ({Qx}, {Qy})")
                return k, closest_points
        
        if iterations % 10000 == 0:
            elapsed = time.time() - start_time
            print(f"Q = ({Qx}, {Qy}): Iterations: {iterations}, Time: {elapsed:.2f}s, Keys/s: {iterations/elapsed:.2f}")
            if closest_points:
                print(f"Closest k values: {[f'k={k}, dist={d:.2f}' for k, d in closest_points]}")
    
    print(f"No k found after {max_iterations} iterations for Q = ({Qx}, {Qy})")
    return None, closest_points

def test_candidate_k(Qx, Qy, k, G):
    """Test if k * G = Q"""
    try:
        result_x, result_y = compute_kG(k, G)
        if result_x is None or result_y is None:
            return False
        return result_x == Qx and result_y == Qy
    except Exception as e:
        print(f"Error testing k = {k} for Q = ({Qx}, {Qy}): {e}")
        return False

def load_public_keys(filename):
    """Load public keys from file"""
    pubkeys = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                try:
                    Qx, Qy = map(int, line.strip().split(','))
                    pubkeys.append((Qx, Qy))
                except ValueError:
                    print(f"Skipping invalid line: {line.strip()}")
        return pubkeys
    except FileNotFoundError:
        print(f"File {filename} not found.")
        sys.exit(1)

def load_candidates_from_file(filename):
    """Load candidate k values from a file"""
    candidates = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                try:
                    k = int(line.strip())
                    if 1 <= k < N:
                        candidates.append(k)
                except ValueError:
                    continue
        return candidates
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

def save_found_key(Qx, Qy, k, filename="found_keys.txt"):
    """Save found private key and public key to file"""
    try:
        with open(filename, 'a') as f:
            f.write(f"Public Key: ({Qx}, {Qy}), Private Key: {k}\n")
        print(f"Saved k = {k} for Q = ({Qx}, {Qy}) to {filename}")
    except Exception as e:
        print(f"Error saving key: {e}")

# Load public keys from allpubs.txt
pubkeys = load_public_keys("allpubs.txt")
print(f"Loaded {len(pubkeys)} public keys from allpubs.txt")

# Allow user to input candidate k values or range
print("\nEnter candidate k values (comma-separated), range (e.g., '100-200'), file path (e.g., 'file:steps.txt'), or 'none' to skip:")
user_input = input().strip()
candidate_ks = []
if user_input.lower() != 'none':
    if user_input.startswith('file:'):
        filename = user_input[5:].strip()
        candidate_ks = load_candidates_from_file(filename)
    elif '-' in user_input:
        try:
            start, end = map(int, user_input.split('-'))
            candidate_ks = list(range(max(1, start), min(end + 1, N)))
        except ValueError:
            print("Invalid range format. Skipping candidate k testing.")
    else:
        try:
            candidate_ks = [int(k.strip()) for k in user_input.split(',')]
        except ValueError:
            print("Invalid input. Skipping candidate k testing.")

# Test candidate k values for each public key
for Qx, Qy in pubkeys:
    print(f"\nTesting candidates for Q = ({Qx}, {Qy})...")
    is_valid = verify_point_on_curve(Qx, Qy, p)
    if not is_valid:
        print(f"Q = ({Qx}, {Qy}) is not on the curve. Skipping.")
        continue
    for k in candidate_ks:
        print(f"Testing candidate k = {k}...")
        if test_candidate_k(Qx, Qy, k, G):
            save_found_key(Qx, Qy, k)
            print(f"Match found! k = {k} for Q = ({Qx}, {Qy})")
            candidate_ks = []  # Stop testing candidates for this Q
            break

# Run Pollard's Rho for each public key
print(f"\nRunning Pollard's Rho for {len(pubkeys)} public keys...")
for Qx, Qy in pubkeys:
    print(f"\nProcessing Q = ({Qx}, {Qy})...")
    is_valid = verify_point_on_curve(Qx, Qy, p)
    if not is_valid:
        print(f"Q = ({Qx}, {Qy}) is not on the curve. Skipping.")
        continue
    try:
        Q_point = point.Point(Qx, Qy, curve=curve.secp256k1)
    except Exception as e:
        print(f"Error creating Q point: {e}")
        continue
    found_k, closest_points = pollard_rho_with_closeness(G, Q_point, Qx, Qy, N)
    if found_k:
        save_found_key(Qx, Qy, found_k)
    elif closest_points:
        print(f"Closest k values: {[f'k={k}, dist={d:.2f}' for k, d in closest_points]}")
        min_k = min(k for k, _ in closest_points)
        max_k = max(k for k, _ in closest_points)
        print(f"Suggested k range: [{min_k}, {max_k}]")