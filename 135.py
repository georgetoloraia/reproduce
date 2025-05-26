import ecdsa
import os
import random
import multiprocessing
import pickle
import time

# secp256k1 parameters
G = ecdsa.SECP256k1.generator
N = ecdsa.SECP256k1.order
p = ecdsa.SECP256k1.curve.p()
lower = 21778071482940061661655974875633165533184
upper = 43556142965880123323311949751266331066367

# Target public key
public_keys = [(
    9445582654557659263594117016832412554674411684964312971801700192446590930102,
    11357316416262876303695105717843937983601816665268710442633943981472828481412
)]

# Modular inverse
def mod_inverse(a, m):
    try:
        return pow(a, m - 2, m)
    except ValueError:
        return None

# Compute k * G
def compute_point(k):
    k = k % N
    if k == 0:
        return None
    if k < 0:
        k = -k
        Q = k * G
        return ecdsa.ellipticcurve.Point(G.curve(), Q.x(), -Q.y() % p)
    return k * G

# Compute line for Q + G
def get_line(Q, G):
    if Q is None:
        return None, None, None
    x1, y1 = Q.x(), Q.y()
    x2, y2 = G.x(), G.y()
    if x1 == x2 and y1 == (-y2 % p):
        return None, x1, y1
    denom = mod_inverse(x2 - x1, p)
    if denom is None:
        return None, x1, y1
    lambda_ = (y2 - y1) * denom % p
    return lambda_, x1, y1

# Check if point matches the target public key
def check_match(Q, public_keys):
    if Q is None:
        return None
    x, y = Q.x(), Q.y()
    for idx, (pub_x, pub_y) in enumerate(public_keys, 1):
        if x == pub_x and (y == pub_y or y == (-pub_y % p)):
            return idx, pub_x, pub_y, (y == pub_y)
    return None

# Generate or load random precomputed inverse steps
def get_precomputed_steps(filename="inverse_steps.txt", max_steps=10000000):
    steps = {}
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                for line in f:
                    m, x, y = map(int, line.strip().split(','))
                    steps[m] = (x, y)
        except (FileNotFoundError, ValueError):
            print("Invalid inverse_steps.txt, regenerating")
    if len(steps) < max_steps:
        print(f"Generating {max_steps} random inverse steps...")
        used_m = set(steps.keys())
        neg_G = ecdsa.ellipticcurve.Point(G.curve(), G.x(), -G.y() % p)
        while len(steps) < max_steps:
            m = random.randint(lower, upper)
            if m in used_m:
                continue
            used_m.add(m)
            point = compute_point(-m)
            if point:
                steps[m] = (point.x(), point.y())
        with open(filename, 'w') as f:
            for m, (x, y) in steps.items():
                f.write(f"{m},{x},{y}\n")
    return steps

# Modifications to test
modifications = [
    lambda k, lam: (k * lam) % N if lam is not None else k,
    lambda k, lam: (lam - k) % p if lam is not None else k,
    lambda k, lam: (lam - k) % N if lam is not None else k,
    lambda k, lam: (lam * mod_inverse(k, N)) % N if lam is not None and k % N != 0 and mod_inverse(k, N) is not None else k,
    lambda k, lam: (-k) % N,
    lambda k, lam: (k + 1) % N,
]

# Worker function for parallel processing
def search_worker(Q, steps, start_j, end_j, result_queue):
    neg_G = ecdsa.ellipticcurve.Point(G.curve(), G.x(), -G.y() % p)
    backward = Q
    found_k = {}
    
    # Backward steps
    for j in range(start_j, end_j + 1):
        backward = backward + neg_G
        if backward is None:
            continue
        # Check against public keys
        match = check_match(backward, public_keys)
        if match:
            pub_idx, pub_x, pub_y, is_positive = match
            k = j
            print(f"Found k = {k} (backward step {j}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
            found_k[k] = found_k.get(k, 0) + 1
        # Check against precomputed steps
        backward_coords = (backward.x(), backward.y())
        for m, (step_x, step_y) in steps.items():
            if backward_coords == (step_x, step_y):
                k = (j + m) % N
                Q_k = compute_point(k)
                match = check_match(Q_k, public_keys)
                if match:
                    pub_idx, pub_x, pub_y, is_positive = match
                    print(f"Found k = {k} (backward step {j} + precomputed step {m}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
                    found_k[k] = found_k.get(k, 0) + 1
    
    result_queue.put(found_k)

# Main function
def main():
    if not public_keys:
        print("No public keys to process")
        return
    
    # Load or generate random steps
    max_steps = 10000000
    steps = get_precomputed_steps(max_steps=max_steps)
    
    # Process the single public key
    x, y = public_keys[0]
    try:
        Q = ecdsa.ellipticcurve.Point(G.curve(), x, y)
        found_k = {}
        
        # Parallelize backward steps
        num_processes = multiprocessing.cpu_count()  # 8 threads
        chunk_size = max_steps // num_processes
        processes = []
        result_queue = multiprocessing.Queue()
        
        for i in range(num_processes):
            start_j = i * chunk_size + 1
            end_j = (i + 1) * chunk_size if i < num_processes - 1 else max_steps
            p = multiprocessing.Process(
                target=search_worker,
                args=(Q, steps, start_j, end_j, result_queue)
            )
            processes.append(p)
            p.start()
        
        # Collect results
        for _ in range(num_processes):
            result = result_queue.get()
            for k, count in result.items():
                found_k[k] = found_k.get(k, 0) + count
        
        for p in processes:
            p.join()
        
        # Scalar modifications
        lambda_, x1, y1 = get_line(Q, G)
        if lambda_ is not None:
            scalars = [x % N, y % N, (-x) % N, (-y) % N]
            for k in scalars + [j for j in range(max_steps + 1)]:
                for mod_idx, mod_func in enumerate(modifications, 1):
                    try:
                        k_prime = mod_func(k, lambda_)
                        Q_prime = compute_point(k_prime)
                        match = check_match(Q_prime, public_keys)
                        if match:
                            pub_idx, pub_x, pub_y, is_positive = match
                            print(f"Found k' = {k_prime} (from k = {k}, modification {mod_idx}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
                            found_k[k_prime] = found_k.get(k_prime, 0) + 1
                    except (ZeroDivisionError, TypeError):
                        continue
        
        # Summary
        if found_k:
            print("\nSummary of found k values:")
            for k, count in found_k.items():
                print(f"k = {k} matched {count} public keys")
                if k * G == Q and lower <= k <= upper:
                    print(f"Verified k = {k} for target public key within range!")
                    with open("found_k.txt", 'w') as f:
                        f.write(str(k))
        else:
            print("\nNo k values found")
    
    except ecdsa.ellipticcurve.InvalidPointError:
        print(f"Invalid public key: ({x}, {y})")

if __name__ == "__main__":
    main()