import ecdsa
import os

# secp256k1 parameters
G = ecdsa.SECP256k1.generator
N = ecdsa.SECP256k1.order
p = ecdsa.SECP256k1.curve.p()

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

# Read public keys from file
def read_public_keys(filename):
    public_keys = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        x, y = map(int, line.split(','))
                        public_keys.append((x, y))
                    except ValueError:
                        print(f"Skipping invalid line: {line}")
    except FileNotFoundError:
        print(f"{filename} not found, using fallback keys")
        public_keys = [
            (59382383157702485475325267938578413169450322187573480106317056493002856376754, 9836116463052255418200680198398505221381913792643484273036320736605312966009),
            (80149482019880222811699851001361424469498217674683127144318311626420247032495, 103419421519136724725646423659250528065426232395167465993707784564921855598042),
            (22006797671099401852940627850712367644036030418968371563519129329366762451, 17822184556563903053797178732011762107116171993492968345660629500847055312960),
            (74389405667259208740902087810378959523338430306894928876466436087758939449881, 72363491525512241416837909517881098869782915292357912366479015192841544714772),
        ]
    return public_keys

# Check if point matches any public key
def check_match(Q, public_keys):
    if Q is None:
        return None
    x, y = Q.x(), Q.y()
    for idx, (pub_x, pub_y) in enumerate(public_keys, 1):
        if x == pub_x and (y == pub_y or y == (-pub_y % p)):
            return idx, pub_x, pub_y, (y == pub_y)
    return None

# Generate or load precomputed inverse steps
def get_precomputed_steps(filename="inverse_steps.txt", max_steps=10000000):
    steps = {}
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                for line in f:
                    j, x, y = map(int, line.strip().split(','))
                    steps[j] = (x, y)
        except (FileNotFoundError, ValueError):
            print("Invalid inverse_steps.txt, regenerating")
    if len(steps) < max_steps:
        print(f"Generating {max_steps} inverse steps...")
        neg_G = ecdsa.ellipticcurve.Point(G.curve(), G.x(), -G.y() % p)
        current = ecdsa.ellipticcurve.Point(G.curve(), G.x(), -G.y() % p)
        steps[1] = (current.x(), current.y())
        for j in range(2, max_steps + 1):
            current = current + neg_G
            steps[j] = (current.x(), current.y())
        with open(filename, 'w') as f:
            for j, (x, y) in steps.items():
                f.write(f"{j},{x},{y}\n")
    return steps

# Modifications to test
modifications = [
    lambda k, lam: (k * lam) % N if lam is not None else k,  # k' = k * lambda_i mod N
    lambda k, lam: (lam - k) % p if lam is not None else k,  # k' = lambda_i - k
    lambda k, lam: (lam - k) % N if lam is not None else k,  # k' = lambda_i - k mod N
    lambda k, lam: (lam * mod_inverse(k, N)) % N if lam is not None and k % N != 0 and mod_inverse(k, N) is not None else k,  # k' = lambda_i / k mod N
    lambda k, lam: (-k) % N,  # k' = -k
    lambda k, lam: (k + 1) % N,  # k' = k + 1
]

# Read public keys
public_keys = read_public_keys("allpubs.txt")

if not public_keys:
    print("No public keys to process")
else:
    # Load or generate precomputed steps
    max_steps = 100000000  # Adjustable
    steps = get_precomputed_steps(max_steps=max_steps)
    neg_G = ecdsa.ellipticcurve.Point(G.curve(), G.x(), -G.y() % p)

    # Track found k values
    found_k = {}
    for idx, (x, y) in enumerate(public_keys, 1):
        try:
            Q = ecdsa.ellipticcurve.Point(G.curve(), x, y)
            
            # Backward and forward steps
            backward = Q
            forward = Q
            for j in range(1, max_steps + 1):
                # Backward step: Q - j * G
                backward = backward + neg_G
                if backward is not None:
                    # Check against public keys
                    match = check_match(backward, public_keys)
                    if match:
                        pub_idx, pub_x, pub_y, is_positive = match
                        k = j
                        print(f"Found k = {k} (backward step {j}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
                        found_k[k] = found_k.get(k, 0) + 1
                    # Check against precomputed steps
                    backward_coords = (backward.x(), backward.y())
                    for step_j, (step_x, step_y) in steps.items():
                        if backward_coords == (step_x, step_y):
                            k = j + step_j
                            Q_k = compute_point(k)
                            match = check_match(Q_k, public_keys)
                            if match:
                                pub_idx, pub_x, pub_y, is_positive = match
                                print(f"Found k = {k} (backward step {j} + precomputed step {step_j}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
                                found_k[k] = found_k.get(k, 0) + 1

                # Forward step: Q + j * G
                forward = forward + G
                if forward is not None:
                    match = check_match(forward, public_keys)
                    if match:
                        pub_idx, pub_x, pub_y, is_positive = match
                        k = -j % N
                        print(f"Found k = {k} (forward step {j}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
                        found_k[k] = found_k.get(k, 0) + 1
                    forward_coords = (forward.x(), forward.y())
                    for step_j, (step_x, step_y) in steps.items():
                        if forward_coords == (step_x, step_y):
                            k = (-j - step_j) % N
                            Q_k = compute_point(k)
                            match = check_match(Q_k, public_keys)
                            if match:
                                pub_idx, pub_x, pub_y, is_positive = match
                                print(f"Found k = {k} (forward step {j} + precomputed step {step_j}) for public key {pub_idx}: ({pub_x}, {pub_y}) {'(Q)' if is_positive else '(-Q)'}")
                                found_k[k] = found_k.get(k, 0) + 1

            # Scalar modifications
            scalars = [x % N, y % N, (-x) % N, (-y) % N]
            lambda_, x1, y1 = get_line(Q, G)
            if lambda_ is None:
                continue

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

        except ecdsa.ellipticcurve.InvalidPointError:
            print(f"Invalid public key {idx}: ({x}, {y})")

    # Check for universal k
    if found_k:
        print("\nSummary of found k values:")
        for k, count in found_k.items():
            print(f"k = {k} matched {count} public keys")
            if count == len(public_keys):
                print(f"Universal k = {k} found for all {count} public keys!")
    else:
        print("\nNo k values found for any public keys")